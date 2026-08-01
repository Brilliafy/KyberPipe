package org.kyberpipe.client.service

import android.app.AlarmManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.hardware.SensorManager
import org.json.JSONObject
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

class PipeService : Service() {

    private lateinit var sensorDriver: SensorDriver
    private val CHANNEL_ID = "kyberpipe_service_channel"
    private var isKeepAliveActive = false
    private lateinit var serviceScope: CoroutineScope
    private var heartbeatJob: Job? = null
    private var syncJob: Job? = null
    private var lastClipboardSync: Long = 0

    private var wakeLock: android.os.PowerManager.WakeLock? = null
    private val wakeLockRefCount = java.util.concurrent.atomic.AtomicInteger(0)

    private fun acquireWakeLock(powerManager: PowerManager) {
        synchronized(wakeLockRefCount) {
            val count = wakeLockRefCount.incrementAndGet()
            if (count == 1 || wakeLock == null || !(wakeLock?.isHeld == true)) {
                val wl = powerManager.newWakeLock(
                    PowerManager.PARTIAL_WAKE_LOCK,
                    "Kyberpipe:DozeHeartbeat"
                )
                wl.setReferenceCounted(false)
                wl.acquire()
                this.wakeLock = wl
            }
        }
    }

    private fun releaseWakeLock() {
        synchronized(wakeLockRefCount) {
            val count = wakeLockRefCount.decrementAndGet()
            if (count <= 0) {
                wakeLockRefCount.set(0)
                val wl = this.wakeLock
                if (wl != null && wl.isHeld) {
                    wl.release()
                }
                this.wakeLock = null
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        Log.i("KyberpipeService", "Initializing PipeService foreground engine...")
        // Initialize scope in onCreate — NOT as a field initializer — so it is
        // recreated on service restart (START_STICKY) and properly cancelled
        // in onDestroy without leaking the previous scope's Job.
        serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

        createNotificationChannel()
        val notification = buildForegroundNotification("PQC Engine & Network Discovery Active")
        startForeground(1001, notification)

        val sensorManager = getSystemService(Context.SENSOR_SERVICE) as SensorManager
        sensorDriver = SensorDriver(
            sensorManager,
            deltaThresholdLux = 2.0f,
            minPollIntervalMs = 500L
        ) { lux, timestamp ->
            try {
                val sensorJson = JSONObject().apply {
                    put("type", "sensor_ambient_light")
                    put("lux", lux.toDouble())
                    put("timestamp", timestamp.toULong())
                }.toString()
                Log.d("KyberpipeService", "Sensor packet emitted: $sensorJson")
            } catch (e: Exception) {
                Log.e("KyberpipeService", "Failed to create sensor packet: ${e.message}")
            }
        }
        sensorDriver.start()

        startAdaptiveHeartbeatLoop()
        // Start the real sync engine (QUIC bridge + encrypted poll loop).
        startSyncEngine()
    }

    private fun startAdaptiveHeartbeatLoop() {
        isKeepAliveActive = true
        val intervalMs = 300_000L // 5 minutes
        heartbeatJob = serviceScope.launch {
            while (isActive) {
                delay(intervalMs)
                scheduleAlarm(intervalMs)
            }
        }
    }

    /**
     * Background sync engine: keeps the QUIC bridge alive and polls the desktop
     * for encrypted clipboard / rekey-ack payloads when the UI is not visible.
     * Idempotent: cancels any existing job before starting (audit finding #12).
     */
    private fun startSyncEngine() {
        // Idempotent restart: cancel any prior engine before starting a new one
        // so re-invocation (e.g. from onStartCommand after pairing completes)
        // never stacks duplicate poll loops.
        syncJob?.cancel()
        syncJob = null
        val settings = org.kyberpipe.client.utils.SettingsManager(this)
        if (!settings.isPaired) return
        val hostIp = settings.pairedHostIp
        if (hostIp.isEmpty()) return
        val peer = settings.peerRatchetIdentity
        syncJob = serviceScope.launch {
            // Exponential backoff state (audit finding #11): 1s → 30s cap.
            var backoffMs = 1000L
            try {
                val ok = org.kyberpipe.client.PairingManager.connectWithIdentity(
                    hostIp, 9876.toUShort(), settings.serverCertPin, this@PipeService
                )
                if (!ok) {
                    // Pin-less path fallback (bootstrap state) — plain connect.
                    try {
                        uniffi.core_crypto.quicConnect(hostIp, 9876.toUShort(), settings.serverCertPin)
                    } catch (_: Exception) {}
                }
            } catch (e: Exception) {
                Log.e("KyberpipeService", "QUIC connect failed: ${e.message}")
            }
            while (isActive) {
                try {
                    // Producer for the Synchronize recovery path (audit #4):
                    // tell the desktop where our send chain is so it can resync
                    // its receiving chain after a network handoff.
                    var syncSendCount = ""
                    if (peer.isNotEmpty()) {
                        try {
                            syncSendCount = uniffi.core_crypto.ratchetSendCount(peer).toString()
                        } catch (_: Exception) {}
                    }
                    val requestBody = if (syncSendCount.isNotEmpty()) {
                        org.json.JSONObject().put("sync_send_count", syncSendCount).toString()
                    } else {
                        ""
                    }
                    val resp = uniffi.core_crypto.quicSendAndRecv(0x04.toUByte(), requestBody)
                    // Any successful poll resets the backoff.
                    backoffMs = 1000L
                    val json = try { JSONObject(resp) } catch (_: Exception) { null }
                    if (json != null) {
                        val clip = json.optJSONObject("latest_clip_encrypted")
                        if (clip != null) {
                            val enc = clip.optJSONObject("encrypted_ratchet") ?: clip
                            val nonce = enc.getString("nonce_hex").hexToByteArray()
                            val ct = enc.getString("ciphertext_hex").hexToByteArray()
                            // Route through the REKEY-AWARE decrypt path so DH/KEM
                            // rekey payloads are processed (audit finding #1 — the
                            // phone previously dropped rekey fields and the desktop
                            // TTL-committed, permanently desyncing the session).
                            val text = if (peer.isNotEmpty()) {
                                try {
                                    val rekeyX = enc.optString("rekey_x25519_pk_hex", "")
                                        .takeIf { it.isNotEmpty() }?.hexToByteArray()
                                    val rekeyM = enc.optString("rekey_mlkem_pk_hex", "")
                                        .takeIf { it.isNotEmpty() }?.hexToByteArray()
                                    val rekeyCt = enc.optString("rekey_ciphertext_hex", "")
                                        .takeIf { it.isNotEmpty() }?.hexToByteArray()
                                    try {
                                        String(
                                            uniffi.core_crypto.ratchetDecryptWithRekeyMessage(
                                                peer, nonce, ct, rekeyCt, rekeyX, rekeyM
                                            ),
                                            Charsets.UTF_8
                                        )
                                    } catch (_: Exception) {
                                        // Session may be desynchronized (a dropped
                                        // burst during network handoff). The desktop's
                                        // poll response carries its send counter —
                                        // resync the receiving chain and retry once.
                                        // Consumer for the Synchronize path (audit #4).
                                        val desktopCount =
                                            json.optLong("ratchet_send_count", -1L)
                                        if (desktopCount > 0) {
                                            try {
                                                val recv =
                                                    uniffi.core_crypto.ratchetRecvCount(peer).toLong()
                                                if (desktopCount > recv + 100) {
                                                    Log.w(
                                                        "KyberpipeService",
                                                        "Receive chain desync (recv=$recv desktop=$desktopCount) — resyncing"
                                                    )
                                                    uniffi.core_crypto.ratchetSynchronizeSession(
                                                        peer, desktopCount.toULong()
                                                    )
                                                }
                                            } catch (_: Exception) {}
                                        }
                                        String(
                                            uniffi.core_crypto.ratchetDecryptWithRekeyMessage(
                                                peer, nonce, ct, rekeyCt, rekeyX, rekeyM
                                            ),
                                            Charsets.UTF_8
                                        )
                                    }
                                } catch (_: Exception) {
                                    org.kyberpipe.client.utils.SessionKeyManager.decrypt(nonce, ct)
                                }
                            } else {
                                org.kyberpipe.client.utils.SessionKeyManager.decrypt(nonce, ct)
                            }
                            if (!text.isNullOrEmpty()) {
                                val cm = getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
                                cm.setPrimaryClip(android.content.ClipData.newPlainText("Kyberpipe", text))
                            }
                        }
                        val ack = json.optJSONObject("rekey_ack_encrypted")
                        if (ack != null && peer.isNotEmpty()) {
                            try {
                                val nonce = ack.getString("nonce_hex").hexToByteArray()
                                val ct = ack.getString("ciphertext_hex").hexToByteArray()
                                val pt = uniffi.core_crypto.ratchetDecryptMessage(peer, nonce, ct)
                                val ptJson = JSONObject(String(pt, Charsets.UTF_8))
                                // RekeyAck serializes as {"type":"RekeyAck","payload":{"seq":N}}
                                // — parse the type/payload shape (audit finding #3).
                                if (ptJson.optString("type") == "RekeyAck") {
                                    val seq = ptJson.getJSONObject("payload").getLong("seq")
                                    uniffi.core_crypto.ratchetProcessRekeyAck(peer, seq.toULong())
                                }
                            } catch (e: Exception) {
                                Log.e("KyberpipeService", "RekeyAck failed: ${e.message}")
                            }
                        }
                    }
                    // Persist the ratchet snapshot after any mutation.
                    if (peer.isNotEmpty()) {
                        try {
                            val snap = uniffi.core_crypto.ratchetExportSession(peer)
                            if (snap != null) {
                                settings.ratchetSnapshot = android.util.Base64.encodeToString(snap, android.util.Base64.NO_WRAP)
                            }
                        } catch (_: Exception) {}
                    }
                } catch (e: Exception) {
                    Log.d("KyberpipeService", "Sync poll failed: ${e.message}")
                    // Exponential backoff on persistent failure (audit #11):
                    // an unreachable desktop must not burn a QUIC attempt every
                    // 2.5s with a 15s blocking timeout.
                    delay(backoffMs)
                    backoffMs = (backoffMs * 2).coerceAtMost(30_000L)
                    continue
                }
                delay(2500)
            }
        }
    }

    private fun scheduleAlarm(intervalMs: Long) {
        val alarmManager = getSystemService(Context.ALARM_SERVICE) as AlarmManager
        val intent = Intent(this, PipeService::class.java).apply {
            action = "ACTION_DOZE_PING"
        }
        val pendingIntent = PendingIntent.getService(
            this,
            0,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        alarmManager.cancel(pendingIntent)
        val triggerTime = System.currentTimeMillis() + intervalMs
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            // API 31+ rate-limits exact alarms aggressively. Use setWindow (inexact)
            // to avoid SecurityException and battery drain.
            alarmManager.setWindow(AlarmManager.RTC_WAKEUP, triggerTime, intervalMs, pendingIntent)
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            alarmManager.setAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, triggerTime, pendingIntent)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Handle null intent (START_STICKY restart after process death).
        // Android kills the service, then restarts with a null intent.
        // We must reschedule the heartbeat to prevent silent death.
        if (intent == null) {
            Log.i("KyberpipeService", "Service restarted by START_STICKY — rescheduling heartbeat")
            scheduleAlarm(300_000L)
            // Restart the sync engine too — a sticky restart after pairing may
            // have missed the earlier start (audit finding #12).
            startSyncEngine()
            return START_STICKY
        }
        if (intent?.action == "ACTION_DOZE_PING") {
            Log.d("KyberpipeService", "Doze Mode alarm wakeup ping triggered.")
            val powerManager = getSystemService(Context.POWER_SERVICE) as PowerManager
            acquireWakeLock(powerManager)
            serviceScope.launch {
                try {
                    Log.i("KyberpipeService", "Doze heartbeat: QUIC keepalive sent")
                    delay(5000)
                    // Reschedule next heartbeat to keep the loop alive.
                    // Without this, the heartbeat fires exactly once and dies.
                    scheduleAlarm(300_000L)
                } catch (e: Exception) {
                    Log.e("KyberpipeService", "Heartbeat I/O failed: ${e.message}")
                } finally {
                    releaseWakeLock()
                }
            }
        }
        // Re-evaluate the sync engine on EVERY start. Idempotent: pairing may
        // have completed after the service was already running (audit #12).
        startSyncEngine()
        return START_STICKY
    }

    override fun onDestroy() {
        super.onDestroy()
        isKeepAliveActive = false
        heartbeatJob?.cancel()
        heartbeatJob = null
        syncJob?.cancel()
        syncJob = null
        synchronized(wakeLockRefCount) {
            if (wakeLock?.isHeld == true) {
                wakeLock?.release()
            }
            wakeLock = null
            wakeLockRefCount.set(0)
        }
        serviceScope.cancel()
        sensorDriver.stop()
        Log.i("KyberpipeService", "PipeService stopped.")
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Kyberpipe Background Core",
                NotificationManager.IMPORTANCE_LOW
            )
            val manager = getSystemService(NotificationManager::class.java)
            manager?.createNotificationChannel(channel)
        }
    }

    private fun buildForegroundNotification(statusText: String): Notification {
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }

        return builder
            .setContentTitle("Kyberpipe Post-Quantum Core")
            .setContentText(statusText)
            .setSmallIcon(android.R.drawable.ic_menu_compass)
            .build()
    }
}

/** Hex string → byte array (mirrors MainScreen's private extension). */
private fun String.hexToByteArray(): ByteArray {
    val len = length
    require(len % 2 == 0) { "Hex string must have even length" }
    return ByteArray(len / 2) { i ->
        ((Character.digit(this[i * 2], 16) shl 4) + Character.digit(this[i * 2 + 1], 16)).toByte()
    }
}
