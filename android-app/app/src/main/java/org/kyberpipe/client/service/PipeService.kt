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
     * Background sync engine: THE single poll loop (audit findings #8/#15/#29).
     * The foreground UI subscribes to [KyberPipePollEngine.updates] instead of
     * polling, so the ratchet session is only ever advanced by one loop. The
     * engine is idempotent — re-invocation (onStartCommand after pairing,
     * START_STICKY restart) never stacks a second loop.
     */
    private fun startSyncEngine() {
        KyberPipePollEngine.start(this)
    }

    override fun onDestroy() {
        super.onDestroy()
        isKeepAliveActive = false
        heartbeatJob?.cancel()
        heartbeatJob = null
        syncJob?.cancel()
        syncJob = null
        // Stop the single poll loop.
        KyberPipePollEngine.stop()
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

    /**
     * AEAD-wrap the ratchet snapshot with an INDEPENDENT at-rest wrap key and
     * persist it as Base64 (audit finding #13). The wrap key is 32 random bytes
     * kept in EncryptedSharedPreferences, separate from the session key, so a
     * session-key compromise does not expose stored ratchet state. The stored
     * value is Base64("{nonce_hex}:{ct_hex}") — never raw ratchet bytes.
     * On any failure the snapshot is NOT persisted (never plaintext at rest).
     * Shared with the single poll engine (audit finding #8).
     */
    companion object {
        @JvmStatic
        fun persistRatchetSnapshotWrapped(
            settings: org.kyberpipe.client.utils.SettingsManager,
            snap: ByteArray
        ) {
            try {
                var wrapKeyHex = settings.ratchetSnapshotKey
                if (wrapKeyHex.isEmpty()) {
                    val wrapKey = ByteArray(32)
                    java.security.SecureRandom().nextBytes(wrapKey)
                    wrapKeyHex = wrapKey.toHexString()
                    settings.ratchetSnapshotKey = wrapKeyHex
                }
                val wrapped = uniffi.core_crypto.encryptPayloadWithHandle(
                    wrapKeyHex.hexToByteArray(), snap
                )
                val nonceHex = wrapped.nonce.toHexString()
                val ctHex = wrapped.ciphertext.toHexString()
                settings.ratchetSnapshot = android.util.Base64.encodeToString(
                    "$nonceHex:$ctHex".toByteArray(Charsets.UTF_8),
                    android.util.Base64.NO_WRAP
                )
            } catch (e: Exception) {
                // Never store plaintext — skip persistence on failure.
                Log.w("KyberpipeService", "Ratchet snapshot persist skipped: ${e.message}")
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

/** Byte array → lowercase hex string (mirrors MainScreen's private extension). */
private fun ByteArray.toHexString(): String =
    joinToString("") { "%02x".format(it.toInt() and 0xFF) }
