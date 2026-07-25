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
    private val serviceScope = CoroutineScope(Dispatchers.Default + SupervisorJob())
    private var heartbeatJob: Job? = null
    private var lastClipboardSync: Long = 0

    private var wakeLock: android.os.PowerManager.WakeLock? = null
    private val wakeLockRefCount = java.util.concurrent.atomic.AtomicInteger(0)

    private fun acquireWakeLock(powerManager: PowerManager, timeoutMs: Long) {
        synchronized(wakeLockRefCount) {
            if (wakeLockRefCount.incrementAndGet() == 1) {
                val wl = powerManager.newWakeLock(
                    PowerManager.PARTIAL_WAKE_LOCK,
                    "Kyberpipe:DozeHeartbeat"
                )
                wl.acquire(timeoutMs)
                this.wakeLock = wl
            }
        }
    }

    private fun releaseWakeLock() {
        synchronized(wakeLockRefCount) {
            if (wakeLockRefCount.decrementAndGet() <= 0) {
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
                val sensorJson = uniffi.core_crypto.createSensorPacket(lux.toDouble(), timestamp.toULong())
                Log.d("KyberpipeService", "Sensor packet emitted: $sensorJson")
            } catch (e: Exception) {
                Log.e("KyberpipeService", "Failed to create sensor packet: ${e.message}")
            }
        }
        sensorDriver.start()

        startAdaptiveHeartbeatLoop()
    }

    private fun startAdaptiveHeartbeatLoop() {
        isKeepAliveActive = true
        val intervalMs = 300_000L // 5 minutes — exact alarms every 15s would be rate-limited and crash on API 31+
        scheduleAlarm(intervalMs)
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
            return START_STICKY
        }
        if (intent?.action == "ACTION_DOZE_PING") {
            Log.d("KyberpipeService", "Doze Mode alarm wakeup ping triggered.")
            val powerManager = getSystemService(Context.POWER_SERVICE) as PowerManager
            acquireWakeLock(powerManager, 10_000L)
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
        return START_STICKY
    }

    override fun onDestroy() {
        super.onDestroy()
        isKeepAliveActive = false
        heartbeatJob?.cancel()
        heartbeatJob = null
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
