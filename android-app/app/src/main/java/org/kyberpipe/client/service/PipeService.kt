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

class PipeService : Service() {

    private lateinit var sensorDriver: SensorDriver
    private val CHANNEL_ID = "kyberpipe_service_channel"
    private var isKeepAliveActive = false

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
                val sensorJson = uniffi.kyberpipe.createSensorPacket(lux, timestamp.toULong())
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
        Thread {
            val powerManager = getSystemService(Context.POWER_SERVICE) as PowerManager
            while (isKeepAliveActive) {
                val isDozeMode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    powerManager.isDeviceIdleMode
                } else false

                val intervalMs = if (isDozeMode) 120_000L else 15_000L
                Log.i("KyberpipeService", "QUIC Heartbeat Ping sent (DozeMode = $isDozeMode, Interval = ${intervalMs}ms)")

                if (isDozeMode && Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    scheduleDozeWakeupAlarm(intervalMs)
                }

                try {
                    Thread.sleep(intervalMs)
                } catch (e: InterruptedException) {
                    break
                }
            }
        }.start()
    }

    private fun scheduleDozeWakeupAlarm(intervalMs: Long) {
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
        val triggerTime = System.currentTimeMillis() + intervalMs
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            alarmManager.setExactAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, triggerTime, pendingIntent)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == "ACTION_DOZE_PING") {
            Log.d("KyberpipeService", "Doze Mode alarm wakeup ping triggered.")
        }
        return START_STICKY
    }

    override fun onDestroy() {
        super.onDestroy()
        isKeepAliveActive = false
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
