package org.kyberpipe.client.service

import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import android.util.Log
import kotlin.math.abs

class SensorDriver(
    private val sensorManager: SensorManager,
    private val deltaThresholdLux: Float = 2.0f,
    private val minPollIntervalMs: Long = 500L,
    private val onLightChanged: (lux: Double, timestamp: Long) -> Unit
) : SensorEventListener {

    private var lightSensor: Sensor? = sensorManager.getDefaultSensor(Sensor.TYPE_LIGHT)
    private var lastEmittedLux: Float = -1.0f
    private var lastEmittedTimeMs: Long = 0L

    fun start() {
        lightSensor?.let { sensor ->
            sensorManager.registerListener(this, sensor, SensorManager.SENSOR_DELAY_NORMAL)
            Log.i("KyberpipeSensorDriver", "Ambient light sensor polling registered.")
        } ?: run {
            Log.w("KyberpipeSensorDriver", "Ambient light sensor unavailable on device.")
        }
    }

    fun stop() {
        sensorManager.unregisterListener(this)
        Log.i("KyberpipeSensorDriver", "Ambient light sensor polling stopped.")
    }

    override fun onSensorChanged(event: SensorEvent?) {
        if (event == null || event.sensor.type != Sensor.TYPE_LIGHT) return

        val currentLux = event.values[0]
        val now = System.currentTimeMillis()

        // 1. Delta Compression Check: |L_new - L_last| >= Delta L
        val deltaMet = lastEmittedLux < 0 || abs(currentLux - lastEmittedLux) >= deltaThresholdLux
        // 2. Sliding Time-Gate Check: (T_now - T_last) >= minPollIntervalMs
        val timeMet = (now - lastEmittedTimeMs) >= minPollIntervalMs

        if (deltaMet && timeMet) {
            lastEmittedLux = currentLux
            lastEmittedTimeMs = now
            Log.d("KyberpipeSensorDriver", "Debounced Lux change emitted: $currentLux lux")
            onLightChanged(currentLux.toDouble(), now)
        }
    }

    override fun onAccuracyChanged(sensor: Sensor?, accuracy: Int) {}
}
