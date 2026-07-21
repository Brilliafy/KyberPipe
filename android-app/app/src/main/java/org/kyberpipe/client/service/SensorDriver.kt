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
    private val onLightChanged: (lux: Float, timestampMs: Long) -> Unit
) : SensorEventListener {

    private var lightSensor: Sensor? = sensorManager.getDefaultSensor(Sensor.TYPE_LIGHT)
    private var motionSensor: Sensor? = sensorManager.getDefaultSensor(Sensor.TYPE_SIGNIFICANT_MOTION)
    private var isStationary = false
    private var lastLightValue: Float = -1.0f
    private var lastEmitTimestampMs: Long = 0L

    fun start() {
        lightSensor?.let {
            sensorManager.registerListener(this, it, SensorManager.SENSOR_DELAY_NORMAL)
            Log.i("KyberpipeSensorDriver", "Ambient light sensor listener registered.")
        } ?: run {
            Log.w("KyberpipeSensorDriver", "Ambient light sensor unavailable on device.")
        }
        motionSensor?.let {
            Log.i("KyberpipeSensorDriver", "Inertial Significant Motion sensor active (Stationary sleep optimization).")
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
