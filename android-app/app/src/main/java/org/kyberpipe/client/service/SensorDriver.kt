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
    private val onLightChanged: (lux: Double, timestamp: Long) -> Unit
) : SensorEventListener {

    private var lightSensor: Sensor? = sensorManager.getDefaultSensor(Sensor.TYPE_LIGHT)
    private var lastEmittedLux: Float = -1.0f

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

        // Delta Compression Filter: |L_new - L_last| >= Delta L
        if (lastEmittedLux < 0 || abs(currentLux - lastEmittedLux) >= deltaThresholdLux) {
            lastEmittedLux = currentLux
            val now = System.currentTimeMillis()
            Log.d("KyberpipeSensorDriver", "Lux change detected: $currentLux lux")
            onLightChanged(currentLux.toDouble(), now)
        }
    }

    override fun onAccuracyChanged(sensor: Sensor?, accuracy: Int) {}
}
