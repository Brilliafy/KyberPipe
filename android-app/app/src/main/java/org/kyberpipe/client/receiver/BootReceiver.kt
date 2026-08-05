package org.kyberpipe.client.receiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import org.kyberpipe.client.service.PipeService

/**
 * Reboot recovery (audit finding #25).
 *
 * The legacy design had NO boot path: after a device reboot the foreground
 * sync service never restarted until the user opened the app, so a paired
 * phone silently stopped syncing with no recovery. This receiver runs on
 * BOOT_COMPLETED / LOCKED_BOOT_COMPLETED and hands the service a plain
 * start intent. `PipeService.onStartCommand` then:
 *  - reschedules the keepalive alarm, and
 *  - starts the single poll engine (idempotent), so sync resumes without any
 *    user interaction.
 *
 * It deliberately does NOT call `startForeground` here: Android 12+ (API 31+)
 * restricts starting a foreground service directly from BOOT_COMPLETED, and
 * the direct restriction applies to the service START, not to its alarm
 * resumption. By starting with a plain intent, the service's onStartCommand
 * runs under the FGS rules the manifest already declares (connectedDevice |
 * specialUse) once the app is eligible, and the scheduled keepalive alarm
 * (ACTION_DOZE_PING) provides the recurring wake path that performs the real
 * QUIC heartbeat.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        val action = intent?.action ?: return
        if (action == Intent.ACTION_BOOT_COMPLETED ||
            action == Intent.ACTION_LOCKED_BOOT_COMPLETED
        ) {
            Log.i("KyberpipeBoot", "Device booted — resuming background sync")
            try {
                val serviceIntent = Intent(context, PipeService::class.java).apply {
                    // A plain start: onStartCommand schedules the
                    // keepalive and starts the idempotent sync engine.
                    this.action = "ACTION_BOOT_RESUME"
                }
                context.startService(serviceIntent)
            } catch (e: Exception) {
                Log.w("KyberpipeBoot", "Cannot start sync service after boot: ${e.message}")
                // Android 12+ may block FGS start from BOOT_COMPLETED in some
                // configurations. Fall back to scheduling the keepalive alarm
                // via the service's own alarm path when the app is next opened.
            }
        }
    }
}
