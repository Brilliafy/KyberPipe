package org.kyberpipe.client.receiver

import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.util.Log

class NotificationHook : NotificationListenerService() {

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        if (sbn == null) return

        // Filter out ongoing system notifications
        if (sbn.isOngoing) return

        val packageName = sbn.packageName ?: return
        val extras = sbn.notification?.extras ?: return

        val title = extras.getCharSequence("android.title")?.toString() ?: ""
        val text = extras.getCharSequence("android.text")?.toString() ?: ""
        val timestamp = System.currentTimeMillis()

        if (title.isEmpty() && text.isEmpty()) return

        Log.i("KyberpipeNotifHook", "Intercepted notification from $packageName: $title")

        try {
            val jsonPacket = uniffi.kyberpipe.createNotificationPacket(
                title,
                text,
                packageName,
                timestamp.toULong()
            )
            Log.d("KyberpipeNotifHook", "Serialized notification packet: $jsonPacket")
        } catch (e: Exception) {
            Log.e("KyberpipeNotifHook", "Failed to format notification packet: ${e.message}")
        }
    }

    override fun onNotificationRemoved(sbn: StatusBarNotification?) {}
}
