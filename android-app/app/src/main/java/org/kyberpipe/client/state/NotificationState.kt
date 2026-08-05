package org.kyberpipe.client.state

import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.snapshots.SnapshotStateList
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.kyberpipe.client.components.AndroidNotificationRecord
import org.kyberpipe.client.utils.NotificationStore
import org.kyberpipe.client.utils.SettingsManager

/**
 * `useNotificationState` — the notification-mirror feature state (audit #8
 * follow-up). Owns the notification history list, the local broadcast receiver
 * that mirrors intercepted notifications, and the 30s store auto-sync loop.
 */
class NotificationState(
    private val context: Context,
    private val addLog: (String) -> Unit,
) {
    private val notifStore = NotificationStore(context)

    val notificationsList: SnapshotStateList<AndroidNotificationRecord> =
        mutableStateListOf<AndroidNotificationRecord>().apply {
            addAll(notifStore.loadNotifications())
        }

    /** Register the local NOTIFICATION_INTERCEPTED mirror receiver. */
    fun registerReceiver() {
        val receiver = object : android.content.BroadcastReceiver() {
            override fun onReceive(c: Context?, intent: Intent?) {
                if (intent?.action == "org.kyberpipe.client.NOTIFICATION_INTERCEPTED") {
                    val title = intent.getStringExtra("title") ?: ""
                    val text = intent.getStringExtra("text") ?: ""
                    val pkg = intent.getStringExtra("packageName") ?: ""
                    val ts = intent.getLongExtra("timestamp", System.currentTimeMillis())

                    val newRecord = AndroidNotificationRecord(
                        id = "notif_${ts}_${pkg.hashCode()}",
                        title = title,
                        text = text,
                        appPackage = pkg,
                        timestamp = ts,
                        type = "local"
                    )
                    notificationsList.add(0, newRecord)
                    notifStore.saveNotifications(notificationsList)
                    addLog("[Notification] Intercepted from $pkg: $title")
                }
            }
        }
        val filter = android.content.IntentFilter("org.kyberpipe.client.NOTIFICATION_INTERCEPTED")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("UnspecifiedRegisterReceiverFlag")
            context.registerReceiver(receiver, filter)
        }
        receivers.add(receiver)
    }

    private val receivers = mutableListOf<android.content.BroadcastReceiver>()

    fun unregisterReceiver() {
        receivers.forEach { runCatching { context.unregisterReceiver(it) } }
        receivers.clear()
    }

    /** Auto-sync with the local store every 30 s (bounded loop, cancelled with scope). */
    fun startAutoSync(scope: CoroutineScope, purgeDays: Int) {
        scope.launch {
            while (isActive) {
                delay(30_000)
                val stored = notifStore.loadNotifications()
                val changed = notifStore.mergeSync(notificationsList, stored)
                if (changed) {
                    addLog("[Sync] Notifications auto-synced with local store")
                }
                notifStore.purgeOldRecords(purgeDays, notificationsList)
            }
        }
    }

    fun dismiss(id: String) {
        val idx = notificationsList.indexOfFirst { it.id == id }
        if (idx != -1) {
            val item = notificationsList[idx]
            notificationsList[idx] = item.copy(isDismissed = true, updatedAt = System.currentTimeMillis())
            notifStore.saveNotifications(notificationsList)
            addLog("[Notification] Dismissed $id. Sync queued.")
        }
    }
}

/** Compose entry point for [NotificationState] (the `useNotificationState` hook). */
@Composable
fun rememberNotificationState(
    context: Context,
    addLog: (String) -> Unit,
): NotificationState {
    return remember(context) { NotificationState(context, addLog) }
}
