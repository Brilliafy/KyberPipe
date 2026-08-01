package org.kyberpipe.client.receiver

import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.util.Log
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import java.util.ArrayList
import org.kyberpipe.client.utils.SessionKeyManager

data class NotificationEvent(
    val title: String,
    val text: String,
    val packageName: String,
    val timestamp: Long
)

class NotificationHook : NotificationListenerService() {

    private lateinit var serviceScope: CoroutineScope

    companion object {
        /** Extracted media notification state — avoids holding full StatusBarNotification
         *  (which retains Context, Bitmaps, and PendingIntent references). */
        private var activeMediaPackage: String? = null
        private var activeMediaActions: List<Pair<Int, android.app.PendingIntent>>? = null

        /** SharedFlow for notification events — replaces exported broadcast receiver. */
        private val _notificationEvents = MutableSharedFlow<NotificationEvent>(extraBufferCapacity = 64)
        val notificationEvents: SharedFlow<NotificationEvent> = _notificationEvents.asSharedFlow()

        fun triggerMediaAction(actionIndex: Int) {
            val actions = activeMediaActions ?: return
            val (_, pendingIntent) = actions.firstOrNull { it.first == actionIndex } ?: return
            try {
                pendingIntent.send()
                Log.d("KyberpipeMedia", "Successfully sent media action pending intent at index $actionIndex")
            } catch (e: Exception) {
                Log.e("KyberpipeMedia", "Failed to send media action pending intent: ${e.message}")
            }
        }

        /// Send media payload over QUIC via UniFFI bindings instead of HTTP/TCP.
        /// Uses stream type 0x03 (STREAM_MEDIA).
        fun quicSendMedia(scope: CoroutineScope, hostIp: String, payload: String) {
            // Launch on IO dispatcher to avoid blocking the NotificationListenerService thread.
            // Blocking here causes ANR when the QUIC connection is slow or unreachable.
            scope.launch {
                try {
                    val result = uniffi.core_crypto.quicSendAndRecv(0x03.toUByte(), payload)
                    Log.d("KyberpipeMedia", "QUIC media sync response: $result")
                } catch (e: Exception) {
                    Log.e("KyberpipeMedia", "QUIC media sync failed: ${e.message}")
                }
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    }

    override fun onDestroy() {
        serviceScope.cancel()
        super.onDestroy()
    }


    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        if (sbn == null) return

        val packageName = sbn.packageName ?: return
        val extras = sbn.notification?.extras ?: return

        // Intercept Media Notifications
        val isMedia = extras.containsKey("android.mediaSession")
            || packageName == "com.spotify.music"
            || packageName.contains("music")
            || packageName.contains("player")
            || packageName.contains("audio")

        if (isMedia) {
            handleMediaNotification(sbn)
            return
        }

        // Filter out ongoing system notifications
        if (sbn.isOngoing) return

        val title = extras.getCharSequence("android.title")?.toString() ?: ""
        var text = extras.getCharSequence("android.text")?.toString() ?: ""
        val subText = extras.getCharSequence("android.subText")?.toString() ?: ""
        val bigText = extras.getCharSequence("android.bigText")?.toString() ?: ""

        // If bigText is richer/longer, use it
        if (bigText.length > text.length) {
            text = bigText
        }

        // MessagingStyle messages parsing (e.g. Signal, WhatsApp group conversations)
        var messagesLog = ""
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            val messages = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                extras.getParcelableArray("android.messages")
            } else {
                @Suppress("DEPRECATION")
                extras.get("android.messages") as? Array<*>
            }
            if (messages is Array<*>) {
                val sb = java.lang.StringBuilder()
                for (msg in messages as Array<*>) {
                    if (msg is Bundle) {
                        val sender = msg.getCharSequence("sender")?.toString() ?: "Sender"
                        val msgText = msg.getCharSequence("text")?.toString() ?: ""
                        if (msgText.isNotEmpty()) {
                            sb.append("$sender: $msgText\n")
                        }
                    }
                }
                messagesLog = sb.toString().trim()
            }
        }

        // Combine into a structured representation
        val formattedText = buildString {
            if (subText.isNotEmpty()) {
                append("[$subText] ")
            }
            if (messagesLog.isNotEmpty()) {
                append("\n$messagesLog")
            } else {
                append(text)
            }
        }.trim()

        if (title.isEmpty() && formattedText.isEmpty()) return

        val timestamp = System.currentTimeMillis()
        Log.i("KyberpipeNotifHook", "Intercepted notification from $packageName: $title")

        try {
            // Create the UniFFI serialized packet for transmission logs
            val jsonPacket = uniffi.core_crypto.createNotificationPacket(
                title,
                formattedText,
                packageName,
                timestamp.toULong()
            )
            Log.d("KyberpipeNotifHook", "Serialized notification packet: $jsonPacket")

            // Emit to SharedFlow instead of broadcast — no exported receiver needed
            _notificationEvents.tryEmit(
                NotificationEvent(
                    title = title,
                    text = formattedText,
                    packageName = packageName,
                    timestamp = timestamp
                )
            )
        } catch (e: Exception) {
            Log.e("KyberpipeNotifHook", "Failed to format notification packet: ${e.message}")
        }
    }

    private fun handleMediaNotification(sbn: StatusBarNotification) {
        val extras = sbn.notification?.extras ?: return
        val title = extras.getCharSequence("android.title")?.toString() ?: ""
        val artist = extras.getCharSequence("android.text")?.toString() ?: ""
        
        var albumArtBase64 = ""
        val bitmap = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            extras.getParcelable("android.largeIcon", android.graphics.Bitmap::class.java)
                ?: extras.getParcelable("android.picture", android.graphics.Bitmap::class.java)
        } else {
            @Suppress("DEPRECATION")
            extras.getParcelable<android.graphics.Bitmap>("android.largeIcon")
                ?: @Suppress("DEPRECATION")
            extras.getParcelable<android.graphics.Bitmap>("android.picture")
        }
        if (bitmap != null) {
            try {
                val outputStream = java.io.ByteArrayOutputStream()
                bitmap.compress(android.graphics.Bitmap.CompressFormat.JPEG, 60, outputStream)
                val bytes = outputStream.toByteArray()
                albumArtBase64 = "data:image/jpeg;base64," + android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP)
            } catch (e: Exception) {
                Log.e("KyberpipeMedia", "Failed to compress album art bitmap: ${e.message}")
            }
        }

        var isPlaying = false
        val actionsList = ArrayList<org.json.JSONObject>()
        val actions = sbn.notification.actions
        if (actions != null) {
            for (i in actions.indices) {
                val act = actions[i]
                val actTitle = act.title?.toString() ?: ""
                if (actTitle.lowercase().contains("pause")) {
                    isPlaying = true
                }
                val actJson = org.json.JSONObject()
                    .put("title", actTitle)
                    .put("index", i)
                actionsList.add(actJson)
            }
        }

        // Extract only what we need — don't hold the full StatusBarNotification
        activeMediaPackage = sbn.packageName
        activeMediaActions = sbn.notification.actions?.mapIndexed { i, action ->
            i to action.actionIntent
        }

        val settings = org.kyberpipe.client.utils.SettingsManager(applicationContext)
        if (settings.isPaired) {
            val jsonMedia = org.json.JSONObject()
                .put("title", title)
                .put("artist", artist)
                .put("album_art", albumArtBase64)
                .put("is_playing", isPlaying)
                .put("actions", org.json.JSONArray(actionsList))
            
            val jsonStr = jsonMedia.toString()
            val hostIp = settings.pairedHostIp
            val sessionKey = settings.sessionKey
            if (hostIp.isNotEmpty()) {
                val payload = if (sessionKey.isNotEmpty()) {
                    // Encrypt the payload. On failure, abort transmission — never fall back to plaintext.
                    val encrypted = SessionKeyManager.encrypt(jsonStr)
                    if (encrypted != null) {
                        org.json.JSONObject().put("encrypted", org.json.JSONObject()
                            .put("nonce_hex", encrypted.nonce.joinToString("") { "%02x".format(it) })
                            .put("ciphertext_hex", encrypted.ciphertext.joinToString("") { "%02x".format(it) })
                        ).toString()
                    } else {
                        Log.e("KyberpipeMedia", "Encryption failed — aborting transmission")
                        return
                    }
                } else {
                    Log.e("KyberpipeMedia", "No session key — aborting transmission")
                    return
                }
                // Use QUIC instead of HTTP/TCP for media sync
                quicSendMedia(serviceScope, hostIp, payload)
            }
        }
    }

    override fun onNotificationRemoved(sbn: StatusBarNotification?) {
        if (sbn != null && sbn.packageName == activeMediaPackage) {
            activeMediaPackage = null
            activeMediaActions = null
        }
    }
}
