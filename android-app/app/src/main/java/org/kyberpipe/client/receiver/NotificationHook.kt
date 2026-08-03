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

data class NotificationEvent(
    val title: String,
    val text: String,
    val packageName: String,
    val timestamp: Long
)

class NotificationHook : NotificationListenerService() {

    private lateinit var serviceScope: CoroutineScope

    /// Cached SettingsManager (audit finding #9): opened ONCE in onCreate and
    /// reused — building an EncryptedSharedPreferences instance per notification
    /// (Keystore-backed AES-256-GCM init) on the binder thread is expensive and
    /// ANR-prone.
    private var cachedSettings: org.kyberpipe.client.utils.SettingsManager? = null

    companion object {
        /** Extracted media notification state — avoids holding full StatusBarNotification
         *  (which retains Context, Bitmaps, and PendingIntent references). */
        private var activeMediaPackage: String? = null
        private var activeMediaActions: List<Pair<Int, android.app.PendingIntent>>? = null

        /// Maximum forwarded notification title/text length in chars
        /// (audit finding #14).
        private const val MAX_NOTIFICATION_TEXT_CHARS = 2048

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
        // Cap forwarded notification title/text (audit finding #14): never push
        // oversized content over QUIC.
        val rawTitle = extras.getCharSequence("android.title")?.toString() ?: ""
        val rawArtist = extras.getCharSequence("android.text")?.toString() ?: ""
        val title = rawTitle.take(MAX_NOTIFICATION_TEXT_CHARS)
        val artist = rawArtist.take(MAX_NOTIFICATION_TEXT_CHARS)
        if (rawTitle.length > MAX_NOTIFICATION_TEXT_CHARS || rawArtist.length > MAX_NOTIFICATION_TEXT_CHARS) {
            Log.d("KyberpipeMedia", "Truncated media notification text to $MAX_NOTIFICATION_TEXT_CHARS chars (audit finding #14)")
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

        // AUDIT FINDING #9: NotificationListenerService.onNotificationPosted runs
        // on a binder thread with strict deadlines. Bitmap JPEG-compression of
        // full-resolution album art plus EncryptedSharedPreferences init (a
        // Keystore-backed AES-256-GCM store) per notification can blow the ANR
        // budget under notification bursts. ALL of that heavy work is offloaded
        // to the worker coroutine below; only the cheap metadata extraction stays
        // on the binder thread.
        val mediaTitle = title
        val mediaArtist = artist
        val mediaActions = ArrayList(actionsList)
        val mediaPlaying = isPlaying
        val pkg = sbn.packageName ?: ""
        val bmp = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            extras.getParcelable("android.largeIcon", android.graphics.Bitmap::class.java)
                ?: extras.getParcelable("android.picture", android.graphics.Bitmap::class.java)
        } else {
            @Suppress("DEPRECATION")
            extras.getParcelable<android.graphics.Bitmap>("android.largeIcon")
                ?: @Suppress("DEPRECATION")
            extras.getParcelable<android.graphics.Bitmap>("android.picture")
        }
        serviceScope.launch {
            var albumArtBase64 = ""
            if (bmp != null) {
                try {
                    val outputStream = java.io.ByteArrayOutputStream()
                    bmp.compress(android.graphics.Bitmap.CompressFormat.JPEG, 60, outputStream)
                    val bytes = outputStream.toByteArray()
                    albumArtBase64 = "data:image/jpeg;base64," + android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP)
                } catch (e: Exception) {
                    Log.e("KyberpipeMedia", "Failed to compress album art bitmap: ${e.message}")
                }
            }

            // Cached SettingsManager (audit finding #9): opened once in onCreate,
            // reused across notifications instead of rebuilding the
            // EncryptedSharedPreferences per call.
            val settings = cachedSettings ?: org.kyberpipe.client.utils.SettingsManager(applicationContext).also { cachedSettings = it }
            // Forward over QUIC only when paired AND the user explicitly enabled
            // notification forwarding (audit finding #14 — opt-in, default OFF).
            if (settings.isPaired && settings.notificationForwardingEnabled) {
                val jsonMedia = org.json.JSONObject()
                    .put("title", mediaTitle)
                    .put("artist", mediaArtist)
                    .put("album_art", albumArtBase64)
                    .put("is_playing", mediaPlaying)
                    .put("actions", org.json.JSONArray(mediaActions))

                val jsonStr = jsonMedia.toString()
                val hostIp = settings.pairedHostIp
                val peer = settings.peerRatchetIdentity
                if (hostIp.isNotEmpty() && peer.isNotEmpty()) {
                    // Audit finding F7: the legacy session-key wire path is gone —
                    // encrypt with the ratchet (binary TLV). On failure, abort
                    // transmission — never fall back to plaintext.
                    val tlv = try {
                        uniffi.core_crypto.ratchetEncryptMessageBinary(peer, jsonStr.toByteArray())
                    } catch (e: Exception) {
                        Log.e("KyberpipeMedia", "Ratchet encrypt failed — aborting transmission: ${e.message}")
                        return@launch
                    }
                    val payload = org.json.JSONObject().put("encrypted_ratchet", org.json.JSONObject()
                        .put("tlv_b64", android.util.Base64.encodeToString(tlv, android.util.Base64.NO_WRAP))
                    ).toString()
                    Log.d("KyberpipeMedia", "Forwarding media payload for $pkg")
                    quicSendMedia(serviceScope, hostIp, payload)
                }
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
