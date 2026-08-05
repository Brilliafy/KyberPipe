package org.kyberpipe.client.state

import android.content.ClipboardManager
import android.content.Context
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshots.SnapshotStateList
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.json.JSONObject
import org.kyberpipe.client.components.AndroidClipboardRecord
import org.kyberpipe.client.service.KyberPipePollEngine
import org.kyberpipe.client.utils.SettingsManager

/**
 * `useClipboardState` — the clipboard feature state (audit #8 follow-up).
 * Owns the local clipboard-history list, the OS primary-clip listener (with
 * debounced ratchet-wrapped sync), and the POLL slice that mirrors the
 * desktop's remote clipboard into the list + the system clipboard.
 */
class ClipboardState(
    private val settings: SettingsManager,
    private val context: Context,
    private val addLog: (String) -> Unit,
) {
    val clipboardList: SnapshotStateList<AndroidClipboardRecord> = mutableStateListOf()
    private var clipboardSyncJob: Job? = null

    /** Hook the OS primary-clipboard listener (called once from the router). */
    fun hookPrimaryClipboard() {
        val clipboardManager = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboardManager.addPrimaryClipChangedListener {
            val clipData = clipboardManager.primaryClip
            if (clipData != null && clipData.itemCount > 0) {
                val text = clipData.getItemAt(0).text?.toString() ?: ""
                if (text.isNotEmpty()) {
                    val exists = clipboardList.any { it.text == text }
                    if (!exists) {
                        clipboardList.add(
                            0,
                            AndroidClipboardRecord(
                                id = "clip_${System.currentTimeMillis()}",
                                text = text,
                                source = "local",
                                timestamp = System.currentTimeMillis()
                            )
                        )
                        addLog("[Clipboard] Intercepted new primary clip (${text.length} chars)")

                        if (settings.isPaired) {
                            val hostIp = settings.pairedHostIp
                            val peer = settings.peerRatchetIdentity
                            if (hostIp.isNotEmpty() && peer.isNotEmpty()) {
                                // Audit finding F7: encrypt with the ratchet
                                // (binary TLV) — no raw key bytes.
                                val tlv = try {
                                    uniffi.core_crypto.ratchetEncryptMessageBinary(peer, text.toByteArray())
                                } catch (e: Exception) {
                                    addLog("[Clipboard] Ratchet encrypt failed: ${e.message}")
                                    null
                                }
                                if (tlv != null) {
                                    val jsonBody = JSONObject().put("encrypted_ratchet", JSONObject()
                                        .put("tlv_b64", android.util.Base64.encodeToString(tlv, android.util.Base64.NO_WRAP))
                                    ).toString()
                                    // Clipboard sync with debounce + single in-flight.
                                    clipboardSyncJob?.cancel()
                                    clipboardSyncJob = CoroutineScope(Dispatchers.IO).launch {
                                        delay(500)
                                        if (!isActive) return@launch
                                        try {
                                            uniffi.core_crypto.quicSendAndRecv(0x02.toUByte(), jsonBody)
                                        } catch (e: Exception) {
                                            addLog("[Clipboard] QUIC sync failed: ${e.message}")
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        addLog("[Service] Hooked primary clipboard listener")
    }

    /** Consume the CLIPBOARD slice of a poll update (remote clip mirror). */
    fun onPollUpdate(update: KyberPipePollEngine.PollUpdate) {
        val latestClip = update.remoteClipboard
        if (!latestClip.isNullOrEmpty()) {
            val exists = clipboardList.any { it.text == latestClip }
            if (!exists) {
                clipboardList.add(
                    0,
                    AndroidClipboardRecord(
                        id = "clip_${System.currentTimeMillis()}",
                        text = latestClip,
                        source = "remote",
                        timestamp = System.currentTimeMillis()
                    )
                )
                val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                cm.setPrimaryClip(android.content.ClipData.newPlainText("Kyberpipe", latestClip))
                addLog("[Clipboard] Received remote clip (${latestClip.length} chars)")
            }
        }
    }

    fun addLocalClip(text: String) {
        if (text.isNotEmpty()) {
            clipboardList.add(
                0,
                AndroidClipboardRecord(
                    id = "clip_${System.currentTimeMillis()}",
                    text = text,
                    source = "local",
                    timestamp = System.currentTimeMillis()
                )
            )
        }
    }

    fun copyToSystemClipboard(text: String) {
        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(android.content.ClipData.newPlainText("Kyberpipe", text))
        android.widget.Toast.makeText(context, "Copied to phone clipboard", android.widget.Toast.LENGTH_SHORT).show()
    }

    fun deleteClip(id: String) {
        clipboardList.removeAll { it.id == id }
    }
}

/** Compose entry point for [ClipboardState] (the `useClipboardState` hook). */
@Composable
fun rememberClipboardState(
    settings: SettingsManager,
    context: Context,
    addLog: (String) -> Unit,
): ClipboardState {
    return remember(settings, context) {
        ClipboardState(settings, context, addLog)
    }
}

/**
 * `useMediaState` — the media-action feature state (audit #8 follow-up +
 * P4-1(b)). The desktop's `pending_media_action` is NO LONGER fired
 * automatically: it is surfaced as a phone-side confirmation dialog
 * ([pendingTrigger]) and the foreign PendingIntent is fired only when the
 * phone user explicitly approves ([confirmPending]). This mirrors the
 * desktop's native-gesture token model — a compromised desktop renderer
 * cannot initiate phone-side actions without the phone user's consent.
 */
data class MediaTriggerRequest(
    val index: Int,
    val actionTitle: String,
    val packageName: String,
)

class MediaState(
    private val context: Context,
    private val addLog: (String) -> Unit,
) {
    /// Phone-side confirmation request awaiting the user's Allow/Deny (audit
    /// P4-1(b)). Non-null renders the dialog; cleared by confirm/dismiss.
    var pendingTrigger by mutableStateOf<MediaTriggerRequest?>(null)
        private set

    fun onPollUpdate(update: KyberPipePollEngine.PollUpdate) {
        update.pendingMediaAction?.let { idx ->
            // AUDIT P4-1(b): surface a phone-side confirmation INSTEAD of
            // firing. `peekPendingMediaAction` returns the action title +
            // package without touching the PendingIntent; the fire happens
            // only after the user approves in the dialog.
            val info = org.kyberpipe.client.receiver.NotificationHook
                .peekPendingMediaAction(idx)
            if (info != null) {
                pendingTrigger = MediaTriggerRequest(idx, info.first, info.second)
            } else {
                addLog("[Media] Media action index $idx not dispatched (stale, out-of-range, or rate-limited)")
            }
        }
    }

    /// The phone user approved — now (and only now) fire the PendingIntent.
    /// `triggerMediaAction` still enforces the TTL/freshness and the 5s
    /// rate limit and returns whether the send actually happened.
    fun confirmPending() {
        val req = pendingTrigger ?: return
        pendingTrigger = null
        val sent = org.kyberpipe.client.receiver.NotificationHook.triggerMediaAction(req.index)
        if (sent) {
            addLog("[Media] Triggered media action index ${req.index} from PC (approved on phone)")
        } else {
            addLog("[Media] Media action index ${req.index} not dispatched (stale or rate-limited)")
        }
    }

    /// The phone user denied — drop the request without firing.
    fun dismissPending() {
        val req = pendingTrigger ?: return
        pendingTrigger = null
        addLog("[Media] Media action index ${req.index} rejected on phone (user denied)")
    }
}

/** Compose entry point for [MediaState] (the `useMediaState` hook). */
@Composable
fun rememberMediaState(
    addLog: (String) -> Unit,
): MediaState {
    val context = androidx.compose.ui.platform.LocalContext.current
    return remember(context) { MediaState(context, addLog) }
}
