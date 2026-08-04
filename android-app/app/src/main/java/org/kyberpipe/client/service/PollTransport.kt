package org.kyberpipe.client.service

import android.content.Context
import android.util.Base64
import android.util.Log
import org.json.JSONObject
import org.kyberpipe.client.utils.SettingsManager
import kotlinx.coroutines.flow.MutableSharedFlow

/**
 * Poll WIRE PROTOCOL (audit finding #20 — extracted from the former
 * `KyberPipePollEngine` singleton monolith so the QUIC request/response and
 * ratchet-session parse logic live apart from the loop/lifecycle). Owns:
 *
 *  - `buildRequestBody`: the poll REQUEST (authenticated Synchronize packet +
 *    outbound RekeyAck + `need_sync` heartbeat flag),
 *  - `processResponse`: the poll RESPONSE parse (pairing two-phase commit,
 *    clipboard decrypt, RekeyAck/Synchronize consumers, ordered by the
 *    desktop's `manifest` — audit finding #18),
 *  - `emit`: forwards poll results into the ENGINE-OWNED update flow.
 *
 * It is a plain class (not a singleton) so the transport is unit-testable and
 * the engine owns only the loop. All ratchet FFI calls remain rekey-aware in
 * Rust; this layer only marshals TLVs.
 *
 * AUDIT #1 (follow-up): there is exactly ONE update flow, owned by
 * [KyberPipePollEngine]. It is injected here as `updates` instead of the
 * transport creating its own private flow — the extraction (finding #20)
 * previously left the success-path emissions on an orphaned SharedFlow that
 * the UI never subscribed to.
 */
class PollTransport(
    private val context: Context,
    private val settings: SettingsManager,
    private val updates: MutableSharedFlow<KyberPipePollEngine.PollUpdate>,
    private val requestSync: () -> Unit,
) {
    private val TAG = "PollTransport"

    /** Emit a poll result to the UI (forwards to the engine-owned flow). */
    fun emit(update: KyberPipePollEngine.PollUpdate) {
        updates.tryEmit(update)
    }

    /**
     * Build the poll request: an authenticated Synchronize packet (audit
     * finding #4 — the only resync trigger) plus the phone's OUTBOUND RekeyAck
     * (audit finding #1 — the missing phone→desktop ack channel).
     *
     * AUDIT FINDING #16: the phone's Synchronize packet is sent ONLY when its
     * receive chain needs realignment — after a decrypt gap, or on a slow
     * heartbeat — never on every poll. The legacy unconditional sync advanced
     * the phone's send chain every 2.5s AND collided with the desktop's per-
     * peer 15s sync rate limit (5 of every 6 syncs were rejected before
     * decryption, so the desktop's receive chain lagged the phone's send chain
     * by ~6 positions every window). `need_sync` tells the desktop to attach
     * ITS Synchronize carrier in response (the desktop only advances its own
     * chain when asked).
     */
    fun buildRequestBody(peer: String, needSync: Boolean): String {
        val body = JSONObject()
        if (peer.isNotEmpty()) {
            // Authenticated Synchronize producer: the phone's send counter as a
            // ratchet-encrypted binary-TLV packet (audit finding #12). Sent only
            // when recovery is genuinely needed (audit finding #16).
            if (needSync) {
                try {
                    val syncTlv = uniffi.core_crypto.ratchetSynchronizePacketBinary(peer)
                    body.put("sync", JSONObject().put(
                        "tlv_b64", Base64.encodeToString(syncTlv, Base64.NO_WRAP)
                    ))
                } catch (_: Exception) {}
                // Ask the desktop to attach ITS Synchronize carrier in response
                // (audit finding #16).
                body.put("need_sync", true)
            }
            // Phone→desktop RekeyAck channel (audit finding #1): the desktop's
            // outgoing proposal is acked here. Peek (non-consuming) so a lost
            // request retains the ack for the next poll (audit finding #6).
            try {
                val ackTlv = uniffi.core_crypto.ratchetGenerateRekeyAckBinaryPeek(peer)
                if (ackTlv != null) {
                    body.put("rekey_ack_encrypted", JSONObject().put(
                        "tlv_b64", Base64.encodeToString(ackTlv, Base64.NO_WRAP)
                    ))
                }
            } catch (_: Exception) {}
        }
        return body.toString()
    }

    /**
     * Parse the poll RESPONSE (audit finding #20 extraction). Consumes the
     * ratchet-encrypted fields strictly in the order prescribed by the
     * desktop's `manifest` (audit finding #18), so a producer that reorders
     * its inserts fails loudly instead of silently decrypting out of order.
     */
    fun processResponse(
        peer: String,
        json: JSONObject,
        decryptClip: (JSONObject, JSONObject, String) -> String?,
    ) {
        // Two-phase pairing commit (audit finding #6): commit isPaired only when
        // the desktop reports it.
        var pairingConfirmed = false
        if (settings.pendingPairingConfirmation) {
            if (json.optBoolean("is_paired", false)) {
                settings.isPaired = true
                settings.pendingPairingConfirmation = false
                pairingConfirmed = true
                Log.i(TAG, "Desktop confirmed SAS — pairing committed")
            } else if (json.optString("reason", "").contains("Not paired", ignoreCase = true) ||
                respContainsNotPaired(json)
            ) {
                settings.pendingPairingConfirmation = false
                Log.w(TAG, "Desktop rejected pairing — not confirmed")
            }
        }
        // AUDIT #1 (follow-up): `unpairSignal` is set ONLY when the desktop
        // explicitly reports unpaired in this response — it is the single
        // signal the UI may use to tear down pairing handles. Transport-level
        // failures never reach this branch (they surface as DISCONNECTED
        // updates carrying the persisted isPaired state instead).
        var unpairSignal = false
        if (!json.optBoolean("is_paired", true)) {
            settings.isPaired = false
            settings.pairedDeviceName = ""
            unpairSignal = true
        }

        val status = json.optString("connection_status", "ACTIVE")
        val method = json.optString("connection_method", "LAN")
        val color = json.optString("connection_color", "green")

        // AUDIT FINDING #18 (implicit cross-repo ordering contract): the
        // desktop's poll response now carries an explicit `manifest` listing
        // the insertion order of the ratchet-encrypted fields. We consume them
        // strictly in that order — and fall back to the documented legacy order
        // (clip → ack → sync) when the manifest is absent — so a producer that
        // reorders its inserts fails LOUDLY here instead of silently decrypting
        // out of order (AEAD failures + Synchronize storms).
        val manifest: List<String> = runCatching {
            json.optJSONArray("manifest")?.let { arr ->
                (0 until arr.length()).map { arr.getString(it) }
            }
        }.getOrNull() ?: listOf("latest_clip_encrypted", "rekey_ack_encrypted", "sync")

        var remoteClipboard: String? = null
        var pendingMediaAction: Int? = null
        if (json.has("pending_media_action") && !json.isNull("pending_media_action")) {
            val idx = json.optInt("pending_media_action", -1)
            if (idx != -1) {
                pendingMediaAction = idx
            }
        }

        for (field in manifest) {
            when (field) {
                "latest_clip_encrypted" -> {
                    val clip = json.optJSONObject("latest_clip_encrypted")
                    if (clip != null) {
                        remoteClipboard = decryptClip(json, clip, peer)
                    }
                }
                "rekey_ack_encrypted" -> {
                    val ack = json.optJSONObject("rekey_ack_encrypted")
                    if (ack != null && peer.isNotEmpty()) {
                        try {
                            val tlv = Base64.decode(ack.getString("tlv_b64"), Base64.NO_WRAP)
                            uniffi.core_crypto.ratchetProcessRekeyAckBinary(peer, tlv)
                        } catch (e: Exception) {
                            Log.e(TAG, "Desktop RekeyAck processing failed: ${e.message}")
                        }
                    }
                }
                "sync" -> {
                    // The desktop's authenticated Synchronize packet keeps our
                    // receiving chain aligned; processed even when the clip
                    // decrypted fine (audit #4).
                    val sync = json.optJSONObject("sync")
                    if (sync != null && peer.isNotEmpty()) {
                        try {
                            val tlv = Base64.decode(sync.getString("tlv_b64"), Base64.NO_WRAP)
                            uniffi.core_crypto.ratchetProcessSynchronize(peer, tlv)
                        } catch (e: Exception) {
                            Log.d(TAG, "Synchronize not applied: ${e.message}")
                        }
                    }
                }
                else -> Log.d(TAG, "Unknown manifest field '$field' — ignored")
            }
        }

        emit(
            KyberPipePollEngine.PollUpdate(
                connected = color.equals("green", ignoreCase = true),
                status = status,
                method = method,
                color = color,
                isPaired = settings.isPaired,
                remoteClipboard = remoteClipboard,
                pendingMediaAction = pendingMediaAction,
                pairingConfirmed = pairingConfirmed,
                unpairSignal = unpairSignal,
            )
        )
    }

    private fun respContainsNotPaired(json: JSONObject): Boolean {
        return json.optString("reason", "").isNotEmpty() || json.optString("status", "") == "error"
    }

    /**
     * Decrypt the desktop's clipboard payload (binary TLV, rekey-aware in Rust).
     * On a gap past max_skip, the desktop's authenticated Synchronize packet is
     * processed first and the decrypt retried ONCE (audit finding #4). A
     * decrypt gap additionally requests a sync on the NEXT poll (audit #16).
     */
    fun decryptClip(
        json: JSONObject,
        clip: JSONObject,
        peer: String,
    ): String? {
        val enc = clip.optJSONObject("encrypted_ratchet")
        if (enc != null) {
            if (peer.isEmpty()) return null
            val tlv = try {
                Base64.decode(enc.getString("tlv_b64"), Base64.NO_WRAP)
            } catch (e: Exception) {
                Log.d(TAG, "Clip TLV decode failed: ${e.message}")
                return null
            }
            try {
                return String(
                    uniffi.core_crypto.ratchetDecryptMessageBinary(peer, tlv),
                    Charsets.UTF_8
                )
            } catch (e: Exception) {
                // Ratchet decrypt failed — the desktop may be ahead of our
                // receiving chain after a handoff. Its poll response carries an
                // authenticated Synchronize packet: process it, then retry ONCE.
                val sync = json.optJSONObject("sync")
                if (sync != null) {
                    try {
                        val syncTlv = Base64.decode(sync.getString("tlv_b64"), Base64.NO_WRAP)
                        uniffi.core_crypto.ratchetProcessSynchronize(peer, syncTlv)
                        return String(
                            uniffi.core_crypto.ratchetDecryptMessageBinary(peer, tlv),
                            Charsets.UTF_8
                        )
                    } catch (e2: Exception) {
                        Log.w(TAG, "Synchronize recovery failed: ${e2.message}")
                        return null
                    }
                }
                Log.d(TAG, "Ratchet decrypt failed (no sync): ${e.message}")
                // AUDIT FINDING #16: no sync was available — request one on the
                // NEXT poll so our receive chain can realign against the
                // desktop's send position.
                requestSync()
                return null
            }
        }
        // Legacy session-key shape: the legacy wire path is removed (audit F7/F17)
        // — without a ratchet-encrypted TLV there is nothing we can authenticate,
        // so drop it instead of attempting a raw session-key decrypt.
        Log.d(TAG, "Clip payload is not ratchet-shaped — dropping")
        return null
    }
}
