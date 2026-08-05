package org.kyberpipe.client.service

import android.util.Base64
import android.util.Log
import org.json.JSONObject
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
    private val settings: PollSettings,
    private val updates: MutableSharedFlow<KyberPipePollEngine.PollUpdate>,
    private val requestSync: () -> Unit,
    /// Injected ratchet FFI (verification-gap remediation): the real impl
    /// delegates to UniFFI; tests inject a fake so the wire logic — including
    /// the AUDIT #1 flow-forwarding — runs hermetically on the JVM.
    private val ffi: PollFfi = RealPollFfi(),
) {
    private val TAG = "PollTransport"

    companion object {
        /// AUDIT P1-1 (HIGH): the shared wire-contract frame bound, resolved
        /// from the UniFFI-exported `maxMessageSize()` — the SAME export the
        /// desktop producer's cap is derived from, so the two independently-
        /// compiled ends can never disagree. Falls back to the documented
        /// 1 MiB only when the native library is absent (JVM unit tests with
        /// a fake FFI) — in production the export always resolves.
        val MAX_FRAME_BODY_SIZE: Int = runCatching {
            uniffi.core_crypto.maxMessageSize().toInt()
        }.getOrDefault(1024 * 1024)
    }

    /// AUDIT P1-1: the wire-contract size predicate. Extracted as a pure
    /// function so the JVM unit tests can exercise it (the
    /// `android.util.Base64` decode path is not mockable in a plain JVM).
    internal fun refusesOversizedTlv(tlvSize: Int): Boolean = tlvSize > MAX_FRAME_BODY_SIZE

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
                    val syncTlv = ffi.synchronizePacketBinary(peer)
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
                val ackTlv = ffi.generateRekeyAckBinaryPeek(peer)
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
                            ffi.processRekeyAckBinary(peer, tlv)
                        } catch (e: Exception) {
                            Log.e(TAG, "Desktop RekeyAck processing failed: ${e.message}")
                        }
                    }
                }
                "sync" -> {
                    // The desktop's authenticated Synchronize packet keeps our
                    // receiving chain aligned; processed even when the clip
                    // decrypted fine (audit #4). AUDIT #4: this is the ONLY
                    // consumer of the sync packet — `decryptClip` no longer
                    // processes it in-band, so one packet is applied exactly
                    // once per poll (the Rust consumer is idempotent anyway: an
                    // already-aligned sync is a no-op success, never a
                    // rate-limit or replay error).
                    val sync = json.optJSONObject("sync")
                    if (sync != null && peer.isNotEmpty()) {
                        try {
                            val tlv = Base64.decode(sync.getString("tlv_b64"), Base64.NO_WRAP)
                            ffi.processSynchronize(peer, tlv)
                        } catch (e: Exception) {
                            // AUDIT #3: a cross-generation sync that cannot be
                            // applied (the handoff dropped the rekey carrier)
                            // is NOT a benign no-op — surface it loudly so the
                            // user gets a re-pair hint instead of silent
                            // "paired but nothing syncs" + infinite retries
                            // against the rate limiter.
                            val code = e.message?.substringBefore("]")
                            if (code?.contains("CROSS_GENERATION_RESYNC_REQUIRED") == true) {
                                Log.w(
                                    TAG,
                                    "Cross-generation sync cannot be applied (rekey carrier lost in handoff) — re-pair recommended: ${e.message}"
                                )
                            } else {
                                Log.d(TAG, "Synchronize not applied: ${e.message}")
                            }
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
     *
     * AUDIT #4: this method does NOT process the desktop's Synchronize packet
     * in-band. The legacy path decrypted the sync TLV here and then the
     * manifest loop reached the same "sync" field and applied it a SECOND
     * time — a guaranteed stale/replay rejection that wasted the rate budget
     * and logged noise. The manifest loop is the single consumer; on a decrypt
     * gap this method simply requests a sync so the NEXT poll realigns the
     * receive chain (the desktop re-sends its latest clip after the sync).
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
            // AUDIT P1-1 (HIGH): mirror the wire-contract frame bound. The
            // desktop producer now refuses to encrypt clipboard payloads whose
            // TLV+base64 framing would exceed MAX_MESSAGE_SIZE (1 MiB); the
            // phone's QUIC frame consumer hard-rejects anything larger anyway.
            // A TLV beyond the shared bound can only come from a broken/foreign
            // producer — refuse it here instead of feeding an oversized blob to
            // the ratchet. The bound is the SHARED UniFFI-exported constant, so
            // the two independently-compiled ends can never disagree.
            if (refusesOversizedTlv(tlv.size)) {
                Log.w(
                    TAG,
                    "Clip TLV is ${tlv.size} bytes > MAX_MESSAGE_SIZE ($MAX_FRAME_BODY_SIZE) — refusing oversized payload (audit P1-1)"
                )
                return null
            }
            try {
                return String(
                    ffi.decryptMessageBinary(peer, tlv),
                    Charsets.UTF_8
                )
            } catch (e: Exception) {
                // Ratchet decrypt failed — the desktop may be ahead of our
                // receiving chain after a handoff. The poll response's sync
                // packet is applied by the manifest loop (the single consumer,
                // audit #4); request another sync for the NEXT poll so the
                // chain realigns and the desktop's next clip decrypts.
                Log.d(TAG, "Ratchet decrypt failed: ${e.message}")
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
