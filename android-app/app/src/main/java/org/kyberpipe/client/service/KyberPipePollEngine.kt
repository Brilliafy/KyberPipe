package org.kyberpipe.client.service

import android.content.Context
import android.util.Base64
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.json.JSONObject
import org.kyberpipe.client.PairingManager
import org.kyberpipe.client.utils.SettingsManager

/**
 * THE single Android poll engine (audit findings #8/#15/#29).
 *
 * Previously the foreground UI (MainScreen.kt) and the background service
 * (PipeService.kt) each ran their own ~2.5s poll loop against the SAME ratchet
 * session — racing the send chain, dropping acks, and drifting between two wire
 * formats (the foreground used the legacy hex fields the desktop no longer
 * emits; the service used the binary TLV). This engine is the ONLY poller:
 *
 *  - one loop per process, single-flight (a Mutex around each poll);
 *  - one wire format: binary TLV everywhere (audit finding #12);
 *  - rekey-aware decryption inside Rust (ratchetDecryptMessageBinary / ack
 *    processing) so acks/syncs that ride a rekey boundary still authenticate
 *    (audit finding #3);
 *  - the phone's OUTBOUND RekeyAck channel (audit finding #1): the ack of the
 *    desktop's proposal is attached to the poll request via the non-consuming
 *    peek, and consumed only after the response round-trips (audit finding #6);
 *  - the foreground UI subscribes to [updates] instead of polling.
 */
object KyberPipePollEngine {

    private const val TAG = "KyberPipePollEngine"
    private const val POLL_INTERVAL_MS = 2500L
    private const val MAX_BACKOFF_MS = 30_000L

    /** Single poll result — everything the UI needs to render from. */
    data class PollUpdate(
        val connected: Boolean,
        val status: String,
        val method: String,
        val color: String,
        val isPaired: Boolean,
        val remoteClipboard: String?,
        val pendingMediaAction: Int?,
        val pairingConfirmed: Boolean,
    )

    private val _updates = MutableSharedFlow<PollUpdate>(extraBufferCapacity = 32)
    val updates: SharedFlow<PollUpdate> = _updates.asSharedFlow()

    private val pollMutex = Mutex()
    private var loopJob: Job? = null
    private var loopScope: CoroutineScope? = null
    private var currentSettings: SettingsManager? = null

    /**
     * Start the single poll loop. Idempotent — repeated calls (service restart,
     * onStartCommand, activity recreation) never stack a second loop.
     */
    @Synchronized
    fun start(context: Context) {
        if (loopJob?.isActive == true) return
        val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        loopScope = scope
        currentSettings = SettingsManager(context.applicationContext)
        val ctx = context.applicationContext
        loopJob = scope.launch {
            var backoffMs = 1000L
            while (isActive) {
                try {
                    pollOnce(ctx)
                    backoffMs = 1000L
                } catch (e: Exception) {
                    Log.d(TAG, "Poll failed: ${e.message}")
                    delay(backoffMs)
                    backoffMs = (backoffMs * 2).coerceAtMost(MAX_BACKOFF_MS)
                    continue
                }
                delay(POLL_INTERVAL_MS)
            }
        }
        Log.i(TAG, "Poll engine started (single loop)")
    }

    /** Stop the poll loop and release resources. */
    @Synchronized
    fun stop() {
        loopJob?.cancel()
        loopJob = null
        loopScope?.cancel()
        loopScope = null
        currentSettings = null
    }

    @Synchronized
    fun isRunning(): Boolean = loopJob?.isActive == true

    private suspend fun pollOnce(context: Context) {
        val settings = currentSettings ?: SettingsManager(context)
        val targetHostIp = settings.pairedHostIp
        val peer = settings.peerRatchetIdentity
        if (targetHostIp.isEmpty()) return
        // Poll while paired OR while a pairing confirmation is pending
        // (two-phase commit, audit finding #6).
        if (!settings.isPaired && !settings.pendingPairingConfirmation) return

        pollMutex.withLock {
            try {
                // Ensure the QUIC bridge is established (post-pairing presents
                // the per-install identity cert — audit finding #8).
                try {
                    PairingManager.connectWithIdentity(
                        targetHostIp, 9876.toUShort(), settings.serverCertPin, context
                    )
                } catch (_: Exception) {
                    try {
                        uniffi.core_crypto.quicConnect(
                            targetHostIp, 9876.toUShort(), settings.serverCertPin
                        )
                    } catch (_: Exception) {}
                }

                // ── Build the poll REQUEST body ────────────────────────────
                val requestBody = buildRequestBody(peer)

                val resp = uniffi.core_crypto.quicSendAndRecv(0x04.toUByte(), requestBody)
                // The round-trip succeeded — the request (including any peeked
                // RekeyAck) reached the desktop. Consume the ack carrier ONLY
                // now (audit finding #6): a failed round-trip retains it for the
                // next poll.
                if (peer.isNotEmpty()) {
                    try {
                        uniffi.core_crypto.ratchetConsumeRekeyAck(peer)
                    } catch (_: Exception) {}
                }

                val json = try { JSONObject(resp) } catch (_: Exception) { null }
                if (json != null) {
                    processResponse(context, settings, peer, json)
                }
                // Persist the ratchet snapshot after any mutation (AEAD-wrapped,
                // audit finding #13).
                if (peer.isNotEmpty()) {
                    try {
                        val snap = uniffi.core_crypto.ratchetExportSession(peer)
                        if (snap != null) {
                            PipeService.persistRatchetSnapshotWrapped(settings, snap)
                        }
                    } catch (_: Exception) {}
                }
            } finally {
                // Nothing to clean up per-iteration.
            }
        }
    }

    /**
     * Build the poll request: an authenticated Synchronize packet (audit
     * finding #4 — the only resync trigger) plus the phone's OUTBOUND RekeyAck
     * (audit finding #1 — the missing phone→desktop ack channel).
     */
    private fun buildRequestBody(peer: String): String {
        val body = JSONObject()
        if (peer.isNotEmpty()) {
            // Authenticated Synchronize producer: the phone's send counter as a
            // ratchet-encrypted binary-TLV packet (audit finding #12).
            try {
                val syncTlv = uniffi.core_crypto.ratchetSynchronizePacketBinary(peer)
                body.put("sync", JSONObject().put(
                    "tlv_b64", Base64.encodeToString(syncTlv, Base64.NO_WRAP)
                ))
            } catch (_: Exception) {}
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

    private fun processResponse(
        context: Context,
        settings: SettingsManager,
        peer: String,
        json: JSONObject,
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
        if (!json.optBoolean("is_paired", true)) {
            settings.isPaired = false
            settings.pairedDeviceName = ""
        }

        val status = json.optString("connection_status", "ACTIVE")
        val method = json.optString("connection_method", "LAN")
        val color = json.optString("connection_color", "green")

        var remoteClipboard: String? = null
        val clip = json.optJSONObject("latest_clip_encrypted")
        if (clip != null) {
            remoteClipboard = decryptClip(context, settings, peer, json, clip)
        }

        var pendingMediaAction: Int? = null
        if (json.has("pending_media_action") && !json.isNull("pending_media_action")) {
            val idx = json.optInt("pending_media_action", -1)
            if (idx != -1) {
                pendingMediaAction = idx
            }
        }

        // Desktop→phone RekeyAck / Synchronize consumers (audit findings #1/#4):
        // both ride the ratchet and are processed rekey-aware in Rust.
        val ack = json.optJSONObject("rekey_ack_encrypted")
        if (ack != null && peer.isNotEmpty()) {
            try {
                val tlv = Base64.decode(ack.getString("tlv_b64"), Base64.NO_WRAP)
                uniffi.core_crypto.ratchetProcessRekeyAckBinary(peer, tlv)
            } catch (e: Exception) {
                Log.e(TAG, "Desktop RekeyAck processing failed: ${e.message}")
            }
        }
        // The desktop's authenticated Synchronize packet keeps our receiving
        // chain aligned; processed even when the clip decrypted fine (audit #4).
        val sync = json.optJSONObject("sync")
        if (sync != null && peer.isNotEmpty()) {
            try {
                val tlv = Base64.decode(sync.getString("tlv_b64"), Base64.NO_WRAP)
                uniffi.core_crypto.ratchetProcessSynchronize(peer, tlv)
            } catch (e: Exception) {
                Log.d(TAG, "Synchronize not applied: ${e.message}")
            }
        }

        _updates.tryEmit(
            PollUpdate(
                connected = color.equals("green", ignoreCase = true),
                status = status,
                method = method,
                color = color,
                isPaired = settings.isPaired,
                remoteClipboard = remoteClipboard,
                pendingMediaAction = pendingMediaAction,
                pairingConfirmed = pairingConfirmed,
            )
        )
    }

    private fun respContainsNotPaired(json: JSONObject): Boolean {
        return json.optString("reason", "").isNotEmpty() || json.optString("status", "") == "error"
    }

    /**
     * Decrypt the desktop's clipboard payload (binary TLV, rekey-aware in Rust).
     * On a gap past max_skip, the desktop's authenticated Synchronize packet is
     * processed first and the decrypt retried ONCE (audit finding #4).
     */
    private fun decryptClip(
        context: Context,
        settings: SettingsManager,
        peer: String,
        json: JSONObject,
        clip: JSONObject,
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
                return null
            }
        }
        // Legacy session-key shape (unchanged).
        return try {
            val nonce = clip.getString("nonce_hex").hexToByteArray()
            val ct = clip.getString("ciphertext_hex").hexToByteArray()
            org.kyberpipe.client.utils.SessionKeyManager.decrypt(nonce, ct)
        } catch (e: Exception) {
            Log.d(TAG, "Legacy clip decrypt failed: ${e.message}")
            null
        }
    }
}

/** Hex string → byte array. */
internal fun String.hexToByteArray(): ByteArray {
    val len = length
    require(len % 2 == 0) { "Hex string must have even length" }
    return ByteArray(len / 2) { i ->
        ((Character.digit(this[i * 2], 16) shl 4) + Character.digit(this[i * 2 + 1], 16)).toByte()
    }
}
