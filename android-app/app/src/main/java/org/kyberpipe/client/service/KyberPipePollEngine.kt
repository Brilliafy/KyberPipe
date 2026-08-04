package org.kyberpipe.client.service

import android.content.Context
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
import org.kyberpipe.client.utils.RatchetWatermarkStore
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
        /**
         * True ONLY when the DESKTOP explicitly reported unpaired in a
         * successful poll response — the one signal that may tear down
         * pairing handles. Connectivity failures set this to false and carry
         * the persisted `isPaired` instead (audit #1 follow-up), so a
         * transient network blip can never un-pair the phone client-side.
         */
        val unpairSignal: Boolean = false,
    )

    private val _updates = MutableSharedFlow<PollUpdate>(extraBufferCapacity = 32)
    val updates: SharedFlow<PollUpdate> = _updates.asSharedFlow()

    private val pollMutex = Mutex()
    private var loopJob: Job? = null
    private var loopScope: CoroutineScope? = null
    private var currentSettings: SettingsManager? = null

    /// AUDIT FINDING #20: the wire protocol (request build + response parse +
    /// update emission) lives in the extracted [PollTransport] class. The
    /// engine owns ONLY the loop, reconnect gating and persistence.
    ///
    /// AUDIT #1 (follow-up): there is exactly ONE update flow, owned by the
    /// engine. The transport is injected the engine's `_updates` and emits
    /// into it — the transport no longer creates its own orphaned flow that
    /// the UI never subscribes to. The transport is stateless w.r.t. delivery,
    /// so it is kept across engine restarts to give subscribers a stable
    /// identity (it re-reads SettingsManager's SharedPreferences on every
    /// call, so the instance never goes stale).
    private var transport: PollTransport? = null

    /// Timestamp of the last SUCCESSFUL connectWithIdentity. Combined with
    /// quicRegisteredPeers() this gates reconnects so a fresh QUIC connection is
    /// not opened every 2.5s poll (audit finding F8).
    private var lastConnectSuccessAt = 0L

    /// AUDIT FINDING #16: whether the phone's receive chain needs realignment
    /// and the NEXT poll request must carry an authenticated Synchronize +
    /// `need_sync` (so the desktop attaches ITS carrier in response). Set when
    /// a decrypt gap is observed (the desktop is ahead of our receive chain),
    /// and additionally on a slow heartbeat so the desktop's position is
    /// periodically refreshed without advancing our send chain on EVERY poll.
    private var needSync = false

    /// AUDIT FINDING #16: heartbeat counter — every N polls, request a sync
    /// even without a detected gap, so long-lived sessions stay aligned even
    /// when no payload ever fails to decrypt (the failure signal is absent
    /// until it is too late). Kept far below the 15s desktop rate window
    /// (2.5s × 30 = 75s per heartbeat) so it never collides with the limiter.
    private var pollsSinceSyncRequest = 0
    private val SYNC_HEARTBEAT_EVERY = 30

    /**
     * Request a Synchronize on the next poll (audit finding #16). Called by the
     * decrypt path when a gap beyond max_skip is observed.
     */
    @Synchronized
    fun requestSync() {
        needSync = true
    }

    /**
     * Start the single poll loop. Idempotent — repeated calls (service restart,
     * onStartCommand, activity recreation) never stack a second loop.
     */
    @Synchronized
    fun start(context: Context) {
        if (loopJob?.isActive == true) return
        val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        loopScope = scope
        val appCtx = context.applicationContext
        currentSettings = SettingsManager(appCtx)
        // AUDIT FINDING #20: instantiate the extracted wire protocol. AUDIT #1
        // (follow-up): created ONCE and kept across restarts — the transport
        // emits into the engine-owned `_updates` flow and re-reads
        // SettingsManager's backing SharedPreferences on every call, so a
        // restart never orphans buffered updates nor mints a new flow.
        if (transport == null) {
            transport = PollTransport(
                context = appCtx,
                settings = currentSettings!!,
                updates = _updates,
                requestSync = { needSync = true },
            )
        }
        val ctx = context.applicationContext
        loopJob = scope.launch {
            var backoffMs = 1000L
            while (isActive) {
                try {
                    pollOnce(ctx)
                    backoffMs = 1000L
                } catch (e: Exception) {
                    Log.d(TAG, "Poll failed: ${e.message}")
                    // AUDIT F5: a failed/timed-out poll must surface as a
                    // DISCONNECTED update so the UI reflects reality instead of
                    // staying green. The Rust side tears down the wedged QUIC
                    // connection on timeout, so the next poll reconnects.
                    //
                    // AUDIT #1 (follow-up): connectivity failure is NOT an
                    // unpair signal. The DISCONNECTED update carries the
                    // CURRENT persisted pairing state so the UI renders the
                    // outage without MainScreen destroying the pairing handles
                    // on a transient network blip. The only path that flips
                    // `isPaired` to false is the desktop explicitly reporting
                    // `is_paired: false` in a successful poll response.
                    _updates.tryEmit(
                        PollUpdate(
                            connected = false,
                            status = "DISCONNECTED",
                            method = "None",
                            color = "red",
                            isPaired = currentSettings?.isPaired ?: false,
                            remoteClipboard = null,
                            pendingMediaAction = null,
                            pairingConfirmed = false,
                            unpairSignal = false,
                        )
                    )
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
        // AUDIT #1 (follow-up): keep the transport across restarts — it emits
        // into the engine-owned flow and never caches settings, so resetting it
        // would only churn the instance identity for no benefit.
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
                // Audit finding F8: do NOT open a fresh QUIC connection every
                // poll. Skip reconnecting when the peer is still registered in
                // the Rust bridge AND the last connect succeeded within ~10s.
                // Only reconnect when the peer dropped out or the last attempt
                // failed. The peer key is the pinned server cert hash (what the
                // bridge registers under when a pin is present — audit #8), with
                // the ratchet identity as a fallback for pin-less states.
                val peerKey = settings.serverCertPin.takeIf { it.isNotEmpty() }
                    ?: settings.peerRatchetIdentity
                val registeredPeers = try {
                    uniffi.core_crypto.quicRegisteredPeers()
                } catch (_: Exception) {
                    emptyList()
                }
                val peerRegistered = peerKey.isNotEmpty() && registeredPeers.contains(peerKey)
                val recentlyConnected =
                    System.currentTimeMillis() - lastConnectSuccessAt < 10_000L
                if (!peerRegistered || !recentlyConnected) {
                    // Ensure the QUIC bridge is established (post-pairing presents
                    // the per-install identity cert — audit finding #8).
                    var connected = false
                    try {
                        connected = PairingManager.connectWithIdentity(
                            targetHostIp, 9876.toUShort(), settings.serverCertPin, context
                        )
                    } catch (_: Exception) {
                        connected = false
                    }
                    if (!connected) {
                        try {
                            connected = uniffi.core_crypto.quicConnect(
                                targetHostIp, 9876.toUShort(), settings.serverCertPin
                            )
                        } catch (_: Exception) {
                            connected = false
                        }
                    }
                    if (connected) {
                        lastConnectSuccessAt = System.currentTimeMillis()
                    }
                }

                // ── Build the poll REQUEST body ────────────────────────────
                // AUDIT FINDING #16: request a sync when a gap was detected OR
                // on the slow heartbeat; the flag is cleared only AFTER the
                // request round-trips (AUDIT #12 follow-up): clearing it before
                // the send meant a session-momentarily-absent throw or a
                // rejected/rate-limited sync silently dropped the recovery
                // request until the next heartbeat.
                pollsSinceSyncRequest++
                val wantSync = needSync || pollsSinceSyncRequest >= SYNC_HEARTBEAT_EVERY
                // AUDIT FINDING #20: the wire protocol lives in the extracted
                // [PollTransport]; the engine owns only the loop.
                val transport = this.transport ?: return@withLock
                val requestBody = transport.buildRequestBody(peer, wantSync)

                // Audit finding F10: route by peer key so a multi-peer mesh
                // never hits the wrong connection. Fall back to the legacy
                // ACTIVE_PEER API only when no peer identity is known (no pair).
                val resp = if (peerKey.isNotEmpty()) {
                    uniffi.core_crypto.quicSendAndRecvTo(peerKey, 0x04.toUByte(), requestBody)
                } else {
                    uniffi.core_crypto.quicSendAndRecv(0x04.toUByte(), requestBody)
                }
                // The round-trip succeeded — the request (including any peeked
                // RekeyAck) reached the desktop. Consume the ack carrier ONLY
                // now (audit finding #6): a failed round-trip retains it for the
                // next poll.
                if (peer.isNotEmpty()) {
                    try {
                        uniffi.core_crypto.ratchetConsumeRekeyAck(peer)
                    } catch (_: Exception) {}
                }
                // AUDIT #12 (follow-up): the round-trip succeeded — the sync
                // request (and any peeked RekeyAck) reached the desktop. Only
                // now is `needSync` cleared so a lost/rejected request is
                // retried on the next poll; the heartbeat counter is reset so
                // the next natural sync stays 75s away.
                if (wantSync) {
                    pollsSinceSyncRequest = 0
                    needSync = false
                }

                val json = try { JSONObject(resp) } catch (_: Exception) { null }
                if (json != null) {
                    transport.processResponse(peer, json) { j, clip, p ->
                        transport.decryptClip(j, clip, p)
                    }
                }
                // Persist the ratchet snapshot after any mutation (AEAD-wrapped
                // INSIDE Rust — audit finding #5/#13: no raw session key bytes
                // ever cross the FFI boundary into the JVM heap).
                if (peer.isNotEmpty()) {
                    try {
                        // ratchetExportSessionWrapped serializes + wraps in Rust;
                        // we only need the peer identity (the wrap key lives in
                        // settings, read by PipeService).
                        val wrapped = uniffi.core_crypto.ratchetExportSessionWrapped(
                            peer, settings.ratchetSnapshotKey.hexToByteArray()
                        )
                        if (wrapped != null) {
                            PipeService.persistWrappedSnapshot(settings, wrapped.nonce, wrapped.ciphertext)
                        }
                        // AUDIT #2 (follow-up): advance the monotonic rollback
                        // watermark AFTER a successful export so a later cold-start
                        // restore refuses a rolled-back snapshot (device backup /
                        // same-user tamper) exactly like the desktop store does.
                        uniffi.core_crypto.ratchetSessionWatermark(peer)?.let { wm ->
                            RatchetWatermarkStore.update(settings, peer, wm)
                        }
                    } catch (e: Exception) {
                        Log.d(TAG, "Snapshot persist skipped: ${e.message}")
                    }
                }
            } finally {
                // Nothing to clean up per-iteration.
            }
        }
    }

    /**
     * AUDIT FINDING #20: the poll WIRE PROTOCOL — request building
     * (`buildRequestBody`), response parsing (`processResponse`), clipboard
     * decrypt (`decryptClip`) and update emission — was extracted from this
     * singleton into the dedicated [PollTransport] class. The engine now owns
     * only the loop lifecycle, reconnect gating and snapshot persistence.
     */
}
