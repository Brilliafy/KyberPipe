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
import org.kyberpipe.client.utils.RatchetSessionRestorer
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

    /// AUDIT P2-2 (MEDIUM): dirty-gate for snapshot persistence, mirroring the
    /// desktop's `ratchet_dirty_since_last_persist` (audit #11). The legacy
    /// loop exported the AEAD-wrapped snapshot (Rust serialize + wrap) and
    /// wrote BOTH EncryptedSharedPreferences entries — snapshot + watermark,
    /// each a Keystore AES-GCM transaction — on EVERY 2.5s poll (~34,500
    /// serialized exports + ~69,000 Keystore writes/day), on the same IO
    /// thread the poll loop runs on. This tracks the last-persisted
    /// (epoch, generation, send, recv) watermark per peer and only
    /// exports+persists when the ratchet actually mutated.
    private val lastPersistedWatermark =
        java.util.concurrent.ConcurrentHashMap<String, LongArray>()

    /// Whether the ratchet for `peer` mutated past what was last PERSISTED.
    /// Reads the live watermark (non-mutating FFI accessor) and compares the
    /// full 4-tuple. Epoch-aware (audit P1-2): a re-pair's fresh session
    /// (epoch bump, counters reset) must force a persist even though
    /// gen/send/recv all reset to 0. Purely a comparison — the "last
    /// persisted" mark is only advanced by [markRatchetPersisted] AFTER the
    /// write succeeds, so a failed persist is retried on the next poll
    /// instead of being skipped as "not dirty" (the desktop's optimistic mark
    /// has that retry gap; here the dirty gate is write-accurate).
    private fun ratchetDirtySinceLastPersist(peer: String): Boolean {
        val wm = try {
            uniffi.core_crypto.ratchetSessionWatermark(peer)
        } catch (_: Exception) {
            return false
        } ?: return false
        val live = longArrayOf(
            wm.pairingEpoch.toLong(),
            wm.ratchetGeneration.toLong(),
            wm.sendMessageCount.toLong(),
            wm.recvMessageCount.toLong(),
        )
        val last = lastPersistedWatermark[peer]
        return last == null || !last.contentEquals(live)
    }

    /// Record the live watermark as the last successfully PERSISTED one.
    /// Called only after the snapshot export + both prefs writes succeeded, so
    /// the in-memory high-water mark can never run ahead of the on-disk state
    /// (the exact rollback hazard the store-level watermark guard exists to
    /// prevent).
    private fun markRatchetPersisted(peer: String) {
        try {
            val wm = uniffi.core_crypto.ratchetSessionWatermark(peer) ?: return
            lastPersistedWatermark[peer] = longArrayOf(
                wm.pairingEpoch.toLong(),
                wm.ratchetGeneration.toLong(),
                wm.sendMessageCount.toLong(),
                wm.recvMessageCount.toLong(),
            )
        } catch (_: Exception) {
            // Leave the previous mark — a transient accessor failure must not
            // clear the high-water (a subsequent successful read still retries).
        }
    }

    /// AUDIT F5 (MEDIUM): shared per-peer QUIC round-trip gate. The poll loop
    /// and the SMS forwarder both acquire this BEFORE their QUIC round-trip, so
    /// only ONE QUIC round-trip per peer can exist at a time at the Android
    /// layer — a poll that is mid-flight can no longer cause the SMS forwarder's
    /// attempts to hit the Rust per-peer in-flight gate's bounded wait and fail
    /// permanently (silently dropping the SMS). The Rust gate remains as the
    /// second line for any other sender (media push, clipboard sync, pairing).
    /// A PLAIN lock (not a coroutine Mutex) because the SMS forwarder runs on a
    /// raw executor thread; the poll loop's blocking acquisition is acceptable
    /// on Dispatchers.IO.
    private val peerSendLock = java.util.concurrent.locks.ReentrantLock()

    /// Run `block` while holding the shared per-peer QUIC round-trip gate.
    /// Waits (bounded by the holder's round-trip, never stacking) instead of
    /// failing — the SMS forwarder's retry budget is spent on the round-trip,
    /// not on the gate.
    fun <T> withPeerRoundTrip(block: () -> T): T {
        peerSendLock.lock()
        try {
            return block()
        } finally {
            peerSendLock.unlock()
        }
    }

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
    ///
    /// AUDIT F7 FIX: `@Volatile` — `requestSync()` (invoked from the UI /
    /// transport thread via the injected lambda) writes this while `pollOnce`
    /// reads it on the IO thread. `@Synchronized` on `requestSync` alone does
    /// not publish the write to the reader; a plain field could miss a sync
    /// request indefinitely under memory-model reordering.
    @Volatile
    private var needSync = false

    /// AUDIT FINDING #16: heartbeat counter — every N polls, request a sync
    /// even without a detected gap, so long-lived sessions stay aligned even
    /// when no payload ever fails to decrypt (the failure signal is absent
    /// until it is too late). Kept far below the 15s desktop rate window
    /// (2.5s × 30 = 75s per heartbeat) so it never collides with the limiter.
    /// AUDIT F7 FIX: `@Volatile` for the same cross-thread visibility reason.
    @Volatile
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
                settings = currentSettings!!,
                updates = _updates,
                requestSync = { needSync = true },
            )
        }
        val ctx = context.applicationContext
        loopJob = scope.launch {
            // AUDIT F1 (HIGH): restore the persisted ratchet snapshot BEFORE the
            // first poll. The poll engine is the lifecycle-agnostic owner of
            // the cold-start restore — a reboot / START_STICKY restart starts
            // this loop with an EMPTY Rust registry, and the legacy design
            // (restore only in MainActivity) polled forever against nothing
            // until the user opened the app. Single-flight with MainActivity's
            // restore via a process-wide gate inside RatchetSessionRestorer.
            try {
                RatchetSessionRestorer.restoreIfNeeded(currentSettings!!)
            } catch (e: Exception) {
                Log.d(TAG, "Snapshot restore skipped: ${e.message}")
            }
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
                val request = transport.buildRequestBody(peer, wantSync)
                // AUDIT P3-1: a poll request whose authenticated ratchet
                // payloads could not be built (missing/unusable session) must
                // NOT proceed against the desktop — a blind round-trip would
                // still "succeed" and emit a green update while nothing ever
                // decrypts (the silent "paired but nothing syncs" class).
                // Attempt a re-restore (the snapshot import may have failed at
                // cold start) and surface a DISTINCT status so the failure is
                // observable and self-healing.
                if (!request.ratchetHealthy) {
                    Log.w(TAG, "Ratchet session unavailable — attempting re-restore (audit P3-1)")
                    try {
                        RatchetSessionRestorer.restoreIfNeeded(settings)
                    } catch (_: Exception) {}
                    _updates.tryEmit(
                        PollUpdate(
                            connected = false,
                            status = "RATCHET_UNAVAILABLE",
                            method = "None",
                            color = "red",
                            isPaired = settings.isPaired,
                            remoteClipboard = null,
                            pendingMediaAction = null,
                            pairingConfirmed = false,
                            unpairSignal = false,
                        )
                    )
                    return@withLock
                }
                val requestBody = request.body

                // Audit finding F10: route by peer key so a multi-peer mesh
                // never hits the wrong connection. Fall back to the legacy
                // ACTIVE_PEER API only when no peer identity is known (no pair).
                //
                // AUDIT F5: the round-trip runs under the SHARED per-peer gate
                // (`withPeerRoundTrip`) — the SMS forwarder acquires the same
                // gate, so the two can never stack QUIC round-trips on the
                // same peer (the SMS no longer loses to a mid-flight poll).
                val resp = withPeerRoundTrip {
                    if (peerKey.isNotEmpty()) {
                        uniffi.core_crypto.quicSendAndRecvTo(peerKey, 0x04.toUByte(), requestBody)
                    } else {
                        uniffi.core_crypto.quicSendAndRecv(0x04.toUByte(), requestBody)
                    }
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
                //
                // AUDIT P2-2 (MEDIUM): the persistence is now gated by the same
                // dirty-flag the desktop uses (audit #11). The legacy code
                // exported + wrote EncryptedSharedPreferences on EVERY poll —
                // ~69,000 Keystore AES-GCM transactions/day on this IO thread.
                // The watermark accessor is non-mutating; only when
                // (epoch, gen, send, recv) actually changed does the expensive
                // export + wrap + two-prefs-write path run.
                if (peer.isNotEmpty() && ratchetDirtySinceLastPersist(peer)) {
                    try {
                        // ratchetExportSessionWrapped serializes + wraps in Rust;
                        // we only need the peer identity (the wrap key lives in
                        // settings, read by PipeService).
                        val wrapped = uniffi.core_crypto.ratchetExportSessionWrapped(
                            peer, settings.ratchetSnapshotKey.hexToByteArray()
                        )
                        if (wrapped != null) {
                            // AUDIT FINDING #4: the rollback watermark advances
                            // ONLY when the snapshot write actually succeeded.
                            // The legacy order ran the export+persist and then
                            // unconditionally updated the watermark — if the
                            // persist failed (prefs/Keystore transient) the
                            // recorded high-water mark moved strictly ahead of
                            // the on-disk snapshot, and the next cold start
                            // refused the snapshot as a "rollback", silently
                            // un-pairing the phone.
                            val persisted = PipeService.persistWrappedSnapshot(
                                settings, wrapped.nonce, wrapped.ciphertext
                            )
                            if (persisted) {
                                // Advance the monotonic rollback watermark AFTER
                                // a successful write so a later cold-start restore
                                // refuses a rolled-back snapshot (device backup /
                                // same-user tamper) exactly like the desktop
                                // store does. `RatchetWatermarkStore.update`
                                // records max(persisted, live) and only moves
                                // forward.
                                uniffi.core_crypto.ratchetSessionWatermark(peer)?.let { wm ->
                                    RatchetWatermarkStore.update(settings, peer, wm)
                                }
                                // AUDIT P2-2: only now — after the snapshot AND
                                // the rollback watermark both landed — is the
                                // in-memory dirty-gate mark advanced, so a
                                // failed persist is retried on the next poll.
                                markRatchetPersisted(peer)
                            }
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
