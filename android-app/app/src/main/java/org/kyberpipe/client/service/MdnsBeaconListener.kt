package org.kyberpipe.client.service

import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.net.DatagramPacket
import java.net.DatagramSocket

data class BeaconHost(
    val hostPkHex: String,
    val localIp: String,
    val deviceName: String,
    /**
     * ALWAYS false during discovery (audit #3). The beacon's ML-DSA signature
     * verifies only that the sender owns the signing key it EMBEDDED in the
     * beacon — any LAN host can mint its own keypair — so a discovered host is
     * an unauthenticated hint, never a trusted identity. The phone does not
     * hold the desktop's beacon signing key until pairing completes, so
     * callers must treat `verified == false` as "pairing-phishing bait" and
     * never auto-fill pairing or drive connections from it.
     */
    val verified: Boolean = false,
)

class MdnsBeaconListener(
    private val scope: CoroutineScope,
    private val appContext: android.content.Context? = null,
) {

    companion object {
        /// AUDIT F15: per-receiver seen-nonce cache (mirrors the Rust
        /// `beacon_nonce_is_replay`). The ML-DSA signature proves the sender
        /// owns the key it embedded — not that the packet is FRESH. A captured
        /// signed beacon can be replayed by any LAN host within the ±60 s
        /// timestamp window, and the declared-IP check does not stop a
        /// same-IP re-announcement. Every VERIFIED beacon records its
        /// (signing_pk, nonce) pair for the validity window; a duplicate is
        /// dropped. Bounded (pruned by TTL + capped).
        private val seenBeaconNonces =
            java.util.concurrent.ConcurrentHashMap<String, Long>()
        private const val BEACON_NONCE_TTL_MS = 60_000L
        private const val BEACON_NONCE_CACHE_MAX = 1024

        /// True when `(signing_pk, nonce)` was already accepted within the TTL
        /// (a replay); records it otherwise. Thread-safe (ConcurrentHashMap),
        /// though the listener is single-coroutine in practice.
        private fun beaconNonceIsReplay(signingPkHex: String, nonceHex: String): Boolean {
            val now = System.currentTimeMillis()
            // Amortized bounded pruning — only when near the cap.
            if (seenBeaconNonces.size >= BEACON_NONCE_CACHE_MAX) {
                seenBeaconNonces.entries.removeAll { now - it.value > BEACON_NONCE_TTL_MS }
            }
            val key = "$signingPkHex:$nonceHex"
            while (true) {
                val prev = seenBeaconNonces[key]
                if (prev == null) {
                    val existing = seenBeaconNonces.putIfAbsent(key, now)
                    if (existing == null) return false
                    if (now - existing > BEACON_NONCE_TTL_MS) {
                        // Stale entry from a concurrent writer — replace, accept.
                        seenBeaconNonces[key] = now
                        return false
                    }
                    return true
                }
                if (now - prev > BEACON_NONCE_TTL_MS) {
                    // Stale — replace and accept as a fresh beacon.
                    if (seenBeaconNonces.replace(key, prev, now)) return false
                    continue // lost the race — re-read
                }
                return true
            }
        }
    }

    private val tag = "KyberpipeMDNS"
    private val beaconPort = 9877
    private val beaconMagic = "KYBERPIPE_P2P_BEACON_V1"
    private var listenJob: Job? = null
    private var onHostDiscovered: ((BeaconHost) -> Unit)? = null

    /// Hex string → byte array (matches the helper in KyberPipePollEngine).
    private fun String.hexBytes(): ByteArray {
        val len = length
        if (len % 2 != 0) return ByteArray(0)
        return ByteArray(len / 2) { i ->
            ((Character.digit(this[i * 2], 16) shl 4) + Character.digit(this[i * 2 + 1], 16)).toByte()
        }
    }

    fun start(onHost: ((BeaconHost) -> Unit)? = null) {
        onHostDiscovered = onHost
        // AUDIT F6 FIX: stop() must actually stop the listener before a new
        // one binds the same port. The old code called `listenJob?.cancel()`
        // on a coroutine blocked in a NON-suspend `DatagramSocket.receive()`
        // — cancellation cannot interrupt the blocking call, the loop had no
        // `isActive` check and never closed the socket, so the port stayed
        // bound and a restart threw "address already in use", killing
        // discovery permanently. `stop()` closes the socket (which wakes
        // `receive()` with an exception) so the port is released; `start()` is
        // then a clean no-op while a live listener is still running.
        if (listenJob?.isActive == true) {
            Log.d(tag, "Beacon listener already running — ignoring duplicate start (audit F6)")
            return
        }
        listenJob = scope.launch(Dispatchers.IO) {
            var socket: DatagramSocket? = null
            try {
                val s = DatagramSocket(beaconPort)
                socket = s
                trackedSocket = s
                s.reuseAddress = true
                s.broadcast = true
                s.soTimeout = 3000
                Log.d(tag, "Beacon listener started on port $beaconPort")

                val buf = ByteArray(1024)
                while (coroutineContext.isActive) {
                    try {
                        val packet = DatagramPacket(buf, buf.size)
                        s.receive(packet)
                        if (!coroutineContext.isActive) break
                        val raw = String(packet.data, 0, packet.length)
                        if (raw.startsWith(beaconMagic)) {
                            val payload = raw.removePrefix("$beaconMagic:")
                            // Signed beacon format: pk:ip:ts:nonce:signing_pk:sig
                            // (the device name is deliberately NOT broadcast on the
                            // unauthenticated discovery channel).
                            val parts = payload.split(":")
                            // Audit finding F13-Android: post-pairing discovery MUST
                            // require the signed format — the legacy unsigned
                            // pk:ip[:ts] beacon is dropped (an unsigned beacon
                            // proves nothing about the sender).
                            if (parts.size < 6 || parts[4].isEmpty() || parts[5].isEmpty()) {
                                Log.w(tag, "Unsigned/malformed beacon dropped (${parts.size} fields, signed format requires 6)")
                                continue
                            }
                            val declIp = parts[1]
                            // Validate beacon timestamp (anti-replay)
                            val beaconTs = parts[2].toLongOrNull() ?: 0L
                            val now = System.currentTimeMillis() / 1000
                            if (kotlin.math.abs(now - beaconTs) > 60) {
                                Log.w(tag, "Stale beacon rejected (age=${now - beaconTs}s)")
                                continue
                            }
                            val srcIp = packet.address.hostAddress ?: ""
                            // Validate beacon source IP matches declared IP — prevents
                            // trivial IP spoofing where an attacker claims a different host.
                            if (declIp != srcIp) {
                                Log.w(tag, "Beacon IP mismatch: declared=$declIp, source=$srcIp — dropped")
                                continue
                            }
                            // AUDIT F13: verify the ML-DSA signature at DISCOVERY
                            // time. The signed region is exactly what the sender
                            // signed — `pk:ip:ts:nonce` — and the signing public key
                            // is embedded IN the beacon, so a self-consistent
                            // signature proves the sender owns that key. Without
                            // this check, any LAN host could mint its own keypair,
                            // sign its own `pk:ip:ts:nonce`, and pass every
                            // shape/timestamp/IP check — pairing-phishing bait.
                            //
                            // AUDIT #3: this proves ONLY self-ownership. The host
                            // stays UNVERIFIED for discovery purposes (see
                            // [BeaconHost.verified]) and is never a trusted identity
                            // until pairing pins the desktop's real signing key.
                            val signedRegion = "${parts[0]}:${parts[1]}:${parts[2]}:${parts[3]}"
                            val sigOk = try {
                                uniffi.core_crypto.verifyMldsaSignature(
                                    signedRegion.toByteArray(Charsets.US_ASCII),
                                    parts[5].hexBytes(),
                                    parts[4].hexBytes()
                                )
                            } catch (e: Exception) {
                                Log.e(tag, "ML-DSA verify call failed: ${e.message}")
                                false
                            }
                            if (!sigOk) {
                                Log.w(tag, "Beacon signature verification failed for $srcIp — dropped (audit F13)")
                                continue
                            }
                            // AUDIT FINDING #5: when the phone is PAIRED, the
                            // beacon's embedded signing key must EQUAL the paired
                            // desktop's signing key (persisted from the QR at
                            // pairing). A self-consistent signature proves only
                            // that the sender owns the key it embedded — any LAN
                            // host can mint its own keypair — so a key mismatch
                            // means an impostor beacon and is dropped. This is
                            // the same `listen_for_beacons_with_expected_key`
                            // check the Rust side performs. Empty expected key
                            // (legacy QR without the field) = hint only, never
                            // applied downstream.
                            val expectedSigningKey =
                                appContext?.let {
                                    org.kyberpipe.client.utils.SettingsManager(it)
                                        .pairedBeaconSigningKey
                                } ?: ""
                            if (expectedSigningKey.isNotEmpty() &&
                                !expectedSigningKey.equals(parts[4], ignoreCase = true)
                            ) {
                                Log.w(
                                    tag,
                                    "Beacon signing key does not match the paired device key — dropped (audit finding #5)"
                                )
                                continue
                            }
                            // AUDIT F15: replay within the ±60 s window — drop
                            // duplicates (mirrors the Rust beacon nonce cache).
                            if (beaconNonceIsReplay(parts[4], parts[3])) {
                                Log.w(
                                    tag,
                                    "Replayed beacon (pk+nonce already seen) from $srcIp — dropped (audit F15)"
                                )
                                continue
                            }
                            // AUDIT F3: register the beacon IP as a LAST-KNOWN-GOOD
                            // candidate address for the paired peer, so the reconnect
                            // path is never pinned to a stale stored IP (DHCP
                            // renewal / Wi-Fi→cellular handoff). The peer key is the
                            // pinned server cert hash (what quicSendAndRecvTo routes
                            // on); a no-op pre-pairing or when the peer is unknown.
                            val appCtx = appContext
                            if (appCtx != null) {
                                try {
                                    val ctx = org.kyberpipe.client.utils.SettingsManager(appCtx)
                                    val peerKey = ctx.serverCertPin.takeIf { it.isNotEmpty() }
                                        ?: ctx.peerRatchetIdentity.takeIf { it.isNotEmpty() }
                                    if (peerKey != null) {
                                        uniffi.core_crypto.quicNotePeerCandidateAddress(
                                            peerKey, declIp, 9876.toUShort()
                                        )
                                    }
                                } catch (_: Exception) {}
                            }
                            val host = BeaconHost(
                                hostPkHex = parts[0],
                                localIp = declIp,
                                // Name is intentionally absent from the beacon
                                // payload — show a neutral default.
                                deviceName = "Desktop",
                                // AUDIT #3: unauthenticated discovery — the
                                // self-embedded key is not a trusted identity.
                                verified = false,
                            )
                            Log.d(tag, "Beacon from ${packet.address.hostAddress}: UNVERIFIED host @ ${host.localIp}")
                            onHostDiscovered?.invoke(host)
                        }
                    } catch (_: java.net.SocketTimeoutException) {
                        continue
                    } catch (e: java.net.SocketException) {
                        // AUDIT F6: the socket was closed by stop() (or the
                        // peer went away) — the listener must EXIT, not loop
                        // on a closed socket.
                        if (coroutineContext.isActive) {
                            Log.d(tag, "Beacon socket closed while active: ${e.message}")
                        }
                        break
                    } catch (e: Exception) {
                        Log.e(tag, "Beacon receive error: ${e.message}")
                    }
                }
            } catch (e: Exception) {
                Log.e(tag, "Failed to start beacon listener: ${e.message}")
            } finally {
                // AUDIT F6: ALWAYS release the UDP port so a later start()
                // can re-bind it.
                try {
                    socket?.close()
                } catch (_: Exception) {}
                trackedSocket = null
            }
        }
    }

    fun stop() {
        // AUDIT F6 FIX: cancel AND close the socket so the blocking receive()
        // wakes immediately (a plain cancel() could not interrupt it).
        // `DatagramSocket.close()` releases the UDP port synchronously, so a
        // subsequent start() can re-bind without waiting for the coroutine to
        // wind down — no blocking join here (stop() is called from the UI
        // thread's onDispose and must not block).
        val job = listenJob
        if (job == null) return
        try {
            // Closing from a different thread than the receive is allowed
            // (DatagramSocket.close is thread-safe); the loop's finally also
            // closes it (a no-op once already closed).
            trackedSocket?.close()
        } catch (_: Exception) {}
        job.cancel()
        listenJob = null
        Log.d(tag, "Beacon listener stopped (socket closed, port released — audit F6)")
    }

    @Volatile
    private var trackedSocket: DatagramSocket? = null
}
