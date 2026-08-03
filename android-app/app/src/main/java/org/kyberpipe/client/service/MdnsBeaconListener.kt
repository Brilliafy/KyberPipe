package org.kyberpipe.client.service

import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress

data class BeaconHost(
    val hostPkHex: String,
    val localIp: String,
    val deviceName: String
)

class MdnsBeaconListener(
    private val scope: CoroutineScope,
    private val appContext: android.content.Context? = null,
) {

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
        listenJob?.cancel()
        listenJob = scope.launch(Dispatchers.IO) {
            try {
                val socket = DatagramSocket(beaconPort)
                socket.reuseAddress = true
                socket.broadcast = true
                socket.soTimeout = 3000
                Log.d(tag, "Beacon listener started on port $beaconPort")

                val buf = ByteArray(1024)
                while (true) {
                    try {
                        val packet = DatagramPacket(buf, buf.size)
                        socket.receive(packet)
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
                                deviceName = "Desktop"
                            )
                            Log.d(tag, "Beacon from ${packet.address.hostAddress}: ${host.deviceName} @ ${host.localIp}")
                            onHostDiscovered?.invoke(host)
                        }
                    } catch (_: java.net.SocketTimeoutException) {
                        continue
                    } catch (e: Exception) {
                        Log.e(tag, "Beacon receive error: ${e.message}")
                    }
                }
            } catch (e: Exception) {
                Log.e(tag, "Failed to start beacon listener: ${e.message}")
            }
        }
    }

    fun stop() {
        listenJob?.cancel()
        listenJob = null
        Log.d(tag, "Beacon listener stopped")
    }
}
