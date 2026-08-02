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

class MdnsBeaconListener(private val scope: CoroutineScope) {

    private val tag = "KyberpipeMDNS"
    private val beaconPort = 9877
    private val beaconMagic = "KYBERPIPE_P2P_BEACON_V1"
    private var listenJob: Job? = null
    private var onHostDiscovered: ((BeaconHost) -> Unit)? = null

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
                            // Identity-minimal signed format: pk:ip:ts:nonce:signing_pk:sig
                            // (the device name is deliberately NOT broadcast on the
                            // unauthenticated discovery channel).
                            val parts = payload.split(":", limit = 4)
                            if (parts.size >= 3) {
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
