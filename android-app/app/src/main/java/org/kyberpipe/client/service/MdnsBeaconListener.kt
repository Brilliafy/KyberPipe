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
                            val parts = payload.split(":", limit = 3)
                            if (parts.size >= 2) {
                                val host = BeaconHost(
                                    hostPkHex = parts[0],
                                    localIp = parts[1],
                                    deviceName = if (parts.size >= 3) parts[2] else "Desktop"
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
