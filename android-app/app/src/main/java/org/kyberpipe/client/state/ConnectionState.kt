package org.kyberpipe.client.state

import android.content.Context
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.graphics.Color
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.kyberpipe.client.service.BeaconHost
import org.kyberpipe.client.service.KyberPipePollEngine
import org.kyberpipe.client.service.MdnsBeaconListener
import org.kyberpipe.client.service.WifiDirectManager
import org.kyberpipe.client.utils.SettingsManager

/**
 * `useConnectionState` — the connection feature state (audit #8 follow-up,
 * structural decomposition). Owns the connectivity state machine (status /
 * method / color), the Wi-Fi Direct manager + beacon listener, the ambient
 * light sensor, and the POLL slice that mirrors connection status AND the
 * explicit-unpair signal.
 *
 * AUDIT #1 follow-up: the DISCONNECTED emissions from the engine carry the
 * persisted `isPaired` (never a derived false), and `destroyPairingHandles`
 * runs ONLY when the desktop explicitly reported `is_paired: false`
 * (`update.unpairSignal`) — never on a transient connectivity failure. The
 * teardown calls back into [PairingState.clearPairingHandles] so the keypair /
 * KEM handles are released exactly once, on that single signal.
 */
class ConnectionState(
    private val settings: SettingsManager,
    private val context: Context,
    private val addLog: (String) -> Unit,
    private val coroutineScope: CoroutineScope,
    private val p2pIpProvider: () -> String,
    private val onExplicitUnpair: () -> Unit,
    /// Created in `rememberConnectionState` (remember is composable-only);
    /// the holder owns their lifecycle through the router's DisposableEffect.
    val p2pManager: WifiDirectManager,
    val beaconListener: MdnsBeaconListener,
) {
    var connectionStatus by mutableStateOf("DISCONNECTED")
    var connectionMethod by mutableStateOf("None")
    var connectionColor by mutableStateOf(Color.Red)
    var attemptCount by mutableStateOf(0)
    var ambientLux by mutableStateOf(250.0f)

    var wifiDirectActive by mutableStateOf(true)
    var lanActive by mutableStateOf(false)
    var wireguardActive by mutableStateOf(true)
    var resolvedPublicIp by mutableStateOf("Not Queried")

    val evaluateConnection: () -> Unit = {
        coroutineScope.launch {
            if (!settings.isPaired) {
                connectionStatus = "DISCONNECTED (No paired device)"
                connectionMethod = "None"
                connectionColor = Color.Red
                addLog("[Network] Idle: Waiting for pairing credentials")
                return@launch
            }

            val hostToTry = p2pIpProvider().takeIf { it.isNotEmpty() }
                ?: settings.pairedHostIp.takeIf { it.isNotEmpty() }
            if (hostToTry == null) {
                connectionStatus = "DISCONNECTED (No host IP)"
                connectionMethod = "None"
                connectionColor = Color.Red
                addLog("[Network] No host IP available")
                return@launch
            }

            connectionStatus = "CONNECTING..."
            connectionColor = Color.Yellow
            addLog("[Network] Testing connection to $hostToTry:9876")

            val reachable = withContext(Dispatchers.Default) {
                try {
                    try {
                        uniffi.core_crypto.quicConnect(hostToTry, 9876.toUShort(), settings.serverCertPin)
                    } catch (_: Exception) {}
                    val result = uniffi.core_crypto.quicSendAndRecv(0x04.toUByte(), "")
                    result.isNotEmpty()
                } catch (_: Exception) {
                    false
                }
            }

            if (reachable) {
                connectionStatus = "ACTIVE"
                connectionMethod = "LAN"
                connectionColor = Color.Green
                attemptCount = 0
                addLog("[Network] Host reachable at $hostToTry:9876")
            } else {
                connectionStatus = "DISCONNECTED (Unreachable)"
                connectionMethod = "None"
                connectionColor = Color.Red
                addLog("[Network] Host $hostToTry:9876 not reachable")
            }
        }
    }

    /** Direct status write used by PairingState's two-phase-commit transitions. */
    fun setConnection(status: String, method: String, color: Color) {
        connectionStatus = status
        connectionMethod = method
        connectionColor = color
    }

    fun onWifiDirectStateChange(groupOwnerIp: String, connected: Boolean) {
        if (connected && groupOwnerIp.isNotEmpty()) {
            wifiDirectActive = true
            addLog("[P2P] Wi-Fi Direct connected via $groupOwnerIp")
        }
    }

    fun onBeaconDiscovered(host: BeaconHost) {
        // AUDIT #3: discovery beacons are UNAUTHENTICATED hints — never render a
        // real device name, never auto-fill pairing, never drive a connection.
        // The only permitted use is refreshing the LAST-KNOWN-GOOD IP for an
        // ALREADY-PAIRED host (the pinned server cert authenticates the QUIC
        // connection, not the beacon).
        addLog("[mDNS] Discovered UNVERIFIED host @ ${host.localIp}")
        if (settings.isPaired && settings.pairedHostIp.isEmpty() && host.localIp.isNotEmpty()) {
            settings.pairedHostIp = host.localIp
            addLog("[mDNS] Updated paired host IP from beacon hint: ${host.localIp}")
        }
    }

    /**
     * Consume the CONNECTION slice of a poll update: status/color mirror plus
     * the explicit-unpair signal. `update.isPaired` alone is NEVER enough to
     * tear down handles — a DISCONNECTED (connectivity) update carries the
     * persisted isPaired and `unpairSignal=false`, so a network blip can never
     * un-pair the phone (audit #1 follow-up).
     */
    fun onPollUpdate(update: KyberPipePollEngine.PollUpdate) {
        connectionStatus = update.status
        connectionMethod = update.method
        connectionColor = when (update.color) {
            "green" -> Color.Green
            "yellow" -> Color.Yellow
            else -> Color.Red
        }
        if (update.unpairSignal) {
            // Audit finding F7 + AUDIT #1 follow-up: the HOST explicitly
            // unpaired us — release every Rust-side pairing handle. This is the
            // ONLY path that destroys pairing handles.
            settings.isPaired = false
            settings.pairedDeviceName = ""
            org.kyberpipe.client.PairingManager.destroyPairingHandles(context)
            onExplicitUnpair()
            connectionStatus = "DISCONNECTED (Host unpaired)"
            connectionMethod = "None"
            connectionColor = Color.Red
        } else if (!update.isPaired) {
            // Not paired and no explicit unpair signal (first run, or a
            // connectivity failure while already unpaired): reflect the UI state
            // without touching pairing handles.
            connectionStatus = "DISCONNECTED (Not paired)"
            connectionMethod = "None"
            connectionColor = Color.Red
        }
    }
}

/** Compose entry point for [ConnectionState] (the `useConnectionState` hook). */
@Composable
fun rememberConnectionState(
    settings: SettingsManager,
    context: Context,
    addLog: (String) -> Unit,
    p2pIpProvider: () -> String,
    onExplicitUnpair: () -> Unit,
): ConnectionState {
    val scope = rememberCoroutineScope()
    val p2pManager = remember(context) { WifiDirectManager(context) }
    val beaconListener = remember(context) { MdnsBeaconListener(scope, context.applicationContext) }
    return remember(settings, context) {
        ConnectionState(
            settings, context, addLog, scope, p2pIpProvider, onExplicitUnpair,
            p2pManager, beaconListener,
        )
    }
}
