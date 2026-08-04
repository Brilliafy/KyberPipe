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
import org.kyberpipe.client.utils.SettingsManager

/**
 * `useConnectionState` — the connection feature state (audit #8 follow-up,
 * structural decomposition). Owns the connectivity state machine (status /
 * method / color), the beacon listener, the ambient light sensor, and the
 * POLL slice that mirrors connection status AND the explicit-unpair signal.
 *
 * AUDIT #1 follow-up: the DISCONNECTED emissions from the engine carry the
 * persisted `isPaired` (never a derived false), and `destroyPairingHandles`
 * runs ONLY when the desktop explicitly reported `is_paired: false`
 * (`update.unpairSignal`) — never on a transient connectivity failure. The
 * teardown calls back into [PairingState.clearPairingHandles] so the keypair /
 * KEM handles are released exactly once, on that single signal.
 *
 * Wi-Fi Direct (P2P) support was REMOVED (audit finding #1): the group was
 * never actually WPA2-secured and the Android join path was a dead stub, so
 * the WifiDirectManager, its `onWifiDirectStateChange` callback and the
 * `p2pIp` source are gone.
 */
class ConnectionState(
    private val settings: SettingsManager,
    private val context: Context,
    private val addLog: (String) -> Unit,
    private val coroutineScope: CoroutineScope,
    private val onExplicitUnpair: () -> Unit,
    /// Created in `rememberConnectionState` (remember is composable-only);
    /// the holder owns their lifecycle through the router's DisposableEffect.
    val beaconListener: MdnsBeaconListener,
) {
    var connectionStatus by mutableStateOf("DISCONNECTED")
    var connectionMethod by mutableStateOf("None")
    var connectionColor by mutableStateOf(Color.Red)
    var attemptCount by mutableStateOf(0)
    var ambientLux by mutableStateOf(250.0f)

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

            val hostToTry = settings.pairedHostIp.takeIf { it.isNotEmpty() }
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

    fun onBeaconDiscovered(host: BeaconHost) {
        // AUDIT #3 + FINDING #5: discovery beacons are UNAUTHENTICATED hints.
        // The ML-DSA signature proves only that the sender owns the key it
        // EMBEDDED — any LAN host can mint its own keypair. The phone therefore
        // NEVER auto-applies a beacon IP to the connection target: the legacy
        // code wrote `pairedHostIp = host.localIp` when paired, so an attacker
        // could inject its own IP and redirect every poll (persistent DoS plus
        // a presence probe of the phone). The paired host IP is set ONLY from
        // the QR config at pairing (PairingState.confirmSasAndCommit) and is
        // never derived from an unverified hint. A beacon is surfaced as a
        // diagnostic hint at most; the listener independently drops beacons
        // whose embedded signing key is not the paired desktop's (finding #5).
        addLog("[mDNS] Discovered UNVERIFIED host @ ${host.localIp} (hint only — never applied)")
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
    onExplicitUnpair: () -> Unit,
): ConnectionState {
    val scope = rememberCoroutineScope()
    val beaconListener = remember(context) { MdnsBeaconListener(scope, context.applicationContext) }
    return remember(settings, context) {
        ConnectionState(
            settings, context, addLog, scope, onExplicitUnpair,
            beaconListener,
        )
    }
}
