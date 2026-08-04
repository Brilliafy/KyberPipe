package org.kyberpipe.client.state

import android.content.Context
import android.widget.Toast
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import org.kyberpipe.client.service.KyberPipePollEngine
import org.kyberpipe.client.utils.SettingsManager
import java.io.ByteArrayInputStream
import java.util.zip.InflaterInputStream

/**
 * `usePairingState` — the pairing feature state (audit #8 follow-up, structural
 * decomposition). Owns the KEM/QR/deep-link pairing state machine that used to
 * live inline in the 1041-line MainScreen composable: QR/deep-link config,
 * keypair handle, SAS display, the two-phase commit mirrors, the first-connect
 * SAS modal, and the poll-flow slice that drives the pairing timeout/commit.
 *
 * Every LaunchedEffect surface is owned HERE; MainScreen is a pure tab router
 * that calls [rememberPairingState] and renders [PairingModals].
 *
 * AUDIT #1 follow-up: this state also consumes the `pairingConfirmed` slice of
 * each poll update — but NEVER the unpair signal (that lives in
 * [ConnectionState] and calls back into [clearPairingHandles] so handle
 * teardown happens exactly once, only on an explicit desktop unpair).
 */
class PairingState(
    private val settings: SettingsManager,
    private val context: Context,
    private val addLog: (String) -> Unit,
    private val setConnection: (status: String, method: String, color: androidx.compose.ui.graphics.Color) -> Unit,
    private val setCurrentTab: (org.kyberpipe.client.components.TabItem) -> Unit,
    /// Shared p2p IP coordination with ConnectionState: MainScreen owns the
    /// single source of truth; pairing WRITES it (QR p2p_ip), connection READS
    /// it (evaluateConnection).
    private val p2pIp: () -> String,
    private val setP2pIp: (String) -> Unit,
    initialPairingConfig: String?,
    initialPairingConfigWarning: String?,
) {
    /// Opaque Rust-side hybrid keypair handle (audit F7): raw private halves
    /// never enter the JVM heap.
    var keyPairHandle by mutableStateOf<ULong?>(null)

    var pairingConfigInput by mutableStateOf("")
    var sasCodeDisplay by mutableStateOf("")
    /// KEM shared-secret handle produced during the handshake; the derived
    /// session-key handle is created from it at SAS confirmation (audit F7).
    /// Only handles are held — never raw secret bytes.
    var pendingKemHandleId by mutableStateOf<ULong?>(null)
    var kemCiphertext by mutableStateOf("")

    /// QR-bound server cert hash (audit finding #15): preferred pin over
    /// runtime capture at SAS-confirm time.
    var qrServerCertHash by mutableStateOf("")
    /// Two-phase pairing commit mirrors (audit finding #6) — isPaired must NOT
    /// flip true until the desktop confirms the SAS.
    var pairingConfirmedPending by mutableStateOf(false)
    var pairingPendingStartedAt by mutableStateOf(0L)

    /// Deep-link pairing confirmation (audit finding #22).
    var linkPairingPending by mutableStateOf(initialPairingConfig != null)
    var linkPairingWarning by mutableStateOf(initialPairingConfigWarning)

    /// First-connect SAS modal.
    var showFirstConnectModal by mutableStateOf(false)
    var tempPcName by mutableStateOf("")
    var tempHostIp by mutableStateOf("")
    var tempHostPk by mutableStateOf("")

    /** Called by ConnectionState when the HOST explicitly unpaired us. */
    fun clearPairingHandles() {
        keyPairHandle = null
        pendingKemHandleId = null
    }

    /** Load the initial deep-link config and require user confirmation. */
    fun onDeepLinkConfig(cfg: String?, warning: String?) {
        if (!cfg.isNullOrEmpty()) {
            linkPairingPending = true
            linkPairingWarning = warning
            Toast.makeText(context, "Pairing link received", Toast.LENGTH_SHORT).show()
        }
    }

    /** User confirmed the deep link — load the payload into the pairing flow. */
    fun confirmDeepLink(cfg: String?) {
        if (!cfg.isNullOrEmpty()) {
            pairingConfigInput = cfg
            setCurrentTab(org.kyberpipe.client.components.TabItem.SETTINGS)
            addLog("[Pairing] Pairing config loaded from confirmed deep link")
        }
        linkPairingPending = false
    }

    /** Generate the hybrid keypair inside Rust; keep only the opaque handle. */
    fun loadKeyPair() {
        try {
            keyPairHandle = uniffi.core_crypto.generatePqKeypairHandle()
            addLog("[PQC] Loaded cryptographic provider successfully")
        } catch (e: Exception) {
            e.printStackTrace()
            addLog("[PQC] Failed to load keypair: ${e.message}")
        }
    }

    /**
     * KEM/QR/deep-link handshake. The crypto core is delegated to the SINGLE
     * canonical `PairingManager.performKemHandshake` (audit #2 follow-up): the
     * UI must never re-implement the KEM/ratchet/epoch-bump sequence inline —
     * the old inline copy missed `ratchetBumpPairingEpoch`, a real divergence.
     */
    fun performKemHandshake(json: JSONObject) {
        val hostPkHex = json.optString("pqc_pub", json.optString("host_identity_pk_hex", ""))
        val wireguardPkHex = json.optString("x25519_pub", json.optString("wireguard_pk_hex", ""))
        if (hostPkHex.isEmpty() || wireguardPkHex.isEmpty()) {
            addLog("[Pairing] Invalid QR: missing PQC public keys")
            Toast.makeText(context, "Invalid QR: missing cryptographic keys", Toast.LENGTH_LONG).show()
            return
        }
        tempHostPk = hostPkHex
        tempHostIp = json.optString("local_ip", json.optString("p2p_ip", ""))
        setP2pIp(json.optString("p2p_ip", ""))
        // Remember the QR pairing nonce so it can be echoed back to the desktop
        // — the QR-nonce binding defeats blind pairing races (audit finding #20).
        val qrNonce = json.optString("pairing_nonce_hex", "")
        if (qrNonce.isNotEmpty()) {
            settings.pendingPairingNonce = qrNonce
        }
        // QR-bound server cert hash (audit finding #5/#15).
        qrServerCertHash = json.optString("server_cert_hash", "")
        val method = json.optString("method", "")
        if (method == "p2p") {
            val ssid = json.optString("ssid", "")
            val pass = json.optString("pass", "")
            if (ssid.isNotEmpty()) {
                try {
                    val wifiManager = context.getSystemService(Context.WIFI_SERVICE) as android.net.wifi.WifiManager
                    @Suppress("DEPRECATION")
                    val wifiConfig = android.net.wifi.WifiConfiguration().apply {
                        SSID = "\"$ssid\""
                        preSharedKey = "\"$pass\""
                        allowedKeyManagement.set(android.net.wifi.WifiConfiguration.KeyMgmt.WPA_PSK)
                    }
                    @Suppress("DEPRECATION")
                    val netId = wifiManager.addNetwork(wifiConfig)
                    if (netId != -1) {
                        @Suppress("DEPRECATION")
                        wifiManager.disconnect()
                        @Suppress("DEPRECATION")
                        wifiManager.enableNetwork(netId, true)
                        @Suppress("DEPRECATION")
                        wifiManager.reconnect()
                        addLog("[P2P] Connecting to P2P network: $ssid")
                    }
                } catch (e: Exception) {
                    addLog("[P2P] Failed to connect to P2P: ${e.message}")
                }
            }
        }

        val result = org.kyberpipe.client.PairingManager.performKemHandshake(
            json, keyPairHandle, context
        ) ?: run {
            addLog("[Pairing] Aborted: no keypair handle — regenerate the keypair and retry")
            return
        }
        sasCodeDisplay = result.sasCode
        pendingKemHandleId = result.kemHandleId
        kemCiphertext = result.kemCiphertext
        val clientMlkemPkHex = result.clientMlkemPkHex
        val clientX25519PkHex = result.clientX25519PkHex

        // Do NOT set isPaired yet — the host must first receive the ciphertext.
        var hostAccepted = false
        if (tempHostIp.isNotEmpty()) {
            try {
                // AUDIT FINDING #1 (CRITICAL): the bootstrap connection MUST
                // present the per-install client identity certificate.
                val certHash = org.kyberpipe.client.PairingManager.ensureClientIdentityCert(context)
                val certDer = android.util.Base64.decode(
                    settings.clientIdentityCert, android.util.Base64.NO_WRAP
                )
                val keyDer = android.util.Base64.decode(
                    settings.clientIdentityKey, android.util.Base64.NO_WRAP
                )
                try {
                    uniffi.core_crypto.quicConnectWithClientCert(
                        tempHostIp, 9876.toUShort(), qrServerCertHash, certDer, keyDer
                    )
                    addLog("[Pairing] QUIC bridge connected to $tempHostIp:9876 (mTLS identity presented)")
                } catch (connectErr: Exception) {
                    addLog("[Pairing] QUIC connect: ${connectErr.message}")
                }
                val nonceHex = settings.pendingPairingNonce
                val jsonBody = JSONObject()
                    .put("name", settings.deviceName)
                    .put("ciphertext_hex", kemCiphertext)
                    .put("client_pk_hex", clientMlkemPkHex)
                    .put("client_x25519_pk_hex", clientX25519PkHex)
                    .put("cert_hash_hex", certHash)
                if (nonceHex.isNotEmpty()) {
                    jsonBody.put("pairing_nonce_hex", nonceHex)
                }
                val response = uniffi.core_crypto.quicSendAndRecv(0x01.toUByte(), jsonBody.toString())
                val respJson = try { JSONObject(response) } catch (_: Exception) { null }
                val status = respJson?.optString("status", "")
                if (status == "pairing_pending_sas") {
                    addLog("[Pairing] Host received ciphertext — waiting for user to verify SAS")
                    hostAccepted = true
                } else {
                    addLog("[Pairing] Host rejected handshake: $response")
                }
            } catch (e: Exception) {
                addLog("[Pairing] QUIC send failed: ${e.message}")
            }
        }
        if (hostAccepted) {
            tempPcName = "Linux Desktop workstation"
            showFirstConnectModal = true
            addLog("[Pairing] Successfully verified host identity ($tempHostIp). SAS Code: $result.sasCode")
        }
    }

    /**
     * Trigger the pairing handshake from the current [pairingConfigInput]
     * (raw JSON or Base64(zlib) QR payload). Audit F9: every block_on_sync FFI
     * call runs on Dispatchers.IO — never the Main thread.
     */
    fun handlePairingHandshake(coroutineScope: CoroutineScope) {
        coroutineScope.launch {
            withContext(Dispatchers.IO) {
                val rawInput = pairingConfigInput.trim()
                when {
                    rawInput.isEmpty() -> {
                        Toast.makeText(context, "Please scan the QR code from the desktop app", Toast.LENGTH_SHORT).show()
                    }
                    rawInput.startsWith("{") -> {
                        try {
                            performKemHandshake(JSONObject(rawInput))
                        } catch (e: Exception) {
                            Toast.makeText(context, "Handshake failed: ${e.message}", Toast.LENGTH_LONG).show()
                            addLog("[Pairing] Error: Handshake verification failed (${e.message})")
                        }
                    }
                    else -> {
                        try {
                            val decoded = android.util.Base64.decode(rawInput, android.util.Base64.DEFAULT)
                            val jsonStr = InflaterInputStream(ByteArrayInputStream(decoded)).bufferedReader().readText()
                            addLog("[Pairing] Decompressed QR payload (${jsonStr.length} chars)")
                            performKemHandshake(JSONObject(jsonStr))
                        } catch (_: Exception) {
                            Toast.makeText(context, "Invalid pairing data — scan QR from desktop or use the share link", Toast.LENGTH_LONG).show()
                            addLog("[Pairing] Error: Could not decode pairing payload")
                        }
                    }
                }
            }
        }
    }

    /**
     * Consume the PAIRING slice of a poll update (two-phase commit timeout +
     * the desktop's SAS confirmation). The unpair signal is NOT handled here —
     * see [ConnectionState] — so handle teardown happens exactly once.
     */
    fun onPollUpdate(update: KyberPipePollEngine.PollUpdate) {
        // 60s timeout mirror for the pending two-phase pairing confirmation
        // (audit finding #6) — the engine keeps polling during the window.
        if (settings.pendingPairingConfirmation && pairingPendingStartedAt > 0 &&
            System.currentTimeMillis() - pairingPendingStartedAt > 60_000L
        ) {
            settings.pendingPairingConfirmation = false
            pairingConfirmedPending = false
            pairingPendingStartedAt = 0L
            setConnection(
                "DISCONNECTED (Pairing not confirmed)",
                "None",
                androidx.compose.ui.graphics.Color.Red,
            )
            addLog("[Pairing] Pairing not confirmed by desktop (timeout)")
        }
        if (update.pairingConfirmed) {
            pairingConfirmedPending = false
            pairingPendingStartedAt = 0L
            addLog("[Pairing] Desktop confirmed SAS — pairing committed")
        }
    }

    /**
     * Finalize the cryptographic commit ONLY after manual user validation of
     * the SAS (two-phase commit, audit finding #6). Runs the block_on_sync FFI
     * calls off the Main thread (audit F9).
     */
    fun confirmSasAndCommit(coroutineScope: CoroutineScope) {
        coroutineScope.launch {
            withContext(Dispatchers.IO) {
                val realIp = p2pIp().takeIf { it.isNotEmpty() }
                    ?: tempHostIp.takeIf { it.isNotEmpty() }
                    ?: settings.pairedHostIp.takeIf { it.isNotEmpty() }
                if (realIp != null) {
                    val handle = keyPairHandle
                    val kemId = pendingKemHandleId
                    if (handle != null && kemId != null) {
                        try {
                            val sessionKeyHandle = uniffi.core_crypto.deriveSessionKeyHandle(kemId)
                            settings.sessionKeyHandle = sessionKeyHandle.toLong()
                            settings.keypairHandle = handle.toLong()
                            settings.kemHandleId = kemId.toLong()
                            addLog("[Pairing] Session key handle derived (opaque)")
                        } catch (e: Exception) {
                            addLog("[Pairing] Session key handle derive failed: ${e.message}")
                        }
                    } else {
                        addLog("[Pairing] No KEM handle — session key handle not derived")
                    }

                    // Pin the server TLS certificate ONLY after the user confirmed
                    // the SAS — never on first connect (TOFU MitM hazard).
                    val pin = qrServerCertHash.takeIf { it.isNotEmpty() }
                        ?: uniffi.core_crypto.quicCaptureServerCertHash()
                    if (pin != null && pin.isNotEmpty()) {
                        try {
                            uniffi.core_crypto.quicStoreServerPin(pin)
                            settings.serverCertPin = pin
                            addLog("[Pairing] Server cert pinned after SAS confirmation")
                        } catch (pinErr: Exception) {
                            addLog("[Pairing] Cert pin store failed: ${pinErr.message}")
                        }
                    } else {
                        addLog("[Pairing] No server cert pin available")
                    }

                    settings.pairedDeviceName = tempPcName
                    // NOT committed yet — wait for the desktop's SAS confirmation
                    // (two-phase commit, audit finding #6).
                    settings.isPaired = false
                    settings.pendingPairingConfirmation = true
                    pairingConfirmedPending = true
                    pairingPendingStartedAt = System.currentTimeMillis()
                    settings.pairedHostIp = realIp
                    showFirstConnectModal = false
                    setConnection(
                        "Waiting for desktop confirmation",
                        "None",
                        androidx.compose.ui.graphics.Color.Yellow,
                    )
                    // Restart the background engine so the sync loop starts even
                    // if PipeService was already running (audit finding #12).
                    try {
                        val serviceIntent = android.content.Intent(
                            context,
                            org.kyberpipe.client.service.PipeService::class.java
                        ).apply { action = "ACTION_SYNC_START" }
                        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                            context.startForegroundService(serviceIntent)
                        } else {
                            context.startService(serviceIntent)
                        }
                    } catch (se: Exception) {
                        addLog("[Pairing] Service restart failed: ${se.message}")
                    }
                }
            }
        }
    }
}

/** Compose entry point for [PairingState] (the `usePairingState` hook). */
@Composable
fun rememberPairingState(
    settings: SettingsManager,
    context: Context,
    addLog: (String) -> Unit,
    setConnection: (status: String, method: String, androidx.compose.ui.graphics.Color) -> Unit,
    setCurrentTab: (org.kyberpipe.client.components.TabItem) -> Unit,
    p2pIp: () -> String,
    setP2pIp: (String) -> Unit,
    initialPairingConfig: String?,
    initialPairingConfigWarning: String?,
): PairingState {
    return remember(settings, context) {
        PairingState(
            settings, context, addLog, setConnection, setCurrentTab,
            p2pIp, setP2pIp, initialPairingConfig, initialPairingConfigWarning,
        )
    }
}
