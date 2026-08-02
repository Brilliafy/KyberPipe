package org.kyberpipe.client.components

import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import android.os.Build
import android.util.Log
import android.widget.Toast
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.EaseInOutQuart
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.scaleOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.*
import org.json.JSONObject
import org.kyberpipe.client.receiver.NotificationHook
import org.kyberpipe.client.service.BeaconHost
import org.kyberpipe.client.service.KyberPipePollEngine
import org.kyberpipe.client.service.MdnsBeaconListener
import org.kyberpipe.client.service.WifiDirectManager
import org.kyberpipe.client.utils.NotificationStore
import org.kyberpipe.client.utils.PermissionHelper
import org.kyberpipe.client.utils.SettingsManager
import org.kyberpipe.client.utils.bindToWifiNetwork
import org.kyberpipe.client.utils.onFirewallDropDetected
import org.kyberpipe.client.utils.SessionKeyManager
import uniffi.core_crypto.*
import java.io.ByteArrayInputStream
import java.util.zip.InflaterInputStream

private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
private fun String.hexToByteArray(): ByteArray = chunked(2).map { it.toInt(16).toByte() }.toByteArray()

@Composable
fun KyberpipeTheme(
    themeMode: String,
    amoledMode: Boolean,
    content: @Composable () -> Unit
) {
    val isSystemDark = androidx.compose.foundation.isSystemInDarkTheme()
    val isDark = when (themeMode) {
        "light" -> false
        "dark" -> true
        else -> isSystemDark
    }

    val colors = if (isDark) {
        darkColorScheme(
            primary = Color(0xFF06B6D4),
            secondary = Color(0xFF6366F1),
            background = if (amoledMode) Color(0xFF000000) else Color(0xFF0B0D17),
            surface = if (amoledMode) Color(0xFF050505) else Color(0xFF161B2E),
            onPrimary = Color.White,
            onBackground = Color(0xFFF1F5F9)
        )
    } else {
        lightColorScheme(
            primary = Color(0xFF06B6D4),
            secondary = Color(0xFF6366F1),
            background = Color(0xFFF1F5F9),
            surface = Color.White,
            onPrimary = Color.White,
            onBackground = Color(0xFF0F172A)
        )
    }

    MaterialTheme(colorScheme = colors, content = content)
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen(
    settings: SettingsManager,
    initialPairingConfig: String?,
    initialPairingConfigWarning: String? = null,
    onClearInitialPairingConfig: () -> Unit,
    onAvatarPickerClick: () -> Unit,
    onStartService: () -> Unit,
    onStopService: () -> Unit,
    onThemeChanged: (String, Boolean) -> Unit
) {
    var currentTab by remember { mutableStateOf(TabItem.HOME) }
    var keyPair by remember { mutableStateOf<PqKeyPair?>(null) }
    var ambientLux by remember { mutableStateOf(250.0f) }

    // Zero-Trust Local Logging state
    val localLogs = remember { mutableStateListOf("[Engine] Local companion active") }
    val addLog = { msg: String ->
        localLogs.add(msg)
        if (localLogs.size > 100) {
            localLogs.removeAt(0)
        }
    }

    // Connectivity State Machine
    var connectionStatus by remember { mutableStateOf("DISCONNECTED") }
    var connectionMethod by remember { mutableStateOf("None") }
    var connectionColor by remember { mutableStateOf(Color.Red) }
    var attemptCount by remember { mutableStateOf(0) }
    val maxAttempts = 5
    var clipboardSyncJob by remember { mutableStateOf<kotlinx.coroutines.Job?>(null) }

    // Toggles
    var wifiDirectActive by remember { mutableStateOf(true) }
    var lanActive by remember { mutableStateOf(false) }
    var wireguardActive by remember { mutableStateOf(true) }
    var resolvedPublicIp by remember { mutableStateOf("Not Queried") }
    var pairingConfigInput by remember { mutableStateOf("") }
    var sasCodeDisplay by remember { mutableStateOf("") }
    var pendingSharedSecret by remember { mutableStateOf("") }
    var sessionKey by remember { mutableStateOf("") }
    var kemCiphertext by remember { mutableStateOf("") }
    var p2pIp by remember { mutableStateOf("") }

    // QR-bound server cert hash (audit finding #15): preferred pin over runtime
    // capture. UI mirror of settings.pendingPairingConfirmation for the
    // two-phase pairing commit (audit finding #6) — isPaired must NOT flip to
    // true until the desktop confirms the SAS. Declared before the poll loop
    // below, which drives the commit/timeout transitions.
    var qrServerCertHash by remember { mutableStateOf("") }
    var pairingConfirmedPending by remember { mutableStateOf(false) }
    var pairingPendingStartedAt by remember { mutableStateOf(0L) }

    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    val activity = context as org.kyberpipe.client.MainActivity

    val notifStore = remember { NotificationStore(context) }

    // Clipboard and Notification feeds (Real data synced)
    val clipboardList = remember { mutableStateListOf<AndroidClipboardRecord>() }
    val notificationsList = remember { 
        mutableStateListOf<AndroidNotificationRecord>().apply {
            addAll(notifStore.loadNotifications())
        }
    }

    LaunchedEffect(Unit) {
        val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as android.net.ConnectivityManager
        bindToWifiNetwork(connectivityManager)
        onFirewallDropDetected = {
            addLog("[Network] Firewall drop detected — desktop firewall blocking port 9876")
            connectionStatus = "DISCONNECTED (Firewall blocked)"
            connectionMethod = "None"
            connectionColor = Color.Yellow
        }
        notifStore.purgeOldRecords(settings.purgeDays, notificationsList)
    }

    // Auto-sync notifications every 30 seconds
    LaunchedEffect(Unit) {
        while (isActive) {
            delay(30000)
            val stored = notifStore.loadNotifications()
            val changed = notifStore.mergeSync(notificationsList, stored)
            if (changed) {
                addLog("[Sync] Notifications auto-synced with local store")
            }
        }
    }

    // Wi-Fi Direct P2P Manager
    val p2pManager = remember { WifiDirectManager(context) }
    DisposableEffect(Unit) {
        p2pManager.initialize(
            onState = { state ->
                p2pIp = state.groupOwnerIp
                if (state.isConnected && state.groupOwnerIp.isNotEmpty()) {
                    wifiDirectActive = true
                    addLog("[P2P] Wi-Fi Direct connected via ${state.groupOwnerIp}")
                }
            },
            onPeers = { macs ->
                addLog("[P2P] Discovered ${macs.size} peers")
            }
        )
        onDispose { p2pManager.destroy() }
    }

    // mDNS/LAN Beacon Listener
    val beaconListener = remember { MdnsBeaconListener(coroutineScope) }
    LaunchedEffect(Unit) {
        beaconListener.start { host: BeaconHost ->
            addLog("[mDNS] Discovered ${host.deviceName} @ ${host.localIp}")
            if (pairingConfigInput.isEmpty() && host.localIp.isNotEmpty()) {
                settings.pairedHostIp = host.localIp
                p2pManager.findAndConnect(host.hostPkHex)
            }
        }
    }
    DisposableEffect(Unit) {
        onDispose { beaconListener.stop() }
    }

    // When pairing config changes, try Wi-Fi Direct connection if MAC is present
    LaunchedEffect(pairingConfigInput) {
        if (pairingConfigInput.isNotEmpty() && pairingConfigInput.startsWith("{")) {
            try {
                val json = JSONObject(pairingConfigInput)
                val wifiDirectMac = json.optString("wifi_direct_mac", "")
                if (wifiDirectMac.isNotEmpty()) {
                    addLog("[P2P] Attempting Wi-Fi Direct connection to $wifiDirectMac")
                    p2pManager.findAndConnect(wifiDirectMac)
                }
            } catch (_: Exception) {}
        }
    }

    // Audit finding #22: pairing data arriving from a LINK must be confirmed by
    // the user before it is consumed. A warning (missing pairing token / cert
    // pin) makes the payload suspicious and is surfaced explicitly.
    var linkPairingPending by remember { mutableStateOf(initialPairingConfig != null) }
    var linkPairingWarning by remember { mutableStateOf(initialPairingConfigWarning) }

    // Load initial deep link config
    LaunchedEffect(initialPairingConfig) {
        if (initialPairingConfig != null && initialPairingConfig.isNotEmpty()) {
            linkPairingPending = true
            linkPairingWarning = initialPairingConfigWarning
            onClearInitialPairingConfig()
            Toast.makeText(context, "Pairing link received", Toast.LENGTH_SHORT).show()
        }
    }

    // Confirmation dialog for link-initiated pairing (audit finding #22):
    // surface the origin + any warning and require an explicit confirm before
    // the payload is loaded into the pairing flow.
    if (linkPairingPending) {
        AlertDialog(
            onDismissRequest = { linkPairingPending = false },
            title = { Text("Pairing initiated from a link") },
            text = {
                Text(
                    (linkPairingWarning?.let { "$it\n\n" } ?: "") +
                        "Verify the host identity before continuing. Only proceed if you trust the " +
                        "source of this link and the desktop it points to."
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    val cfg = initialPairingConfig
                    if (cfg != null && cfg.isNotEmpty()) {
                        pairingConfigInput = cfg
                        currentTab = TabItem.SETTINGS
                        addLog("[Pairing] Pairing config loaded from confirmed deep link")
                    }
                    linkPairingPending = false
                }) { Text("I trust this link — continue") }
            },
            dismissButton = {
                TextButton(onClick = { linkPairingPending = false }) { Text("Cancel") }
            }
        )
    }

    // Hook notification listeners
    DisposableEffect(Unit) {
        val receiver = object : android.content.BroadcastReceiver() {
            override fun onReceive(c: Context?, intent: Intent?) {
                if (intent?.action == "org.kyberpipe.client.NOTIFICATION_INTERCEPTED") {
                    val title = intent.getStringExtra("title") ?: ""
                    val text = intent.getStringExtra("text") ?: ""
                    val pkg = intent.getStringExtra("packageName") ?: ""
                    val ts = intent.getLongExtra("timestamp", System.currentTimeMillis())
                    
                    val newRecord = AndroidNotificationRecord(
                        id = "notif_${ts}_${pkg.hashCode()}",
                        title = title,
                        text = text,
                        appPackage = pkg,
                        timestamp = ts,
                        type = "local"
                    )
                    notificationsList.add(0, newRecord)
                    notifStore.saveNotifications(notificationsList)
                    addLog("[Notification] Intercepted from $pkg: $title")
                }
            }
        }
        val filter = android.content.IntentFilter("org.kyberpipe.client.NOTIFICATION_INTERCEPTED")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("UnspecifiedRegisterReceiverFlag")
            context.registerReceiver(receiver, filter)
        }
        onDispose {
            context.unregisterReceiver(receiver)
        }
    }

    // Load keys & setup listeners
    LaunchedEffect(Unit) {
        try {
            keyPair = uniffi.core_crypto.generatePqKeypair()
            addLog("[PQC] Loaded cryptographic provider successfully")
        } catch (e: Exception) {
            e.printStackTrace()
            addLog("[PQC] Failed to load keypair: ${e.message}")
        }

        // Hook real Android Clipboard
        val clipboardManager = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboardManager.addPrimaryClipChangedListener {
            val clipData = clipboardManager.primaryClip
            if (clipData != null && clipData.itemCount > 0) {
                val text = clipData.getItemAt(0).text?.toString() ?: ""
                if (text.isNotEmpty()) {
                    val exists = clipboardList.any { it.text == text }
                    if (!exists) {
                        clipboardList.add(
                            0,
                            AndroidClipboardRecord(
                                id = "clip_${System.currentTimeMillis()}",
                                text = text,
                                source = "local",
                                timestamp = System.currentTimeMillis()
                            )
                        )
                        addLog("[Clipboard] Intercepted new primary clip (${text.length} chars)")

                        if (settings.isPaired) {
                            val hostIp = p2pIp.takeIf { it.isNotEmpty() } ?: settings.pairedHostIp
                            if (hostIp.isNotEmpty()) {
                                val encrypted = SessionKeyManager.encrypt(text)
                                if (encrypted != null) {
                                    val jsonBody = JSONObject().put("encrypted", JSONObject()
                                        .put("nonce_hex", encrypted.nonce.toHex())
                                        .put("ciphertext_hex", encrypted.ciphertext.toHex())
                                    ).toString()
                                    // Clipboard sync with debounce + single in-flight.
                                    clipboardSyncJob?.cancel()
                                    clipboardSyncJob = kotlinx.coroutines.CoroutineScope(Dispatchers.IO).launch {
                                        delay(500)
                                        if (!isActive) return@launch
                                        try {
                                            uniffi.core_crypto.quicSendAndRecv(0x02.toUByte(), jsonBody)
                                        } catch (e: Exception) {
                                            addLog("[Clipboard] QUIC sync failed: ${e.message}")
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        addLog("[Service] Hooked primary clipboard listener")
    }

    // Light Sensor Listener
    DisposableEffect(Unit) {
        val sensorManager = context.getSystemService(Context.SENSOR_SERVICE) as SensorManager
        val lightSensor = sensorManager.getDefaultSensor(Sensor.TYPE_LIGHT)
        val listener = object : SensorEventListener {
            override fun onSensorChanged(event: SensorEvent?) {
                event?.let {
                    ambientLux = it.values[0]
                }
            }
            override fun onAccuracyChanged(sensor: Sensor?, accuracy: Int) {}
        }
        lightSensor?.let {
            sensorManager.registerListener(listener, it, SensorManager.SENSOR_DELAY_NORMAL)
        }
        onDispose {
            sensorManager.unregisterListener(listener)
        }
    }

    // Auto failover Connection Logic
    val evaluateConnection = {
        coroutineScope.launch {
            if (!settings.isPaired) {
                connectionStatus = "DISCONNECTED (No paired device)"
                connectionMethod = "None"
                connectionColor = Color.Red
                addLog("[Network] Idle: Waiting for pairing credentials")
                return@launch
            }

            val hostToTry = p2pIp.takeIf { it.isNotEmpty() } ?: settings.pairedHostIp.takeIf { it.isNotEmpty() }
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
                    // Ensure the QUIC bridge is established before polling.
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

    LaunchedEffect(wifiDirectActive, lanActive, settings.isPaired) {
        evaluateConnection()
    }

    // ── Single poll loop (audit findings #8/#15/#29) ────────────────────────
    // The poll loop now lives in ONE place: KyberPipePollEngine, which the
    // background service owns. The foreground SUBSCRIBES to its updates instead
    // of running a second loop against the same ratchet session (the old
    // foreground loop raced the service loop, used the legacy hex wire format
    // the desktop no longer emits, and dropped rekey acks — findings #1/#3/#15).
    // Everything decrypted/parsed below already happened inside the engine with
    // binary-TLV, rekey-aware decryption; we only mirror the result into UI state.
    LaunchedEffect(Unit) {
        // Ensure the engine is running while the UI is visible (idempotent —
        // the service also starts it; only service teardown stops it).
        KyberPipePollEngine.start(context)
        KyberPipePollEngine.updates.collect { update ->
            // 60s timeout mirror for the pending two-phase pairing confirmation
            // (audit finding #6) — the engine keeps polling during the window.
            if (settings.pendingPairingConfirmation && pairingPendingStartedAt > 0 &&
                System.currentTimeMillis() - pairingPendingStartedAt > 60_000L
            ) {
                settings.pendingPairingConfirmation = false
                pairingConfirmedPending = false
                pairingPendingStartedAt = 0L
                connectionStatus = "DISCONNECTED (Pairing not confirmed)"
                connectionMethod = "None"
                connectionColor = Color.Red
                addLog("[Pairing] Pairing not confirmed by desktop (timeout)")
            }
            connectionStatus = update.status
            connectionMethod = update.method
            connectionColor = when (update.color) {
                "green" -> Color.Green
                "yellow" -> Color.Yellow
                else -> Color.Red
            }
            if (update.pairingConfirmed) {
                pairingConfirmedPending = false
                pairingPendingStartedAt = 0L
                addLog("[Pairing] Desktop confirmed SAS — pairing committed")
            }
            if (!update.isPaired) {
                settings.isPaired = false
                settings.pairedDeviceName = ""
                connectionStatus = "DISCONNECTED (Host unpaired)"
                connectionMethod = "None"
                connectionColor = Color.Red
            }
            val latestClip = update.remoteClipboard
            if (!latestClip.isNullOrEmpty()) {
                val exists = clipboardList.any { it.text == latestClip }
                if (!exists) {
                    clipboardList.add(
                        0,
                        AndroidClipboardRecord(
                            id = "clip_${System.currentTimeMillis()}",
                            text = latestClip,
                            source = "remote",
                            timestamp = System.currentTimeMillis()
                        )
                    )
                    val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                    cm.setPrimaryClip(android.content.ClipData.newPlainText("Kyberpipe", latestClip))
                    addLog("[Clipboard] Received remote clip (${latestClip.length} chars)")
                }
            }
            update.pendingMediaAction?.let { idx ->
                NotificationHook.triggerMediaAction(idx)
                addLog("[Media] Triggered media action index $idx from PC")
            }
        }
    }

    // First Connection Modal (Dynamic profile nickname on connect)
    var showFirstConnectModal by remember { mutableStateOf(false) }
    var tempPcName by remember { mutableStateOf("") }
    var tempHostIp by remember { mutableStateOf("") }
    var tempHostPk by remember { mutableStateOf("") }

    val performKemHandshake: (org.json.JSONObject) -> Unit = { json ->
        val hostPkHex = json.optString("pqc_pub", json.optString("host_identity_pk_hex", ""))
        val wireguardPkHex = json.optString("x25519_pub", json.optString("wireguard_pk_hex", ""))
        if (hostPkHex.isNotEmpty() && wireguardPkHex.isNotEmpty()) {
            tempHostPk = hostPkHex
            tempHostIp = json.optString("local_ip", json.optString("p2p_ip", ""))
            p2pIp = json.optString("p2p_ip", "")
            // Remember the QR pairing nonce so it can be echoed back to the
            // desktop — the QR-nonce binding defeats blind pairing races
            // (audit finding #20).
            val qrNonce = json.optString("pairing_nonce_hex", "")
            if (qrNonce.isNotEmpty()) {
                settings.pendingPairingNonce = qrNonce
            }
            // QR-bound server cert hash (audit finding #5/#15): prefer it over
            // runtime capture for the SAS-confirm pin and the bootstrap QUIC
            // connect below. Empty string = legacy accept-any.
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
            val kemResponse = uniffi.core_crypto.encapsulatePqSecret(wireguardPkHex.hexToByteArray(), hostPkHex.hexToByteArray())
            val myPk = keyPair?.mlkemPk ?: ByteArray(0)
            val myPkHex = myPk.toHex()
            val computedSas = uniffi.core_crypto.generateSasCode(hostPkHex.hexToByteArray(), myPk, kemResponse.sharedSecret)
            sasCodeDisplay = computedSas
            pendingSharedSecret = kemResponse.sharedSecret.toHex()
            kemCiphertext = kemResponse.ciphertext.toHex()

            // Initialize the ratchet session NOW (single handshake path), keyed by
            // the host PK fingerprint — the same identity every later decrypt uses.
            val peerIdentity = hostPkHex
            val kp = keyPair
            try {
                uniffi.core_crypto.ratchetRemoveSession(peerIdentity)
                if (kp != null) {
                    // Rekey keypair mismatch (audit finding #1): init the ratchet
                    // with OUR OWN pairing keypair so the DH/KEM chains and the
                    // desktop's rekey proposals share the same secret state. Peer
                    // keys are the desktop's wireguard x25519 pk and host mlkem pk.
                    uniffi.core_crypto.ratchetInitSessionWithKeypair(
                        peerIdentity,
                        kemResponse.sharedSecret,
                        false,
                        kp.x25519Pk,
                        kp.x25519Sk,
                        kp.mlkemPk,
                        kp.mlkemSk,
                        wireguardPkHex.hexToByteArray(),
                        hostPkHex.hexToByteArray()
                    )
                } else {
                    addLog("[Pairing] keyPair null — falling back to legacy ratchet init")
                    uniffi.core_crypto.ratchetInitSession(
                        peerIdentity,
                        kemResponse.sharedSecret,
                        false,
                        wireguardPkHex.hexToByteArray(),
                        hostPkHex.hexToByteArray()
                    )
                }
                settings.peerRatchetIdentity = peerIdentity
                addLog("[Pairing] Ratchet session initialized (peer=$peerIdentity)")
            } catch (e: Exception) {
                addLog("[Pairing] Ratchet init failed: ${e.message}")
            }

            // Do NOT set isPaired yet — the host must first receive
            // the ciphertext and derive its own session key.
            var hostAccepted = false
            if (tempHostIp.isNotEmpty()) {
                try {
                    // Establish the QUIC bridge to the desktop BEFORE sending any
                    // stream. Bootstrap pairing pins the server cert from the QR
                    // (audit finding #15); empty pin = legacy accept-any
                    // allow-private connect (the SSRF guard — audit #6).
                    try {
                        uniffi.core_crypto.quicConnectPairingBootstrap(tempHostIp, 9876.toUShort(), qrServerCertHash)
                        addLog("[Pairing] QUIC bridge connected to $tempHostIp:9876")
                    } catch (connectErr: Exception) {
                        addLog("[Pairing] QUIC connect: ${connectErr.message}")
                    }
                    // Ensure the per-install identity certificate exists and echo
                    // its hash + the QR nonce so the desktop pins OUR identity and
                    // rejects blind races (audit #8/#20).
                    val certHash = org.kyberpipe.client.PairingManager.ensureClientIdentityCert(context)
                    val nonceHex = settings.pendingPairingNonce
                    val jsonBody = JSONObject()
                        .put("name", settings.deviceName)
                        .put("ciphertext_hex", kemCiphertext)
                        .put("client_pk_hex", myPkHex)
                        .put("client_x25519_pk_hex", keyPair?.x25519Pk?.toHex() ?: "")
                        .put("cert_hash_hex", certHash)
                    if (nonceHex.isNotEmpty()) {
                        jsonBody.put("pairing_nonce_hex", nonceHex)
                    }
                    val response = uniffi.core_crypto.quicSendAndRecv(0x01.toUByte(), jsonBody.toString())
                    val respJson = try { JSONObject(response) } catch (_: Exception) { null }
                    val status = respJson?.optString("status", "")
                    if (status == "pairing_pending_sas") {
                        // Show SAS to user for manual OOB verification
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
                addLog("[Pairing] Successfully verified host identity ($tempHostIp). SAS Code: $computedSas")
            }
        } else {
            addLog("[Pairing] Invalid QR: missing PQC public keys")
            Toast.makeText(context, "Invalid QR: missing cryptographic keys", Toast.LENGTH_LONG).show()
        }
    }


    val handlePairingHandshake = {
        val rawInput = pairingConfigInput.trim()
        when {
            rawInput.isEmpty() -> {
                Toast.makeText(context, "Please scan the QR code from the desktop app", Toast.LENGTH_SHORT).show()
            }
            rawInput.startsWith("{") -> {
                // Raw JSON pasted directly
                try {
                    performKemHandshake(JSONObject(rawInput))
                } catch (e: Exception) {
                    Toast.makeText(context, "Handshake failed: ${e.message}", Toast.LENGTH_LONG).show()
                    addLog("[Pairing] Error: Handshake verification failed (${e.message})")
                }
            }
            else -> {
                // Base64(zlib) encoded QR payload (from QR scanner or deep link)
                try {
                    val decoded = android.util.Base64.decode(rawInput, android.util.Base64.DEFAULT)
                    val jsonStr = java.util.zip.InflaterInputStream(ByteArrayInputStream(decoded)).bufferedReader().readText()
                    addLog("[Pairing] Decompressed QR payload (${jsonStr.length} chars)")
                    performKemHandshake(JSONObject(jsonStr))
                } catch (_: Exception) {
                    Toast.makeText(context, "Invalid pairing data — scan QR from desktop or use the share link", Toast.LENGTH_LONG).show()
                    addLog("[Pairing] Error: Could not decode pairing payload")
                }
            }
        }
    }

    val onCopyStacktrace = {
        val crashLog = activity.getLatestCrashLog()
        if (crashLog != null) {
            val clipboardManager = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            clipboardManager.setPrimaryClip(android.content.ClipData.newPlainText("Kyberpipe Stacktrace", crashLog))
            Toast.makeText(context, "Copied anonymized stacktrace", Toast.LENGTH_SHORT).show()
        } else {
            Toast.makeText(context, "No crash log found", Toast.LENGTH_SHORT).show()
        }
    }

    val onExportDiagnosticLogs = {
        val logText = localLogs.joinToString("\n")
        activity.shareTextFile("diagnostic_logs.txt", logText)
    }

    val onExportCrashLog = {
        val crashLog = activity.getLatestCrashLog()
        if (crashLog != null) {
            activity.shareTextFile("anonymous_crash_log.txt", crashLog)
        } else {
            Toast.makeText(context, "No crash log found", Toast.LENGTH_SHORT).show()
        }
    }

    val hasCrashLog = activity.getLatestCrashLog() != null

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        containerColor = MaterialTheme.colorScheme.background,
        bottomBar = {
            BottomNavigationBar(
                selectedTab = currentTab,
                onTabSelected = { currentTab = it }
            )
        }
    ) { padding ->
        Box(
            modifier = Modifier
                .padding(padding)
                .fillMaxSize()
        ) {
            AnimatedContent(
                targetState = currentTab,
                transitionSpec = {
                    (fadeIn(animationSpec = tween(250, easing = EaseInOutQuart)) + 
                     scaleIn(initialScale = 0.96f, animationSpec = tween(250, easing = EaseInOutQuart)))
                        .togetherWith(
                            fadeOut(animationSpec = tween(150, easing = EaseInOutQuart)) + 
                            scaleOut(targetScale = 0.96f, animationSpec = tween(150, easing = EaseInOutQuart))
                        )
                },
                label = "TabTransition"
            ) { targetTab ->
                when (targetTab) {
                    TabItem.HOME -> {
                        OverviewTab(
                            connectionStatus = connectionStatus,
                            connectionMethod = connectionMethod,
                            connectionColor = connectionColor,
                            ambientLux = ambientLux,
                            isPaired = settings.isPaired,
                            settings = settings,
                            clipboardItems = clipboardList,
                            notificationsItems = notificationsList,
                            onRetryConnection = {
                                attemptCount = 0
                                evaluateConnection()
                            },
                            onNavigateToFiles = { currentTab = TabItem.FILES },
                            onNavigateToClipboard = { currentTab = TabItem.CLIPBOARD },
                            onNavigateToNotifications = { currentTab = TabItem.NOTIFICATIONS },
                            onNavigateToSettings = { currentTab = TabItem.SETTINGS },
                            onPairMockDevice = { nodeName ->
                                tempPcName = nodeName
                                showFirstConnectModal = true
                            },
                    pairingConfigInput = pairingConfigInput,
                    onPairingConfigChange = { pairingConfigInput = it },
                    onTriggerHandshake = handlePairingHandshake
                    )
                    }
                    TabItem.FILES -> {
                        FileManagerTab(
                            isConnected = connectionColor == Color.Green,
                            settings = settings,
                            onPermissionRequest = { PermissionHelper.requestStoragePermissions(activity) },
                            onGrantLocalAccessToggle = { settings.fileAccessGrantedPhone = it },
                            onFileAction = { item ->
                            }
                        )
                    }
                    TabItem.CLIPBOARD -> {
                        ClipboardTab(
                            clipboardItems = clipboardList,
                            isConnected = connectionColor == Color.Green,
                            onAddClipboard = { text ->
                                clipboardList.add(
                                    0,
                                    AndroidClipboardRecord(
                                        id = "clip_${System.currentTimeMillis()}",
                                        text = text,
                                        source = "local",
                                        timestamp = System.currentTimeMillis()
                                    )
                                )
                            },
                            onCopyClipboard = { text ->
                                val clipboardManager = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                clipboardManager.setPrimaryClip(android.content.ClipData.newPlainText("Kyberpipe", text))
                                Toast.makeText(context, "Copied to phone clipboard", Toast.LENGTH_SHORT).show()
                            },
                            onDeleteClipboard = { id ->
                                clipboardList.removeAll { it.id == id }
                            },
                            onConnectRequest = { currentTab = TabItem.SETTINGS }
                        )
                    }
                    TabItem.NOTIFICATIONS -> {
                        NotificationsTab(
                            notifications = notificationsList,
                            isConnected = connectionColor == Color.Green,
                            onDismiss = { id ->
                                val idx = notificationsList.indexOfFirst { it.id == id }
                                if (idx != -1) {
                                    val item = notificationsList[idx]
                                    notificationsList[idx] = item.copy(isDismissed = true, updatedAt = System.currentTimeMillis())
                                    notifStore.saveNotifications(notificationsList)
                                    addLog("[Notification] Dismissed $id. Sync queued.")
                                }
                            },
                            onConnectRequest = { currentTab = TabItem.SETTINGS }
                        )
                    }
                    TabItem.SETTINGS -> {
                        SettingsTab(
                            settings = settings,
                            keyPair = keyPair,
                            pairingConfigInput = pairingConfigInput,
                            onPairingConfigChange = { pairingConfigInput = it },
                            onTriggerHandshake = handlePairingHandshake,
                            onAvatarPickerClick = onAvatarPickerClick,
                            onSaveSettings = { onThemeChanged(settings.themeMode, settings.amoledMode) },
                            wifiDirectActive = wifiDirectActive,
                            lanActive = lanActive,
                            wireguardActive = wireguardActive,
                            onWifiDirectToggled = { wifiDirectActive = it },
                            onLanToggled = { lanActive = it },
                            onWireguardToggled = { wireguardActive = it },
                            localLogs = localLogs,
                            onCopyStacktrace = onCopyStacktrace,
                            onExportDiagnosticLogs = onExportDiagnosticLogs,
                            onExportCrashLog = onExportCrashLog,
                            hasCrashLog = hasCrashLog,
                            onPanicTriggered = {
                                try {
                                    uniffi.core_crypto.triggerPanicHardwareWipe()
                                    settings.isPaired = false
                                    connectionStatus = "SELF_DESTRUCTED"
                                    connectionColor = Color.Red
                                    Toast.makeText(context, "Keys zeroized!", Toast.LENGTH_LONG).show()
                                } catch (e: Exception) {
                                    e.printStackTrace()
                                }
                            }
                        )
                    }
                }
            }
        }

        // Profile input Modal on Pairing
        if (showFirstConnectModal) {
            AlertDialog(
                onDismissRequest = { showFirstConnectModal = false },
                title = { Text("Verify SAS Code") },
                text = {
                    Column {
                        Text("Ensure this SAS code matches the one shown on your PC exactly:", fontSize = 14.sp, fontWeight = androidx.compose.ui.text.font.FontWeight.SemiBold)
                        Spacer(modifier = Modifier.height(15.dp))
                        Text(
                            text = sasCodeDisplay, 
                            fontSize = 32.sp, 
                            fontWeight = androidx.compose.ui.text.font.FontWeight.Bold,
                            color = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.fillMaxWidth(),
                            textAlign = androidx.compose.ui.text.style.TextAlign.Center,
                            letterSpacing = 4.sp
                        )
                        Spacer(modifier = Modifier.height(20.dp))
                        Text("Assign a visual nickname for this PC node:", fontSize = 13.sp)
                        Spacer(modifier = Modifier.height(10.dp))
                        OutlinedTextField(
                            value = tempPcName,
                            onValueChange = { tempPcName = it },
                            label = { Text("Visual Nickname") },
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedTextColor = MaterialTheme.colorScheme.onSurface,
                                unfocusedTextColor = MaterialTheme.colorScheme.onSurface,
                                focusedLabelColor = MaterialTheme.colorScheme.onSurface,
                                unfocusedLabelColor = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f),
                                cursorColor = MaterialTheme.colorScheme.onSurface
                            )
                        )
                    }
                },
                confirmButton = {
                    Button(
                        onClick = {
                            val realIp = p2pIp.takeIf { it.isNotEmpty() }
                                ?: tempHostIp.takeIf { it.isNotEmpty() }
                                ?: settings.pairedHostIp.takeIf { it.isNotEmpty() }
                            if (realIp != null) {
                                // Finalize cryptographic commit ONLY after manual user validation of SAS.
                                // Two-phase commit (audit finding #6): the phone must NOT claim
                                // isPaired before the desktop confirms the SAS — it may reject the
                                // code or time out. We persist everything except the commit signal
                                // and let the poll loop commit once the desktop reports is_paired.
                                // Canonical salt — SAME bytes as the desktop (audit finding #2).
                                sessionKey = uniffi.core_crypto.deriveSessionKey(
                                    pendingSharedSecret.hexToByteArray(),
                                    uniffi.core_crypto.sessionDerivationSalt()
                                ).toHex()
                                SessionKeyManager.initFromHex(sessionKey)
                                settings.sessionKey = sessionKey

                                // Pin the server TLS certificate ONLY after the user
                                // confirmed the SAS — never on first connect (TOFU MitM
                                // hazard). Prefer the QR-bound hash (audit finding #15);
                                // fall back to runtime capture for QRs without a hash.
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
                                // NOT committed yet — wait for the desktop's SAS
                                // confirmation (two-phase commit, audit finding #6).
                                settings.isPaired = false
                                settings.pendingPairingConfirmation = true
                                pairingConfirmedPending = true
                                pairingPendingStartedAt = System.currentTimeMillis()
                                settings.pairedHostIp = realIp
                                showFirstConnectModal = false
                                connectionStatus = "Waiting for desktop confirmation"
                                connectionMethod = "None"
                                connectionColor = Color.Yellow
                                // Restart the background engine so the sync loop
                                // starts even if PipeService was already running
                                // when pairing completed (audit finding #12).
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
                    ) {
                        Text("Verify & Connect")
                    }
                },
                dismissButton = {
                    TextButton(onClick = { showFirstConnectModal = false }) {
                        Text("Reject (Mismatch)", color = MaterialTheme.colorScheme.error)
                    }
                }
            )
        }
    }
}
