package org.kyberpipe.client.components

import android.content.Context
import android.os.Build
import android.widget.Toast
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.EaseInOutQuart
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.scaleOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import org.kyberpipe.client.receiver.NotificationHook
import org.kyberpipe.client.service.KyberPipePollEngine
import org.kyberpipe.client.state.PairingModals
import org.kyberpipe.client.state.rememberClipboardState
import org.kyberpipe.client.state.rememberConnectionState
import org.kyberpipe.client.state.rememberMediaState
import org.kyberpipe.client.state.rememberNotificationState
import org.kyberpipe.client.state.rememberPairingState
import org.kyberpipe.client.utils.PermissionHelper
import org.kyberpipe.client.utils.SettingsManager
import org.kyberpipe.client.utils.bindToWifiNetwork
import org.kyberpipe.client.utils.onFirewallDropDetected
import uniffi.core_crypto.*
import org.json.JSONObject

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

/**
 * MainScreen — the TAB ROUTER (audit #8 follow-up, structural decomposition).
 *
 * All feature state now lives in dedicated holders created by the
 * `use*State` hooks below:
 *
 *  - [rememberPairingState]   — KEM/QR/deep-link pairing, SAS modal (PairingModals)
 *  - [rememberConnectionState] — connectivity state machine, Wi-Fi Direct +
 *    beacon listeners, the explicit-unpair signal
 *  - [rememberClipboardState] — clipboard history + OS clipboard hook
 *  - [rememberMediaState]     — remote media-action trigger
 *  - [rememberNotificationState] — notification mirror + store auto-sync
 *
 * This composable owns ONLY the tab routing and the single poll-loop
 * subscription that fans each update out to the feature slices — preserving
 * the deterministic per-update ordering the old monolithic collector had.
 */
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

    // Zero-Trust Local Logging state
    val localLogs = remember { mutableStateListOf("[Engine] Local companion active") }
    val addLog = { msg: String ->
        localLogs.add(msg)
        if (localLogs.size > 100) {
            localLogs.removeAt(0)
        }
    }

    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    val activity = context as org.kyberpipe.client.MainActivity

    // ── Feature state holders (audit #8 follow-up) ──────────────────────────
    // `p2pIp` is genuinely shared between pairing (WRITER: QR p2p_ip, Wi-Fi
    // Direct callback) and connection (READER: evaluateConnection), so the
    // router owns the single source of truth and both holders get a
    // provider/setter. The unpair signal from ConnectionState clears the
    // pairing handles exactly once via `clearPairingHandles`, late-bound below
    // so the two holders need no constructor forward references.
    var p2pIp by remember { mutableStateOf("") }
    var unpairHandler: (() -> Unit)? = null
    val connection = rememberConnectionState(
        settings, context, addLog,
        p2pIpProvider = { p2pIp },
        onExplicitUnpair = { unpairHandler?.invoke() },
    )
    val pairing = rememberPairingState(
        settings, context, addLog,
        setConnection = { status, method, color ->
            // PairingState's two-phase-commit timeout / waiting transitions
            // write through to ConnectionState's fields.
            connection.setConnection(status, method, color)
        },
        setCurrentTab = { currentTab = it },
        p2pIp = { p2pIp },
        setP2pIp = { p2pIp = it },
        initialPairingConfig,
        initialPairingConfigWarning,
    )
    // Bind the unpair teardown now that both holders exist (fires only on an
    // explicit desktop unpair — never on a transient connectivity failure).
    unpairHandler = { pairing.clearPairingHandles() }
    val clipboard = rememberClipboardState(settings, context, addLog)
    val media = rememberMediaState(addLog)
    val notification = rememberNotificationState(context, addLog)

    // ── Startup bindings (single-shot LaunchedEffects) ──────────────────────
    LaunchedEffect(Unit) {
        val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as android.net.ConnectivityManager
        bindToWifiNetwork(connectivityManager)
        onFirewallDropDetected = {
            addLog("[Network] Firewall drop detected — desktop firewall blocking port 9876")
            connection.onPollUpdate(
                KyberPipePollEngine.PollUpdate(
                    connected = false,
                    status = "DISCONNECTED (Firewall blocked)",
                    method = "None",
                    color = "yellow",
                    isPaired = settings.isPaired,
                    remoteClipboard = null,
                    pendingMediaAction = null,
                    pairingConfirmed = false,
                )
            )
        }
    }

    // Wi-Fi Direct P2P Manager (owned by ConnectionState).
    DisposableEffect(Unit) {
        connection.p2pManager.initialize(
            onState = { state ->
                p2pIp = state.groupOwnerIp
                connection.onWifiDirectStateChange(state.groupOwnerIp, state.isConnected)
            },
            onPeers = { macs ->
                addLog("[P2P] Discovered ${macs.size} peers")
            }
        )
        onDispose { connection.p2pManager.destroy() }
    }

    // mDNS/LAN Beacon Listener (unauthenticated hints only — audit #3).
    LaunchedEffect(Unit) {
        connection.beaconListener.start { host ->
            connection.onBeaconDiscovered(host)
        }
    }
    DisposableEffect(Unit) {
        onDispose { connection.beaconListener.stop() }
    }

    // When pairing config changes, try Wi-Fi Direct connection if MAC is present.
    LaunchedEffect(pairing.pairingConfigInput) {
        if (pairing.pairingConfigInput.isNotEmpty() && pairing.pairingConfigInput.startsWith("{")) {
            try {
                val json = JSONObject(pairing.pairingConfigInput)
                val wifiDirectMac = json.optString("wifi_direct_mac", "")
                if (wifiDirectMac.isNotEmpty()) {
                    addLog("[P2P] Attempting Wi-Fi Direct connection to $wifiDirectMac")
                    connection.p2pManager.findAndConnect(wifiDirectMac)
                }
            } catch (_: Exception) {}
        }
    }

    // Load initial deep link config (requires user confirmation — audit #22).
    LaunchedEffect(initialPairingConfig) {
        pairing.onDeepLinkConfig(initialPairingConfig, initialPairingConfigWarning)
        onClearInitialPairingConfig()
    }

    // Hook notification mirror receiver (owned by NotificationState).
    DisposableEffect(Unit) {
        notification.registerReceiver()
        onDispose { notification.unregisterReceiver() }
    }

    // Load the Rust keypair handle + hook the OS clipboard (feature-owned).
    LaunchedEffect(Unit) {
        pairing.loadKeyPair()
        clipboard.hookPrimaryClipboard()
    }

    // Light Sensor Listener (ambient lux → ConnectionState).
    DisposableEffect(Unit) {
        val sensorManager = context.getSystemService(Context.SENSOR_SERVICE) as android.hardware.SensorManager
        val lightSensor = sensorManager.getDefaultSensor(android.hardware.Sensor.TYPE_LIGHT)
        val listener = object : android.hardware.SensorEventListener {
            override fun onSensorChanged(event: android.hardware.SensorEvent?) {
                event?.let { connection.ambientLux = it.values[0] }
            }
            override fun onAccuracyChanged(sensor: android.hardware.Sensor?, accuracy: Int) {}
        }
        lightSensor?.let {
            sensorManager.registerListener(listener, it, android.hardware.SensorManager.SENSOR_DELAY_NORMAL)
        }
        onDispose {
            sensorManager.unregisterListener(listener)
        }
    }

    // Notification store auto-sync every 30 s.
    LaunchedEffect(Unit) {
        notification.startAutoSync(coroutineScope, settings.purgeDays)
    }

    // Auto failover Connection evaluation.
    LaunchedEffect(connection.wifiDirectActive, connection.lanActive, settings.isPaired) {
        connection.evaluateConnection()
    }

    // ── Single poll loop (audit findings #8/#15/#29) ────────────────────────
    // The poll loop lives in ONE place: KyberPipePollEngine. The foreground
    // SUBSCRIBES and fans each update out to the feature slices in a fixed
    // order (pairing → connection → clipboard → media), preserving the
    // deterministic ordering the old monolithic collector had while each
    // feature owns its own state (audit #8 follow-up).
    LaunchedEffect(Unit) {
        KyberPipePollEngine.start(context)
        KyberPipePollEngine.updates.collect { update ->
            pairing.onPollUpdate(update)
            connection.onPollUpdate(update)
            clipboard.onPollUpdate(update)
            media.onPollUpdate(update)
        }
    }

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
                            connectionStatus = connection.connectionStatus,
                            connectionMethod = connection.connectionMethod,
                            connectionColor = connection.connectionColor,
                            ambientLux = connection.ambientLux,
                            isPaired = settings.isPaired,
                            settings = settings,
                            clipboardItems = clipboard.clipboardList,
                            notificationsItems = notification.notificationsList,
                            onRetryConnection = {
                                connection.attemptCount = 0
                                connection.evaluateConnection()
                            },
                            onNavigateToFiles = { currentTab = TabItem.FILES },
                            onNavigateToClipboard = { currentTab = TabItem.CLIPBOARD },
                            onNavigateToNotifications = { currentTab = TabItem.NOTIFICATIONS },
                            onNavigateToSettings = { currentTab = TabItem.SETTINGS },
                            onPairMockDevice = { nodeName ->
                                pairing.tempPcName = nodeName
                                pairing.showFirstConnectModal = true
                            },
                            pairingConfigInput = pairing.pairingConfigInput,
                            onPairingConfigChange = { pairing.pairingConfigInput = it },
                            onTriggerHandshake = { pairing.handlePairingHandshake(coroutineScope) }
                        )
                    }
                    TabItem.FILES -> {
                        FileManagerTab(
                            isConnected = connection.connectionColor == Color.Green,
                            settings = settings,
                            onPermissionRequest = { PermissionHelper.requestStoragePermissions(activity) },
                            onGrantLocalAccessToggle = { settings.fileAccessGrantedPhone = it },
                            onFileAction = { }
                        )
                    }
                    TabItem.CLIPBOARD -> {
                        ClipboardTab(
                            clipboardItems = clipboard.clipboardList,
                            isConnected = connection.connectionColor == Color.Green,
                            onAddClipboard = { text -> clipboard.addLocalClip(text) },
                            onCopyClipboard = { text -> clipboard.copyToSystemClipboard(text) },
                            onDeleteClipboard = { id -> clipboard.deleteClip(id) },
                            onConnectRequest = { currentTab = TabItem.SETTINGS }
                        )
                    }
                    TabItem.NOTIFICATIONS -> {
                        NotificationsTab(
                            notifications = notification.notificationsList,
                            isConnected = connection.connectionColor == Color.Green,
                            onDismiss = { id -> notification.dismiss(id) },
                            onConnectRequest = { currentTab = TabItem.SETTINGS }
                        )
                    }
                    TabItem.SETTINGS -> {
                        SettingsTab(
                            settings = settings,
                            keyPairHandle = pairing.keyPairHandle,
                            pairingConfigInput = pairing.pairingConfigInput,
                            onPairingConfigChange = { pairing.pairingConfigInput = it },
                            onTriggerHandshake = { pairing.handlePairingHandshake(coroutineScope) },
                            onAvatarPickerClick = onAvatarPickerClick,
                            onSaveSettings = { onThemeChanged(settings.themeMode, settings.amoledMode) },
                            wifiDirectActive = connection.wifiDirectActive,
                            lanActive = connection.lanActive,
                            wireguardActive = connection.wireguardActive,
                            onWifiDirectToggled = { connection.wifiDirectActive = it },
                            onLanToggled = { connection.lanActive = it },
                            onWireguardToggled = { connection.wireguardActive = it },
                            localLogs = localLogs,
                            onCopyStacktrace = {
                                val crashLog = activity.getLatestCrashLog()
                                if (crashLog != null) {
                                    val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
                                    cm.setPrimaryClip(android.content.ClipData.newPlainText("Kyberpipe Stacktrace", crashLog))
                                    Toast.makeText(context, "Copied anonymized stacktrace", Toast.LENGTH_SHORT).show()
                                } else {
                                    Toast.makeText(context, "No crash log found", Toast.LENGTH_SHORT).show()
                                }
                            },
                            onExportDiagnosticLogs = {
                                activity.shareTextFile("diagnostic_logs.txt", localLogs.joinToString("\n"))
                            },
                            onExportCrashLog = {
                                val crashLog = activity.getLatestCrashLog()
                                if (crashLog != null) {
                                    activity.shareTextFile("anonymous_crash_log.txt", crashLog)
                                } else {
                                    Toast.makeText(context, "No crash log found", Toast.LENGTH_SHORT).show()
                                }
                            },
                            hasCrashLog = activity.getLatestCrashLog() != null,
                            onPanicTriggered = {
                                // Audit finding F7: self-destruct must also release
                                // the Rust-side pairing handles.
                                org.kyberpipe.client.PairingManager.destroyPairingHandles(context)
                                pairing.clearPairingHandles()
                                try {
                                    uniffi.core_crypto.triggerPanicHardwareWipe()
                                    settings.isPaired = false
                                    connection.onPollUpdate(
                                        KyberPipePollEngine.PollUpdate(
                                            connected = false,
                                            status = "SELF_DESTRUCTED",
                                            method = "None",
                                            color = "red",
                                            isPaired = false,
                                            remoteClipboard = null,
                                            pendingMediaAction = null,
                                            pairingConfirmed = false,
                                        )
                                    )
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
    }

    // Pairing feature modals (deep-link confirm + SAS first-connect).
    PairingModals(pairing, initialPairingConfig, onClearInitialPairingConfig)
}
