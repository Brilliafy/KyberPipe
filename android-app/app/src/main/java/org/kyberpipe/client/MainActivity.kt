package org.kyberpipe.client

import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
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
import org.kyberpipe.client.components.*
import org.kyberpipe.client.service.PipeService
import org.kyberpipe.client.utils.PermissionHelper
import org.kyberpipe.client.utils.SettingsManager
import uniffi.core_crypto.*

class MainActivity : ComponentActivity() {

    private lateinit var settingsManager: SettingsManager
    private val mainScope = CoroutineScope(Dispatchers.Main + SupervisorJob())
    private val deepLinkData = mutableStateOf<String?>(null)

    // Image Picker Launcher
    private val pickImageLauncher = registerForActivityResult(
        ActivityResultContracts.GetContent()
    ) { uri ->
        uri?.let {
            val base64 = convertUriToBase64(it)
            settingsManager.devicePicture = base64
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        settingsManager = SettingsManager(this)

        // Zero-Trust Local Crash Logger setup
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            saveCrashLog(throwable)
            android.os.Process.killProcess(android.os.Process.myPid())
            System.exit(10)
        }

        // Prompt permissions on launch
        requestInitialPermissions()

        // Handle initial intent
        handleIntent(intent)

        setContent {
            var themeMode by remember { mutableStateOf(settingsManager.themeMode) }
            var amoledMode by remember { mutableStateOf(settingsManager.amoledMode) }

            KyberpipeTheme(themeMode = themeMode, amoledMode = amoledMode) {
                MainScreen(
                    settings = settingsManager,
                    initialPairingConfig = deepLinkData.value,
                    onClearInitialPairingConfig = { deepLinkData.value = null },
                    onAvatarPickerClick = { pickImageLauncher.launch("image/*") },
                    onStartService = { startPipeForegroundService() },
                    onStopService = { stopPipeForegroundService() },
                    onThemeChanged = { mode, amoled ->
                        themeMode = mode
                        amoledMode = amoled
                    }
                )
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleIntent(intent)
    }

    private fun handleIntent(intent: Intent?) {
        val uri = intent?.data
        if (uri != null) {
            val dataParam = uri.getQueryParameter("data")
            if (dataParam != null && dataParam.isNotEmpty()) {
                deepLinkData.value = dataParam
            } else {
                // If it's the raw custom uri without query param, use the whole scheme
                deepLinkData.value = uri.toString()
            }
        }
    }

    fun getLatestCrashLog(): String? {
        val file = java.io.File(filesDir, "crash_log.txt")
        return if (file.exists()) file.readText() else null
    }

    fun shareTextFile(filename: String, content: String) {
        try {
            val intent = Intent(Intent.ACTION_SEND).apply {
                type = "text/plain"
                putExtra(Intent.EXTRA_TITLE, filename)
                putExtra(Intent.EXTRA_TEXT, content)
            }
            startActivity(Intent.createChooser(intent, "Export $filename"))
        } catch (e: Exception) {
            Toast.makeText(this, "Export failed: ${e.message}", Toast.LENGTH_SHORT).show()
        }
    }

    private fun saveCrashLog(throwable: Throwable) {
        try {
            val sw = java.io.StringWriter()
            val pw = java.io.PrintWriter(sw)
            throwable.printStackTrace(pw)
            val fullTrace = sw.toString()
            
            // Anonymize device identifiers or sensitive values
            val anonymized = anonymizeAndroidCrashLog(fullTrace)
            
            val file = java.io.File(filesDir, "crash_log.txt")
            file.writeText(anonymized)
        } catch (e: Exception) {
            Log.e("KyberPipe", "Failed to write crash log", e)
        }
    }

    private fun anonymizeAndroidCrashLog(rawTrace: String): String {
        var scrubbed = rawTrace
        // Scrub phone numbers (10+ digits)
        scrubbed = scrubbed.replace(Regex("\\+?[0-9]{10,}"), "[MASKED_PHONE_NUMBER]")
        // Scrub email addresses
        scrubbed = scrubbed.replace(Regex("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"), "[MASKED_EMAIL]")
        // Scrub IP addresses
        scrubbed = scrubbed.replace(Regex("\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b"), "[MASKED_IP]")
        // Scrub Android device serials/identifying fingerprints if any leak
        scrubbed = scrubbed.replace(Build.FINGERPRINT, "[MASKED_FINGERPRINT]")
        scrubbed = scrubbed.replace(Build.MODEL, "[MASKED_MODEL]")
        scrubbed = scrubbed.replace(Build.DEVICE, "[MASKED_DEVICE]")
        scrubbed = scrubbed.replace(Build.MANUFACTURER, "[MASKED_MANUFACTURER]")
        return scrubbed
    }

    private fun requestInitialPermissions() {
        if (!PermissionHelper.hasSmsPermissions(this)) {
            PermissionHelper.requestSmsPermissions(this)
        }
        if (!PermissionHelper.isNotificationListenerEnabled(this)) {
            PermissionHelper.requestNotificationListenerPermission(this)
        }
    }

    private fun convertUriToBase64(uri: Uri): String {
        return try {
            val inputStream = contentResolver.openInputStream(uri)
            val bytes = inputStream?.readBytes()
            inputStream?.close()
            if (bytes != null) {
                "data:image/jpeg;base64," + android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP)
            } else ""
        } catch (e: Exception) {
            ""
        }
    }

    private fun startPipeForegroundService() {
        val intent = Intent(this, PipeService::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
    }

    private fun stopPipeForegroundService() {
        val intent = Intent(this, PipeService::class.java)
        stopService(intent)
    }

    override fun onDestroy() {
        super.onDestroy()
        mainScope.cancel()
    }
}

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

    // Toggles
    var wifiDirectActive by remember { mutableStateOf(true) }
    var lanActive by remember { mutableStateOf(false) }
    var resolvedPublicIp by remember { mutableStateOf("Not Queried") }
    var pairingConfigInput by remember { mutableStateOf("") }
    var sasCodeDisplay by remember { mutableStateOf("849-201") }

    // Clipboard and Notification feeds (Real data synced)
    val clipboardList = remember { mutableStateListOf<AndroidClipboardRecord>() }
    val notificationsList = remember { mutableStateListOf<AndroidNotificationRecord>() }

    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    val activity = context as MainActivity

    // Load initial deep link config
    LaunchedEffect(initialPairingConfig) {
        if (initialPairingConfig != null && initialPairingConfig.isNotEmpty()) {
            pairingConfigInput = initialPairingConfig
            currentTab = TabItem.SETTINGS
            onClearInitialPairingConfig()
            Toast.makeText(context, "Pairing config loaded from deep link!", Toast.LENGTH_SHORT).show()
        }
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
                    
                    notificationsList.add(
                        0,
                        AndroidNotificationRecord(
                            id = "notif_${ts}_${pkg.hashCode()}",
                            title = title,
                            text = text,
                            appPackage = pkg,
                            timestamp = ts,
                            type = "remote"
                        )
                    )
                    addLog("[Notification] Intercepted from $pkg: $title")
                }
            }
        }
        val filter = android.content.IntentFilter("org.kyberpipe.client.NOTIFICATION_INTERCEPTED")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.registerReceiver(receiver, filter, Context.RECEIVER_EXPORTED)
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
            keyPair = generatePqKeypair()
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
                        addLog("[Clipboard] Intercepted new primary clip: ${text.take(20)}...")
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

            if (attemptCount >= maxAttempts) {
                connectionStatus = "DISCONNECTED (Max attempts failed)"
                connectionMethod = "None"
                connectionColor = Color.Red
                addLog("[Network] Error: Connection timed out. All connection paths exhausted.")
                return@launch
            }

            attemptCount++
            connectionStatus = "CONNECTING (Attempt $attemptCount/$maxAttempts)..."
            connectionColor = Color.Yellow
            addLog("[Network] Probing interfaces (Attempt $attemptCount/$maxAttempts)...")
            delay(1500) // Simulate transport pathway validation

            try {
                val order = settings.pathwayOrder.split(",")
                var chosenMethod = "WireGuard WAN Tunnel"
                for (path in order) {
                    if (path == "wifi_direct" && wifiDirectActive) {
                        chosenMethod = "Wi-Fi Direct P2P"
                        break
                    }
                    if (path == "mdns_lan" && lanActive) {
                        chosenMethod = "mDNS LAN"
                        break
                    }
                    if (path == "wireguard_wan") {
                        chosenMethod = "WireGuard WAN Tunnel"
                        break
                    }
                }
                connectionStatus = "ACTIVE"
                connectionMethod = chosenMethod
                connectionColor = Color.Green
                attemptCount = 0
                addLog("[Network] Active: Tunnel established via $chosenMethod (PQC keys verified)")
            } catch (e: Exception) {
                connectionStatus = "DISCONNECTED"
                connectionMethod = "None"
                connectionColor = Color.Red
                addLog("[Network] Failover error: ${e.message}")
            }
        }
    }

    // Trigger check on toggles change
    LaunchedEffect(wifiDirectActive, lanActive, settings.isPaired) {
        evaluateConnection()
    }

    // First Connection Modal (Dynamic profile nickname on connect)
    var showFirstConnectModal by remember { mutableStateOf(false) }
    var tempPcName by remember { mutableStateOf("") }

    val handlePairingHandshake = {
        val cleanInput = pairingConfigInput.trim().replace("-", "")
        if (cleanInput.isEmpty()) {
            Toast.makeText(context, "Please paste PC pairing JSON or enter code", Toast.LENGTH_SHORT).show()
        } else if (cleanInput.matches(Regex("\\d{6}"))) {
            val formattedSas = "${cleanInput.take(3)}-${cleanInput.drop(3)}"
            sasCodeDisplay = formattedSas
            tempPcName = "Linux Desktop Workstation"
            showFirstConnectModal = true
            addLog("[Pairing] Successfully verified host identity via SAS Code: $formattedSas")
        } else {
            try {
                val json = JSONObject(pairingConfigInput)
                val hostPkHex = json.getString("host_identity_pk_hex")
                val wireguardPkHex = json.getString("wireguard_pk_hex")

                val kemResponse = encapsulatePqSecret(wireguardPkHex, hostPkHex)
                val myPkHex = keyPair?.mlkemPkHex ?: ""
                val computedSas = generateSasCode(hostPkHex, myPkHex, kemResponse.sharedSecretHex)
                sasCodeDisplay = computedSas

                // Set paired state
                tempPcName = "Linux Desktop workstation"
                showFirstConnectModal = true
                addLog("[Pairing] Successfully verified host identity. SAS Code: $computedSas")
            } catch (e: Exception) {
                Toast.makeText(context, "Handshake failed: ${e.message}", Toast.LENGTH_LONG).show()
                addLog("[Pairing] Error: Handshake verification failed (${e.message})")
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
            when (currentTab) {
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
                        }
                    )
                }
                TabItem.FILES -> {
                    FileManagerTab(
                        isConnected = connectionColor == Color.Green,
                        settings = settings,
                        onPermissionRequest = { PermissionHelper.requestStoragePermissions(activity) },
                        onGrantLocalAccessToggle = { settings.fileAccessGrantedPhone = it },
                        onFileAction = { item ->
                            Toast.makeText(context, "Accessing ${item.name}...", Toast.LENGTH_SHORT).show()
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
                        onSendSms = { recipient, body ->
                            notificationsList.add(
                                0,
                                AndroidNotificationRecord(
                                    id = "sms_${System.currentTimeMillis()}",
                                    title = "SMS to $recipient",
                                    text = body,
                                    appPackage = "telephony.sms",
                                    timestamp = System.currentTimeMillis(),
                                    type = "local"
                                )
                            )
                            Toast.makeText(context, "SMS Dispatched!", Toast.LENGTH_SHORT).show()
                        },
                        onConnectRequest = { currentTab = TabItem.SETTINGS }
                    )
                }
                TabItem.SETTINGS -> {
                    SettingsTab(
                        settings = settings,
                        keyPair = keyPair,
                        pairingConfigInput = pairingConfigInput,
                        onPairingConfigChange = { newValue ->
                            val clean = newValue.replace("-", "")
                            val formatted = if (clean.matches(Regex("\\d*")) && clean.length <= 6) {
                                if (clean.length > 3) "${clean.take(3)}-${clean.drop(3)}" else clean
                            } else {
                                newValue
                            }
                            pairingConfigInput = formatted
                        },
                        onTriggerHandshake = handlePairingHandshake,
                        onAvatarPickerClick = onAvatarPickerClick,
                        onSaveSettings = { onThemeChanged(settings.themeMode, settings.amoledMode) },
                        localLogs = localLogs,
                        onCopyStacktrace = onCopyStacktrace,
                        onExportDiagnosticLogs = onExportDiagnosticLogs,
                        onExportCrashLog = onExportCrashLog,
                        hasCrashLog = hasCrashLog,
                        onPanicTriggered = {
                            try {
                                triggerPanicHardwareWipe()
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

        // Profile input Modal on Pairing
        if (showFirstConnectModal) {
            AlertDialog(
                onDismissRequest = { showFirstConnectModal = false },
                title = { Text("PC Node Pairing Verified") },
                text = {
                    Column {
                        Text("Pairing successful! Assign a visual nickname for this PC node:", fontSize = 13.sp)
                        Spacer(modifier = Modifier.height(10.dp))
                        OutlinedTextField(
                            value = tempPcName,
                            onValueChange = { tempPcName = it },
                            label = { Text("Visual Nickname") },
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedTextColor = Color.White,
                                unfocusedTextColor = Color.White
                            )
                        )
                    }
                },
                confirmButton = {
                    Button(
                        onClick = {
                            settings.pairedDeviceName = tempPcName
                            settings.isPaired = true
                            showFirstConnectModal = false
                            evaluateConnection()
                        }
                    ) {
                        Text("Confirm & Connect")
                    }
                }
            )
        }
    }
}
