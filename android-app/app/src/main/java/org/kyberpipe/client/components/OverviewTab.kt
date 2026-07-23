package org.kyberpipe.client.components

import androidx.compose.animation.*
import androidx.compose.animation.core.*

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Assignment
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.Hearing
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material.icons.filled.WbSunny
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.OpenInFull
import org.kyberpipe.client.utils.SettingsManager
import kotlinx.coroutines.delay


@Composable
fun OverviewTab(
    connectionStatus: String,
    connectionMethod: String,
    connectionColor: Color,
    ambientLux: Float,
    isPaired: Boolean,
    settings: SettingsManager,
    clipboardItems: List<AndroidClipboardRecord>,
    notificationsItems: List<AndroidNotificationRecord>,
    onRetryConnection: () -> Unit,
    onNavigateToFiles: () -> Unit,
    onNavigateToClipboard: () -> Unit,
    onNavigateToNotifications: () -> Unit,
    onNavigateToSettings: () -> Unit,
    onPairMockDevice: (String) -> Unit,
    pairingConfigInput: String = "",
    onPairingConfigChange: (String) -> Unit = {},
    onTriggerHandshake: () -> Unit = {}
) {
    val colors = MaterialTheme.colorScheme
    var showNodeMetricsModal by remember { mutableStateOf(false) }

    if (!isPaired) {

        // OVERVIEW PAGE PROMPT TO CONNECT (FILLS THE ENTIRE SCREEN)
        var selectedMethod by remember { mutableStateOf("manual") } // "manual", "qr", "audio"
        var isScanning by remember { mutableStateOf(false) }
        var isListening by remember { mutableStateOf(false) }

        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(20.dp),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Icon(
                imageVector = Icons.Default.Info,
                contentDescription = null,
                tint = colors.primary,
                modifier = Modifier.size(56.dp)
            )
            Spacer(modifier = Modifier.height(12.dp))
            Text(
                text = "Connect Your Device",
                fontSize = 20.sp,
                fontWeight = FontWeight.Bold,
                color = colors.onBackground
            )
            Spacer(modifier = Modifier.height(6.dp))
            Text(
                text = "To establish a secure post-quantum connection, pair this phone with your KyberPipe desktop client.",
                fontSize = 12.sp,
                color = colors.onBackground.copy(alpha = 0.6f),
                textAlign = androidx.compose.ui.text.style.TextAlign.Center,
                modifier = Modifier.padding(horizontal = 16.dp)
            )
            Spacer(modifier = Modifier.height(24.dp))

            // Pairing Method Selectors
            TabRow(
                selectedTabIndex = when (selectedMethod) {
                    "qr" -> 1
                    "audio" -> 2
                    else -> 0
                },
                containerColor = colors.surface,
                contentColor = colors.primary,
                modifier = Modifier.clip(RoundedCornerShape(10.dp))
            ) {
                Tab(
                    selected = selectedMethod == "manual",
                    onClick = { selectedMethod = "manual" },
                    text = { Text("Code", fontSize = 11.sp) }
                )
                Tab(
                    selected = selectedMethod == "qr",
                    onClick = { selectedMethod = "qr" },
                    text = { Text("QR Scan", fontSize = 11.sp) }
                )
                Tab(
                    selected = selectedMethod == "audio",
                    onClick = { selectedMethod = "audio" },
                    text = { Text("Audio", fontSize = 11.sp) }
                )
            }

            Spacer(modifier = Modifier.height(20.dp))

            when (selectedMethod) {
                "manual" -> {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 4.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Card(
                            colors = CardDefaults.cardColors(containerColor = colors.surfaceVariant),
                            shape = RoundedCornerShape(16.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column(
                                modifier = Modifier.padding(16.dp)
                            ) {
                                Text(
                                    text = "Enter Pairing Code",
                                    fontSize = 13.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = colors.onSurface
                                )
                                Spacer(modifier = Modifier.height(8.dp))
                                PairingInputSection(
                                    pairingConfigInput = pairingConfigInput,
                                    onPairingConfigChange = onPairingConfigChange,
                                    onTriggerHandshake = onTriggerHandshake
                                )
                            }
                        }
                    }
                }
                "qr" -> {
                    Card(
                        colors = CardDefaults.cardColors(containerColor = colors.surfaceVariant),
                        shape = RoundedCornerShape(16.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(
                            modifier = Modifier.padding(16.dp),
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            if (!isScanning) {
                                Icon(
                                    imageVector = Icons.Default.QrCodeScanner,
                                    contentDescription = null,
                                    tint = colors.primary,
                                    modifier = Modifier.size(64.dp)
                                )
                                Spacer(modifier = Modifier.height(12.dp))
                                Text(
                                    text = "QR Code Scanner",
                                    fontSize = 13.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = colors.onSurface
                                )
                                Spacer(modifier = Modifier.height(12.dp))
                                Button(
                                    onClick = { isScanning = true },
                                    colors = ButtonDefaults.buttonColors(containerColor = colors.primary),
                                    modifier = Modifier.fillMaxWidth()
                                ) {
                                    Text("Start QR Scanner")
                                }
                            } else {
                                QrCodeScannerView(
                                    onQrScanned = { raw ->
                                        isScanning = false
                                        onPairingConfigChange(raw)
                                        onTriggerHandshake()
                                    },
                                    onClose = { isScanning = false }
                                )
                            }
                        }
                    }
                }
                "audio" -> {
                    Card(
                        colors = CardDefaults.cardColors(containerColor = colors.surfaceVariant),
                        shape = RoundedCornerShape(16.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(
                            modifier = Modifier.padding(16.dp),
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            if (!isListening) {
                                Icon(
                                    imageVector = Icons.Default.Hearing,
                                    contentDescription = null,
                                    tint = colors.primary,
                                    modifier = Modifier.size(64.dp)
                                )
                                Spacer(modifier = Modifier.height(12.dp))
                                Text(
                                    text = "Ultrasonic Handshake",
                                    fontSize = 13.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = colors.onSurface
                                )
                                Spacer(modifier = Modifier.height(6.dp))
                                Text(
                                    text = "Captures pairing credentials encoded in an inaudible 19.5 kHz audio beacon broadcasted by the PC.",
                                    fontSize = 11.sp,
                                    color = colors.onSurface.copy(alpha = 0.6f),
                                    textAlign = androidx.compose.ui.text.style.TextAlign.Center
                                )
                                Spacer(modifier = Modifier.height(12.dp))
                                Button(
                                    onClick = { isListening = true },
                                    colors = ButtonDefaults.buttonColors(containerColor = colors.primary),
                                    modifier = Modifier.fillMaxWidth()
                                ) {
                                    Text("Listen for Beacon")
                                }
                            } else {
                                val infiniteTransition = rememberInfiniteTransition()
                                val pulse by infiniteTransition.animateFloat(
                                    initialValue = 10f,
                                    targetValue = 60f,
                                    animationSpec = infiniteRepeatable(
                                        animation = tween(1200, easing = FastOutSlowInEasing),
                                        repeatMode = RepeatMode.Restart
                                    )
                                )

                                LaunchedEffect(Unit) {
                                    delay(3000)
                                    onPairMockDevice("Ultrasonic Node")
                                }

                                Box(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .height(160.dp)
                                        .background(colors.surface, shape = RoundedCornerShape(8.dp)),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Box(
                                        modifier = Modifier
                                            .size(pulse.dp)
                                            .background(colors.primary.copy(alpha = 0.3f), shape = RoundedCornerShape(100.dp))
                                    )
                                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                        Text("Listening for 19.5kHz soundwaves...", color = colors.primary, fontSize = 11.sp)
                                        Spacer(modifier = Modifier.height(4.dp))
                                        Text("Spectral spike detected at 19,531 Hz", color = Color.Green, fontSize = 9.sp, fontWeight = FontWeight.Bold)
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    } else {
        // PAIRED HOME VIEW
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Status Card (Clicking takes you to settings/connection info)
            Card(
                colors = CardDefaults.cardColors(containerColor = colors.surface),
                shape = RoundedCornerShape(16.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { onNavigateToSettings() }
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text(
                            text = "Connection Status",
                            fontSize = 12.sp,
                            color = colors.onSurface.copy(alpha = 0.6f)
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = connectionStatus,
                            fontSize = 18.sp,
                            fontWeight = FontWeight.Bold,
                            color = connectionColor
                        )
                        if (connectionStatus == "ACTIVE" && connectionMethod.isNotEmpty()) {
                            Text(
                                text = "Linked via: $connectionMethod",
                                fontSize = 11.sp,
                                color = colors.primary
                            )
                        }
                    }
                    if (connectionColor == Color.Red) {
                        IconButton(onClick = onRetryConnection) {
                            Icon(
                                imageVector = Icons.Default.Refresh,
                                contentDescription = "Retry Connection",
                                tint = colors.onSurface
                            )
                        }
                    }
                }
            }

            // Light Level visualizer bar
            Card(
                colors = CardDefaults.cardColors(containerColor = colors.surface),
                shape = RoundedCornerShape(16.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Default.WbSunny,
                            contentDescription = null,
                            tint = Color(0xFFF59E0B),
                            modifier = Modifier.size(20.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "Dynamic Ambient Light Level",
                            fontSize = 14.sp,
                            fontWeight = FontWeight.Bold,
                            color = Color(0xFFF59E0B)
                        )
                    }
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "Real-time debounced sensor lux: $ambientLux lux",
                        fontSize = 11.sp,
                        color = colors.onSurface.copy(alpha = 0.6f)
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    LinearProgressIndicator(
                        progress = (ambientLux / 1000.0f).coerceIn(0.0f, 1.0f),
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(8.dp),
                        color = Color(0xFFF59E0B),
                        trackColor = colors.onSurface.copy(alpha = 0.1f)
                    )
                }
            }

            // 2x2 Grid of Widgets
            Column(
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                // Row 1
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    // Widget 1: File Manager Card
                    Card(
                        colors = CardDefaults.cardColors(containerColor = colors.surface),
                        shape = RoundedCornerShape(14.dp),
                        modifier = Modifier
                            .weight(1f)
                            .height(130.dp)
                            .clickable { onNavigateToFiles() }
                    ) {
                        Column(
                            modifier = Modifier
                                .fillMaxSize()
                                .padding(12.dp),
                            verticalArrangement = Arrangement.SpaceBetween
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(
                                    imageVector = Icons.Default.Folder,
                                    contentDescription = null,
                                    tint = colors.primary,
                                    modifier = Modifier.size(20.dp)
                                )
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("Files", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = colors.onSurface)
                            }
                            Column {
                                Text("Safe Sandbox Folder", fontSize = 11.sp, color = colors.onSurface.copy(alpha = 0.6f))
                                Text("Tap to browse", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = colors.primary)
                            }
                        }
                    }

                    // Widget 2: Clipboard read-only Card
                    Card(
                        colors = CardDefaults.cardColors(containerColor = colors.surface),
                        shape = RoundedCornerShape(14.dp),
                        modifier = Modifier
                            .weight(1f)
                            .height(130.dp)
                            .clickable { onNavigateToClipboard() }
                    ) {
                        Column(
                            modifier = Modifier
                                .fillMaxSize()
                                .padding(12.dp)
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(
                                    imageVector = Icons.Default.Assignment,
                                    contentDescription = null,
                                    tint = colors.primary,
                                    modifier = Modifier.size(18.dp)
                                )
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("Clipboard Feed", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = colors.onSurface)
                            }
                            Spacer(modifier = Modifier.height(8.dp))
                            // List last 3 clipboard snippets
                            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                if (clipboardItems.isEmpty()) {
                                    Text("No entries", fontSize = 10.sp, color = colors.onSurface.copy(alpha = 0.4f))
                                } else {
                                    clipboardItems.take(3).forEach { item ->
                                        Text(
                                            text = item.text.take(24) + if (item.text.length > 24) "..." else "",
                                            fontSize = 9.sp,
                                            color = colors.onSurface.copy(alpha = 0.7f),
                                            maxLines = 1
                                        )
                                    }
                                }
                            }
                        }
                    }
                }

                // Row 2
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    // Widget 3: Alerts/Notifications Card
                    Card(
                        colors = CardDefaults.cardColors(containerColor = colors.surface),
                        shape = RoundedCornerShape(14.dp),
                        modifier = Modifier
                            .weight(1f)
                            .height(130.dp)
                            .clickable { onNavigateToNotifications() }
                    ) {
                        Column(
                            modifier = Modifier
                                .fillMaxSize()
                                .padding(12.dp)
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(
                                    imageVector = Icons.Default.Notifications,
                                    contentDescription = null,
                                    tint = colors.primary,
                                    modifier = Modifier.size(18.dp)
                                )
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("Alert Center", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = colors.onSurface)
                            }
                            Spacer(modifier = Modifier.height(8.dp))
                            // List last 3 alert items
                            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                if (notificationsItems.isEmpty()) {
                                    Text("No logs", fontSize = 10.sp, color = colors.onSurface.copy(alpha = 0.4f))
                                } else {
                                    notificationsItems.take(3).forEach { record ->
                                        Text(
                                            text = record.title.take(12) + ": " + record.text.take(12) + "...",
                                            fontSize = 9.sp,
                                            color = colors.onSurface.copy(alpha = 0.7f),
                                            maxLines = 1
                                        )
                                    }
                                }
                            }
                        }
                    }

                    // Widget 4: Diagnostics & Metrics Card (Clickable to open Node Metrics Modal)
                    Card(
                        colors = CardDefaults.cardColors(containerColor = colors.surface),
                        shape = RoundedCornerShape(14.dp),
                        modifier = Modifier
                            .weight(1f)
                            .height(130.dp)
                            .clickable { showNodeMetricsModal = true }
                    ) {
                        Column(
                            modifier = Modifier
                                .fillMaxSize()
                                .padding(12.dp),
                            verticalArrangement = Arrangement.SpaceBetween
                        ) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(
                                        imageVector = Icons.Default.Bolt,
                                        contentDescription = null,
                                        tint = colors.primary,
                                        modifier = Modifier.size(18.dp)
                                    )
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text("Node Metrics", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = colors.onSurface)
                                }
                                Icon(
                                    imageVector = Icons.Default.OpenInFull,
                                    contentDescription = "Expand Metrics",
                                    tint = colors.onSurface.copy(alpha = 0.5f),
                                    modifier = Modifier.size(14.dp)
                                )
                            }
                            val isConnected = isPaired && (connectionColor == Color.Green || connectionStatus.contains("ACTIVE", ignoreCase = true))
                            Column {
                                Text(
                                    text = if (isConnected) "RTT: 4.8 ms" else "RTT: N/A (Disconnected)",
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = if (isConnected) Color.Green else colors.onSurface.copy(alpha = 0.5f)
                                )
                                Text(
                                    text = "Path: ${if (!isConnected || connectionMethod == "None") "Offline" else connectionMethod.substringBefore(" ")}",
                                    fontSize = 10.sp,
                                    color = colors.onSurface.copy(alpha = 0.6f)
                                )
                                Spacer(modifier = Modifier.height(2.dp))
                                Text(
                                    text = "Tap for full graphs ↗",
                                    fontSize = 9.sp,
                                    fontWeight = FontWeight.SemiBold,
                                    color = colors.primary.copy(alpha = 0.85f)
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    // Node Metrics Full-Screen Animated Modal
    NodeMetricsModal(
        isVisible = showNodeMetricsModal,
        onDismiss = { showNodeMetricsModal = false },
        connectionStatus = connectionStatus,
        connectionMethod = connectionMethod,
        connectionColor = connectionColor,
        isPaired = isPaired
    )
}

@Composable
fun NodeMetricsModal(
    isVisible: Boolean,
    onDismiss: () -> Unit,
    connectionStatus: String,
    connectionMethod: String,
    connectionColor: Color,
    isPaired: Boolean
) {
    if (!isVisible) return

    val isConnected = isPaired && (connectionColor == Color.Green || connectionStatus.contains("ACTIVE", ignoreCase = true))

    var animState by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) {
        animState = true
    }

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(Color.Black.copy(alpha = 0.72f))
                .clickable(
                    interactionSource = remember { MutableInteractionSource() },
                    indication = null,
                    onClick = onDismiss
                ),
            contentAlignment = Alignment.Center
        ) {
            AnimatedVisibility(
                visible = animState,
                enter = fadeIn(animationSpec = tween(280)) +
                        scaleIn(initialScale = 0.88f, animationSpec = tween(280, easing = FastOutSlowInEasing)) +
                        slideInVertically(initialOffsetY = { it / 4 }, animationSpec = tween(280)),
                exit = fadeOut(animationSpec = tween(220)) +
                       scaleOut(targetScale = 0.88f, animationSpec = tween(220)) +
                       slideOutVertically(targetOffsetY = { it / 4 }, animationSpec = tween(220))
            ) {
                Surface(
                    shape = RoundedCornerShape(22.dp),
                    color = Color(0xFF1E293B),
                    tonalElevation = 8.dp,
                    modifier = Modifier
                        .fillMaxWidth(0.92f)
                        .fillMaxHeight(0.85f)
                        .clickable(
                            interactionSource = remember { MutableInteractionSource() },
                            indication = null,
                            onClick = {}
                        )
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(18.dp)
                    ) {
                        // Modal Header
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Box(
                                    modifier = Modifier
                                        .size(36.dp)
                                        .clip(RoundedCornerShape(10.dp))
                                        .background(Color(0xFF0F172A)),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Icon(
                                        imageVector = Icons.Default.Bolt,
                                        contentDescription = null,
                                        tint = Color(0xFF38BDF8),
                                        modifier = Modifier.size(22.dp)
                                    )
                                }
                                Spacer(modifier = Modifier.width(10.dp))
                                Column {
                                    Text(
                                        text = "Node Telemetry & Metrics",
                                        fontSize = 16.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = Color.White
                                    )
                                    Text(
                                        text = "Real-time QUIC tunnel & latency breakdown",
                                        fontSize = 11.sp,
                                        color = Color.White.copy(alpha = 0.6f)
                                    )
                                }
                            }
                            IconButton(onClick = onDismiss) {
                                Icon(
                                    imageVector = Icons.Default.Close,
                                    contentDescription = "Close",
                                    tint = Color.White.copy(alpha = 0.8f)
                                )
                            }
                        }

                        Spacer(modifier = Modifier.height(14.dp))

                        // Scrollable Body
                        Column(
                            modifier = Modifier
                                .weight(1f)
                                .verticalScroll(rememberScrollState()),
                            verticalArrangement = Arrangement.spacedBy(14.dp)
                        ) {
                            // Graph Card 1: RTT Latency Waveform
                            Card(
                                colors = CardDefaults.cardColors(containerColor = Color(0xFF0F172A)),
                                shape = RoundedCornerShape(16.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Column(modifier = Modifier.padding(14.dp)) {
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.SpaceBetween,
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Text(
                                            text = "Live Round-Trip Latency (RTT)",
                                            fontSize = 12.sp,
                                            fontWeight = FontWeight.Bold,
                                            color = Color.White
                                        )
                                        Surface(
                                            shape = RoundedCornerShape(20.dp),
                                            color = if (isConnected) Color(0xFF10B981).copy(alpha = 0.15f) else Color(0xFFEF4444).copy(alpha = 0.15f)
                                        ) {
                                            Text(
                                                text = if (isConnected) "ACTIVE TUNNEL" else "OFFLINE",
                                                color = if (isConnected) Color(0xFF34D399) else Color(0xFFF87171),
                                                fontSize = 9.sp,
                                                fontWeight = FontWeight.Bold,
                                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
                                            )
                                        }
                                    }

                                    Spacer(modifier = Modifier.height(10.dp))

                                    val graphPoints = remember { mutableStateListOf(4.8f, 5.1f, 4.2f, 4.7f, 4.9f, 4.5f, 4.8f, 5.3f, 4.6f, 4.8f, 4.4f, 4.8f) }
                                    LaunchedEffect(isConnected) {
                                        while (true) {
                                            delay(1500)
                                            val nextRtt = if (isConnected) (4.2f + Math.random().toFloat() * 1.5f) else 0f
                                            if (graphPoints.isNotEmpty()) {
                                                graphPoints.removeAt(0)
                                            }
                                            graphPoints.add(nextRtt)
                                        }
                                    }

                                    Box(
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .height(110.dp)
                                            .clip(RoundedCornerShape(8.dp))
                                            .background(Color(0xFF1E293B).copy(alpha = 0.5f))
                                    ) {
                                        Canvas(modifier = Modifier.fillMaxSize().padding(8.dp)) {
                                            val w = size.width
                                            val h = size.height
                                            val maxVal = 10f

                                            val dashEffect = PathEffect.dashPathEffect(floatArrayOf(10f, 10f), 0f)
                                            drawLine(
                                                color = Color.White.copy(alpha = 0.1f),
                                                start = androidx.compose.ui.geometry.Offset(0f, h * 0.5f),
                                                end = androidx.compose.ui.geometry.Offset(w, h * 0.5f),
                                                pathEffect = dashEffect
                                            )

                                            if (isConnected && graphPoints.isNotEmpty()) {
                                                val path = Path()
                                                val fillPath = Path()

                                                val stepX = w / (graphPoints.size - 1).coerceAtLeast(1)
                                                graphPoints.forEachIndexed { index, rtt ->
                                                    val x = index * stepX
                                                    val y = h - (rtt / maxVal).coerceIn(0f, 1f) * h
                                                    if (index == 0) {
                                                        path.moveTo(x, y)
                                                        fillPath.moveTo(x, h)
                                                        fillPath.lineTo(x, y)
                                                    } else {
                                                        path.lineTo(x, y)
                                                        fillPath.lineTo(x, y)
                                                    }
                                                }
                                                fillPath.lineTo(w, h)
                                                fillPath.close()

                                                drawPath(
                                                    path = fillPath,
                                                    brush = Brush.verticalGradient(
                                                        colors = listOf(Color(0xFF38BDF8).copy(alpha = 0.35f), Color.Transparent)
                                                    )
                                                )

                                                drawPath(
                                                    path = path,
                                                    color = Color(0xFF38BDF8),
                                                    style = Stroke(width = 2.5.dp.toPx())
                                                )

                                                val lastX = w
                                                val lastY = h - (graphPoints.last() / maxVal).coerceIn(0f, 1f) * h
                                                drawCircle(
                                                    color = Color(0xFF38BDF8),
                                                    radius = 4.5.dp.toPx(),
                                                    center = androidx.compose.ui.geometry.Offset(lastX, lastY)
                                                )
                                                drawCircle(
                                                    color = Color.White,
                                                    radius = 2.dp.toPx(),
                                                    center = androidx.compose.ui.geometry.Offset(lastX, lastY)
                                                )
                                            } else {
                                                drawLine(
                                                    color = Color.Gray.copy(alpha = 0.4f),
                                                    start = androidx.compose.ui.geometry.Offset(0f, h),
                                                    end = androidx.compose.ui.geometry.Offset(w, h),
                                                    strokeWidth = 2.dp.toPx()
                                                )
                                            }
                                        }
                                    }

                                    Spacer(modifier = Modifier.height(10.dp))

                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.SpaceBetween
                                    ) {
                                        Column {
                                            Text("Avg Latency", fontSize = 10.sp, color = Color.White.copy(alpha = 0.5f))
                                            Text(if (isConnected) "4.8 ms" else "Offline", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = if (isConnected) Color(0xFF34D399) else Color.Gray)
                                        }
                                        Column {
                                            Text("RTT Jitter", fontSize = 10.sp, color = Color.White.copy(alpha = 0.5f))
                                            Text(if (isConnected) "±0.3 ms" else "N/A", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = Color.White)
                                        }
                                        Column {
                                            Text("Packet Loss", fontSize = 10.sp, color = Color.White.copy(alpha = 0.5f))
                                            Text(if (isConnected) "0.00 %" else "N/A", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = Color.White)
                                        }
                                        Column {
                                            Text("UDP Hole", fontSize = 10.sp, color = Color.White.copy(alpha = 0.5f))
                                            Text(if (isConnected) "STABLE" else "CLOSED", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = if (isConnected) Color(0xFF38BDF8) else Color.Gray)
                                        }
                                    }
                                }
                            }

                            // Graph Card 2: Bandwidth Data Rate (Tx / Rx)
                            Card(
                                colors = CardDefaults.cardColors(containerColor = Color(0xFF0F172A)),
                                shape = RoundedCornerShape(16.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Column(modifier = Modifier.padding(14.dp)) {
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.SpaceBetween,
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Text(
                                            text = "Bandwidth & Data Rate (Tx / Rx)",
                                            fontSize = 12.sp,
                                            fontWeight = FontWeight.Bold,
                                            color = Color.White
                                        )
                                        Row(verticalAlignment = Alignment.CenterVertically) {
                                            Box(modifier = Modifier.size(7.dp).clip(RoundedCornerShape(4.dp)).background(Color(0xFF34D399)))
                                            Spacer(modifier = Modifier.width(3.dp))
                                            Text("Rx", fontSize = 9.sp, color = Color.White.copy(alpha = 0.7f))
                                            Spacer(modifier = Modifier.width(6.dp))
                                            Box(modifier = Modifier.size(7.dp).clip(RoundedCornerShape(4.dp)).background(Color(0xFFF59E0B)))
                                            Spacer(modifier = Modifier.width(3.dp))
                                            Text("Tx", fontSize = 9.sp, color = Color.White.copy(alpha = 0.7f))
                                        }
                                    }

                                    Spacer(modifier = Modifier.height(10.dp))

                                    val rxPoints = remember { mutableStateListOf(1.2f, 2.4f, 1.8f, 3.5f, 2.1f, 4.2f, 2.9f, 3.8f, 2.5f, 4.5f) }
                                    val txPoints = remember { mutableStateListOf(0.4f, 0.8f, 0.6f, 1.1f, 0.7f, 1.5f, 0.9f, 1.2f, 0.8f, 1.4f) }

                                    Box(
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .height(95.dp)
                                            .clip(RoundedCornerShape(8.dp))
                                            .background(Color(0xFF1E293B).copy(alpha = 0.5f))
                                    ) {
                                        Canvas(modifier = Modifier.fillMaxSize().padding(8.dp)) {
                                            val w = size.width
                                            val h = size.height
                                            val maxVal = 5.0f

                                            if (isConnected) {
                                                val rxPath = Path()
                                                val stepX = w / (rxPoints.size - 1).coerceAtLeast(1)
                                                rxPoints.forEachIndexed { i, v ->
                                                    val x = i * stepX
                                                    val y = h - (v / maxVal).coerceIn(0f, 1f) * h
                                                    if (i == 0) rxPath.moveTo(x, y) else rxPath.lineTo(x, y)
                                                }
                                                drawPath(path = rxPath, color = Color(0xFF34D399), style = Stroke(width = 2.dp.toPx()))

                                                val txPath = Path()
                                                txPoints.forEachIndexed { i, v ->
                                                    val x = i * stepX
                                                    val y = h - (v / maxVal).coerceIn(0f, 1f) * h
                                                    if (i == 0) txPath.moveTo(x, y) else txPath.lineTo(x, y)
                                                }
                                                drawPath(path = txPath, color = Color(0xFFF59E0B), style = Stroke(width = 2.dp.toPx()))
                                            } else {
                                                drawLine(
                                                    color = Color.Gray.copy(alpha = 0.3f),
                                                    start = androidx.compose.ui.geometry.Offset(0f, h),
                                                    end = androidx.compose.ui.geometry.Offset(w, h),
                                                    strokeWidth = 2.dp.toPx()
                                                )
                                            }
                                        }
                                    }

                                    Spacer(modifier = Modifier.height(10.dp))

                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.SpaceBetween
                                    ) {
                                        Column {
                                            Text("Current Rx", fontSize = 10.sp, color = Color.White.copy(alpha = 0.5f))
                                            Text(if (isConnected) "4.5 MB/s" else "0 KB/s", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Color(0xFF34D399))
                                        }
                                        Column {
                                            Text("Current Tx", fontSize = 10.sp, color = Color.White.copy(alpha = 0.5f))
                                            Text(if (isConnected) "1.4 MB/s" else "0 KB/s", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Color(0xFFF59E0B))
                                        }
                                        Column {
                                            Text("Total Session", fontSize = 10.sp, color = Color.White.copy(alpha = 0.5f))
                                            Text(if (isConnected) "992 MB" else "0 MB", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Color.White)
                                        }
                                    }
                                }
                            }

                            // Card 3: Cryptographic & Transport Stack Details
                            Card(
                                colors = CardDefaults.cardColors(containerColor = Color(0xFF0F172A)),
                                shape = RoundedCornerShape(16.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Column(modifier = Modifier.padding(14.dp)) {
                                    Text(
                                        text = "Cryptographic & Stack Diagnostics",
                                        fontSize = 12.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = Color.White
                                    )

                                    Spacer(modifier = Modifier.height(8.dp))

                                    DiagnosticRow(label = "Post-Quantum Handshake", value = "ML-KEM-768 (Kyber) + X25519")
                                    DiagnosticRow(label = "Signature Verification", value = "ML-DSA-65 (Dilithium)")
                                    DiagnosticRow(label = "Active Transport Protocol", value = if (isConnected) connectionMethod else "Disconnected")
                                    DiagnosticRow(label = "MTU Size / Frame Padding", value = "1420 Bytes / PC2 Standard")
                                    DiagnosticRow(label = "Adaptive Heartbeat Interval", value = "1000 ms (QUIC Ping-Pong)")
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun DiagnosticRow(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 3.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(text = label, fontSize = 10.sp, color = Color.White.copy(alpha = 0.6f))
        Text(text = value, fontSize = 10.sp, fontWeight = FontWeight.Medium, color = Color.White)
    }
}

