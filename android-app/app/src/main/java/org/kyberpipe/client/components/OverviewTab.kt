package org.kyberpipe.client.components

import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
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
                                modifier = Modifier.padding(16.dp),
                                horizontalAlignment = Alignment.CenterHorizontally
                            ) {
                                Text(
                                    text = "Enter Pairing Code",
                                    fontSize = 13.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = colors.onSurface
                                )
                                Spacer(modifier = Modifier.height(8.dp))
                                OutlinedTextField(
                                    value = pairingConfigInput,
                                    onValueChange = onPairingConfigChange,
                                    label = { Text("Paste 6-digit code or JSON", fontSize = 11.sp) },
                                    colors = OutlinedTextFieldDefaults.colors(
                                        focusedTextColor = colors.onSurface,
                                        unfocusedTextColor = colors.onSurface,
                                        focusedBorderColor = colors.primary,
                                        unfocusedBorderColor = colors.onSurface.copy(alpha = 0.2f)
                                    ),
                                    modifier = Modifier.fillMaxWidth(),
                                    maxLines = 3,
                                    singleLine = false
                                )
                                Spacer(modifier = Modifier.height(12.dp))
                                Button(
                                    onClick = onTriggerHandshake,
                                    colors = ButtonDefaults.buttonColors(containerColor = colors.primary),
                                    modifier = Modifier.fillMaxWidth()
                                ) {
                                    Text("Complete PQC Handshake & Connect")
                                }
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
                                // Pulsing green scanner overlay simulator
                                val infiniteTransition = rememberInfiniteTransition()
                                val scale by infiniteTransition.animateFloat(
                                    initialValue = 0.8f,
                                    targetValue = 1.0f,
                                    animationSpec = infiniteRepeatable(
                                        animation = tween(1000, easing = LinearEasing),
                                        repeatMode = RepeatMode.Reverse
                                    )
                                )

                                LaunchedEffect(Unit) {
                                    delay(2500)
                                    onPairMockDevice("QR Scanner Node")
                                }

                                Box(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .height(160.dp)
                                        .background(Color.Black, shape = RoundedCornerShape(8.dp))
                                        .border(2.dp, colors.primary, shape = RoundedCornerShape(8.dp)),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Box(
                                        modifier = Modifier
                                            .size((100 * scale).dp)
                                            .border(2.dp, Color.Green, shape = RoundedCornerShape(4.dp))
                                    )
                                    Text(
                                        text = "Scanning PC screen...",
                                        color = Color.White,
                                        fontSize = 11.sp,
                                        modifier = Modifier
                                            .align(Alignment.BottomCenter)
                                            .padding(bottom = 8.dp)
                                    )
                                }
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

                    // Widget 4: Diagnostics & Metrics Card
                    Card(
                        colors = CardDefaults.cardColors(containerColor = colors.surface),
                        shape = RoundedCornerShape(14.dp),
                        modifier = Modifier
                            .weight(1f)
                            .height(130.dp)
                    ) {
                        Column(
                            modifier = Modifier
                                .fillMaxSize()
                                .padding(12.dp),
                            verticalArrangement = Arrangement.SpaceBetween
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
                            Column {
                                Text(
                                    text = "RTT: 4.8 ms",
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = Color.Green
                                )
                                Text(
                                    text = "Path: ${if (connectionMethod == "None") "Offline" else connectionMethod.substringBefore(" ")}",
                                    fontSize = 10.sp,
                                    color = colors.onSurface.copy(alpha = 0.6f)
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}
