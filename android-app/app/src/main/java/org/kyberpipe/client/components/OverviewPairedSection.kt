package org.kyberpipe.client.components

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Assignment
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.OpenInFull
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.WbSunny
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp


@Composable
internal fun OverviewPairedSection(
    connectionStatus: String,
    connectionMethod: String,
    connectionColor: Color,
    ambientLux: Float,
    isPaired: Boolean,
    clipboardItems: List<AndroidClipboardRecord>,
    notificationsItems: List<AndroidNotificationRecord>,
    onRetryConnection: () -> Unit,
    onNavigateToFiles: () -> Unit,
    onNavigateToClipboard: () -> Unit,
    onNavigateToNotifications: () -> Unit,
    onNavigateToSettings: () -> Unit,
    onOpenNodeMetrics: () -> Unit
) {
    val colors = MaterialTheme.colorScheme

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
                        .clickable { onOpenNodeMetrics() }
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
                                text = if (isConnected) "RTT: Measuring..." else "RTT: N/A (Disconnected)",
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
