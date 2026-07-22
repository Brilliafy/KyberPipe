package org.kyberpipe.client.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CloudOff
import androidx.compose.material.icons.filled.Clear

data class AndroidNotificationRecord(
    val id: String,
    val title: String,
    val text: String,
    val appPackage: String,
    val timestamp: Long,
    val type: String, // "local" | "remote"
    var isDismissed: Boolean = false,
    var updatedAt: Long = System.currentTimeMillis()
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NotificationsTab(
    notifications: List<AndroidNotificationRecord>,
    isConnected: Boolean,
    onDismiss: (id: String) -> Unit,
    onConnectRequest: () -> Unit
) {
    var activeSubTab by remember { mutableStateOf("all") }

    val filteredList = remember(activeSubTab, notifications) {
        val activeNotifs = notifications.filter { !it.isDismissed }
        when (activeSubTab) {
            "local" -> activeNotifs.filter { it.type == "local" }
            "remote" -> activeNotifs.filter { it.type == "remote" }
            else -> activeNotifs
        }
    }

    val colors = MaterialTheme.colorScheme

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // Tab Row
        TabRow(
            selectedTabIndex = when (activeSubTab) {
                "local" -> 1
                "remote" -> 2
                else -> 0
            },
            containerColor = colors.surface,
            contentColor = colors.primary
        ) {
            Tab(
                selected = activeSubTab == "all",
                onClick = { activeSubTab = "all" },
                text = { Text("All", fontSize = 12.sp) }
            )
            Tab(
                selected = activeSubTab == "local",
                onClick = { activeSubTab = "local" },
                text = { Text("Local Alerts", fontSize = 12.sp) }
            )
            Tab(
                selected = activeSubTab == "remote",
                onClick = { activeSubTab = "remote" },
                text = { Text("Remote PC", fontSize = 12.sp) }
            )
        }

        if (activeSubTab == "remote" && !isConnected) {
            Column(
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth(),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center
            ) {
                Icon(
                    imageVector = Icons.Default.CloudOff,
                    contentDescription = null,
                    tint = colors.onBackground.copy(alpha = 0.4f),
                    modifier = Modifier.size(48.dp)
                )
                Spacer(modifier = Modifier.height(12.dp))
                Text("Companion PC Offline", fontWeight = FontWeight.Bold, color = colors.onBackground)
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = "Establish a secure connection with your desktop node to mirror alerts and notification feeds.",
                    fontSize = 12.sp,
                    color = colors.onBackground.copy(alpha = 0.6f),
                    modifier = Modifier.padding(horizontal = 24.dp)
                )
                Spacer(modifier = Modifier.height(16.dp))
                Button(
                    onClick = onConnectRequest,
                    colors = ButtonDefaults.buttonColors(containerColor = colors.primary)
                ) {
                    Text("Connect a Device")
                }
            }
        } else {
            // Notifications List
            Column(
                modifier = Modifier
                    .weight(1f)
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                if (filteredList.isEmpty()) {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(32.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Text("No notifications matched this view.", color = colors.onBackground.copy(alpha = 0.4f), fontSize = 13.sp)
                    }
                } else {
                    filteredList.forEach { record ->
                        Card(
                            colors = CardDefaults.cardColors(containerColor = colors.surfaceVariant),
                            shape = RoundedCornerShape(12.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column(modifier = Modifier.padding(12.dp)) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(
                                        text = record.title,
                                        fontSize = 14.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = colors.onSurface,
                                        modifier = Modifier.weight(1f)
                                    )
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Text(
                                            text = record.appPackage.substringAfterLast("."),
                                            fontSize = 11.sp,
                                            color = colors.primary,
                                            modifier = Modifier.padding(end = 8.dp)
                                        )
                                        IconButton(
                                            onClick = { onDismiss(record.id) },
                                            modifier = Modifier.size(24.dp)
                                        ) {
                                            Icon(
                                                imageVector = Icons.Default.Clear,
                                                contentDescription = "Dismiss",
                                                tint = colors.onSurface.copy(alpha = 0.5f),
                                                modifier = Modifier.size(16.dp)
                                            )
                                        }
                                    }
                                }
                                Spacer(modifier = Modifier.height(4.dp))
                                Text(
                                    text = record.text,
                                    fontSize = 13.sp,
                                    color = colors.onSurface
                                )
                                Spacer(modifier = Modifier.height(4.dp))
                                Text(
                                    text = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.getDefault()).format(java.util.Date(record.timestamp)),
                                    fontSize = 10.sp,
                                    color = colors.onSurface.copy(alpha = 0.4f),
                                    modifier = Modifier.align(Alignment.End)
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}
