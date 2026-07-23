package org.kyberpipe.client.components

import android.content.Intent
import android.content.pm.PackageManager
import android.provider.Settings
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
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.Security
import androidx.compose.ui.platform.LocalContext
import org.kyberpipe.client.utils.PermissionHelper
import org.kyberpipe.client.utils.SettingsManager

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
    val context = LocalContext.current
    val settingsManager = remember { SettingsManager(context) }

    var showPermissionDialog by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        if (!settingsManager.notificationPermissionShown && !PermissionHelper.isNotificationListenerEnabled(context)) {
            showPermissionDialog = true
            settingsManager.notificationPermissionShown = true
        }
    }

    if (showPermissionDialog) {
        AlertDialog(
            onDismissRequest = { showPermissionDialog = false },
            icon = { Icon(Icons.Default.Security, contentDescription = null, tint = MaterialTheme.colorScheme.primary) },
            title = { Text("Notification Access Required") },
            text = {
                Column {
                    Text(
                        text = "KyberPipe needs notification read access to intercept and sync notifications from your apps to your paired desktop companion.",
                        fontSize = 14.sp
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    Text(
                        text = "This permission allows KyberPipe to read the title, text, and app info of incoming notifications. They are encrypted end-to-end before being sent to your paired device.",
                        fontSize = 13.sp,
                        color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f)
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = "Tap \"Grant Access\" below, then find and toggle on \"KyberPipe\" in the system notification access list.",
                        fontSize = 13.sp,
                        color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f)
                    )
                }
            },
            confirmButton = {
                Button(onClick = {
                    showPermissionDialog = false
                    PermissionHelper.requestNotificationListenerPermission(context as android.app.Activity)
                }) {
                    Text("Grant Access")
                }
            },
            dismissButton = {
                TextButton(onClick = { showPermissionDialog = false }) {
                    Text("Not Now")
                }
            }
        )
    }

    val filteredList = remember(activeSubTab, notifications) {
        val activeNotifs = notifications.filter { !it.isDismissed }
        when (activeSubTab) {
            "local" -> activeNotifs.filter { it.type == "local" || it.type.startsWith("local") }
            "remote" -> activeNotifs.filter { it.type == "remote" || it.type.startsWith("remote") }
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
                                    Column(modifier = Modifier.weight(1f)) {
                                        Row(verticalAlignment = Alignment.CenterVertically) {
                                            Icon(
                                                imageVector = Icons.Default.Notifications,
                                                contentDescription = null,
                                                tint = colors.primary,
                                                modifier = Modifier.size(16.dp)
                                            )
                                            Spacer(modifier = Modifier.width(6.dp))
                                            Text(
                                                text = record.title,
                                                fontSize = 14.sp,
                                                fontWeight = FontWeight.Bold,
                                                color = colors.onSurface
                                            )
                                        }
                                        Spacer(modifier = Modifier.height(2.dp))
                                        Text(
                                            text = getAppLabel(context, record.appPackage),
                                            fontSize = 10.sp,
                                            color = colors.primary
                                        )
                                    }
                                    Row(verticalAlignment = Alignment.CenterVertically) {
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

private fun getAppLabel(context: android.content.Context, packageName: String): String {
    return try {
        val pm = context.packageManager
        val ai = pm.getApplicationInfo(packageName, 0)
        pm.getApplicationLabel(ai).toString()
    } catch (e: Exception) {
        packageName.substringAfterLast(".")
    }
}