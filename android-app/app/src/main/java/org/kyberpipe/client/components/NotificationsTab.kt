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

data class AndroidNotificationRecord(
    val id: String,
    val title: String,
    val text: String,
    val appPackage: String,
    val timestamp: Long,
    val type: String // "local" | "remote"
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NotificationsTab(
    notifications: List<AndroidNotificationRecord>,
    isConnected: Boolean,
    onSendSms: (recipient: String, body: String) -> Unit,
    onConnectRequest: () -> Unit
) {
    var activeSubTab by remember { mutableStateOf("all") }
    var smsRecipient by remember { mutableStateOf("") }
    var smsBody by remember { mutableStateOf("") }

    val filteredList = remember(activeSubTab, notifications) {
        when (activeSubTab) {
            "local" -> notifications.filter { it.type == "local" }
            "remote" -> notifications.filter { it.type == "remote" }
            else -> notifications
        }
    }

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
            containerColor = Color(0xFF161B2E),
            contentColor = Color(0xFF06B6D4)
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
                        tint = Color(0xFF94A3B8),
                        modifier = Modifier.size(48.dp)
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    Text("Companion PC Offline", fontWeight = FontWeight.Bold, color = Color.White)
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = "Establish a secure connection with your desktop node to mirror alerts and notification feeds.",
                        fontSize = 12.sp,
                        color = Color(0xFF94A3B8),
                    modifier = Modifier.padding(horizontal = 24.dp)
                )
                Spacer(modifier = Modifier.height(16.dp))
                Button(
                    onClick = onConnectRequest,
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF06B6D4))
                ) {
                    Text("Connect a Device")
                }
            }
        } else {
            // Outbound SMS card helper
            Card(
                colors = CardDefaults.cardColors(containerColor = Color(0xFF161B2E)),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Text(
                        text = "Send Outbound SMS via PC Link",
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFF06B6D4)
                    )
                    Spacer(modifier = Modifier.height(6.dp))
                    OutlinedTextField(
                        value = smsRecipient,
                        onValueChange = { smsRecipient = it },
                        label = { Text("Recipient Number", fontSize = 11.sp) },
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedTextColor = Color.White,
                            unfocusedTextColor = Color.White,
                            focusedBorderColor = Color(0xFF06B6D4),
                            unfocusedBorderColor = Color(0xFF334155)
                        ),
                        modifier = Modifier.fillMaxWidth(),
                        maxLines = 1
                    )
                    Spacer(modifier = Modifier.height(6.dp))
                    OutlinedTextField(
                        value = smsBody,
                        onValueChange = { smsBody = it },
                        label = { Text("SMS Message Body", fontSize = 11.sp) },
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedTextColor = Color.White,
                            unfocusedTextColor = Color.White,
                            focusedBorderColor = Color(0xFF06B6D4),
                            unfocusedBorderColor = Color(0xFF334155)
                        ),
                        modifier = Modifier.fillMaxWidth(),
                        maxLines = 2
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Button(
                        onClick = {
                            if (smsRecipient.trim().isNotEmpty() && smsBody.trim().isNotEmpty()) {
                                onSendSms(smsRecipient.trim(), smsBody.trim())
                                smsBody = ""
                            }
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF06B6D4)),
                        modifier = Modifier.align(Alignment.End),
                        enabled = isConnected
                    ) {
                        Text("Send SMS")
                    }
                }
            }

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
                        Text("No notifications matched this view.", color = Color(0xFF64748B), fontSize = 13.sp)
                    }
                } else {
                    filteredList.forEach { record ->
                        Card(
                            colors = CardDefaults.cardColors(containerColor = Color(0xFF1E293B)),
                            shape = RoundedCornerShape(12.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column(modifier = Modifier.padding(12.dp)) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween
                                ) {
                                    Text(
                                        text = record.title,
                                        fontSize = 14.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = Color.White
                                    )
                                    Text(
                                        text = record.appPackage.substringAfterLast("."),
                                        fontSize = 11.sp,
                                        color = Color(0xFF06B6D4)
                                    )
                                }
                                Spacer(modifier = Modifier.height(4.dp))
                                Text(
                                    text = record.text,
                                    fontSize = 13.sp,
                                    color = Color(0xFFE2E8F0)
                                )
                                Spacer(modifier = Modifier.height(4.dp))
                                Text(
                                    text = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.getDefault()).format(java.util.Date(record.timestamp)),
                                    fontSize = 10.sp,
                                    color = Color(0xFF64748B),
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
