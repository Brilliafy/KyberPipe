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
import androidx.compose.material.icons.filled.PhoneAndroid
import androidx.compose.material.icons.filled.Computer

data class AndroidClipboardRecord(
    val id: String,
    val text: String,
    val source: String, // "local" | "remote"
    val timestamp: Long
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ClipboardTab(
    clipboardItems: List<AndroidClipboardRecord>,
    isConnected: Boolean,
    onAddClipboard: (String) -> Unit,
    onCopyClipboard: (String) -> Unit,
    onDeleteClipboard: (String) -> Unit,
    onConnectRequest: () -> Unit
) {
    var activeSubTab by remember { mutableStateOf("all") }
    var inputText by remember { mutableStateOf("") }

    val filteredItems = remember(activeSubTab, clipboardItems) {
        when (activeSubTab) {
            "local" -> clipboardItems.filter { it.source == "local" }
            "remote" -> clipboardItems.filter { it.source == "remote" }
            else -> clipboardItems
        }
    }

    val colors = MaterialTheme.colorScheme

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // Tab Row selector
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
                text = { Text("Local Phone", fontSize = 12.sp) }
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
                    text = "Pair and connect your Linux Desktop node to view and synchronize remote clipboard entries.",
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
            // New Sync Payload Input
            Card(
                colors = CardDefaults.cardColors(containerColor = colors.surface),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Text(
                        text = "Add Clipboard Item",
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Bold,
                        color = colors.primary
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedTextField(
                        value = inputText,
                        onValueChange = { inputText = it },
                        placeholder = { Text("Add clipboard item...", color = colors.onSurface.copy(alpha = 0.4f)) },
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedTextColor = colors.onSurface,
                            unfocusedTextColor = colors.onSurface,
                            focusedBorderColor = colors.primary,
                            unfocusedBorderColor = colors.onSurface.copy(alpha = 0.2f)
                        ),
                        modifier = Modifier.fillMaxWidth(),
                        maxLines = 3
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Button(
                        onClick = {
                            if (inputText.trim().isNotEmpty()) {
                                onAddClipboard(inputText.trim())
                                inputText = ""
                            }
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = colors.primary),
                        modifier = Modifier.align(Alignment.End)
                    ) {
                        Text("Add Item")
                    }
                }
            }

            // Clipboard History List
            Column(
                modifier = Modifier
                    .weight(1f)
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                if (filteredItems.isEmpty()) {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(32.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Text("No clipboard entries found in this view.", color = colors.onBackground.copy(alpha = 0.4f), fontSize = 13.sp)
                    }
                } else {
                    filteredItems.forEach { item ->
                        Card(
                            colors = CardDefaults.cardColors(containerColor = colors.surfaceVariant),
                            shape = RoundedCornerShape(12.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column(modifier = Modifier.padding(12.dp)) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween
                                ) {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        val isLocal = item.source == "local"
                                        Icon(
                                            imageVector = if (isLocal) Icons.Default.PhoneAndroid else Icons.Default.Computer,
                                            contentDescription = null,
                                            tint = if (isLocal) Color(0xFF38BDF8) else Color(0xFFC084FC),
                                            modifier = Modifier.size(14.dp)
                                        )
                                        Spacer(modifier = Modifier.width(4.dp))
                                        Text(
                                            text = if (isLocal) "Mobile" else "PC",
                                            fontSize = 11.sp,
                                            fontWeight = FontWeight.Bold,
                                            color = if (isLocal) Color(0xFF38BDF8) else Color(0xFFC084FC)
                                        )
                                    }
                                    Text(
                                        text = "Synced",
                                        fontSize = 10.sp,
                                        color = colors.onSurface.copy(alpha = 0.4f)
                                    )
                                }
                                Spacer(modifier = Modifier.height(6.dp))
                                Text(
                                    text = item.text,
                                    fontSize = 13.sp,
                                    color = colors.onSurface
                                )
                                Spacer(modifier = Modifier.height(10.dp))
                                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    Button(
                                        onClick = { onCopyClipboard(item.text) },
                                        colors = ButtonDefaults.buttonColors(containerColor = colors.primary),
                                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 2.dp),
                                        modifier = Modifier.height(28.dp)
                                    ) {
                                        Text("Copy", fontSize = 11.sp)
                                    }
                                    Button(
                                        onClick = { onDeleteClipboard(item.id) },
                                        colors = ButtonDefaults.buttonColors(containerColor = colors.error.copy(alpha = 0.15f)),
                                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 2.dp),
                                        modifier = Modifier.height(28.dp)
                                    ) {
                                        Text("Delete", fontSize = 11.sp, color = colors.error)
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
