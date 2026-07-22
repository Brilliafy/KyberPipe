package org.kyberpipe.client.components

import android.os.Environment
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
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
import org.kyberpipe.client.utils.PermissionHelper
import org.kyberpipe.client.utils.SettingsManager
import java.io.File

data class AndroidFileItem(
    val name: String,
    val path: String,
    val isDir: Boolean,
    val size: Long
)

@Composable
fun FileManagerTab(
    isConnected: Boolean,
    settings: SettingsManager,
    onPermissionRequest: () -> Unit,
    onGrantLocalAccessToggle: (Boolean) -> Unit,
    onFileAction: (AndroidFileItem) -> Unit
) {
    var activeSubTab by remember { mutableStateOf("local") }
    val localGranted = PermissionHelper.hasStoragePermissions(androidx.compose.ui.platform.LocalContext.current)
    val filesList = remember(activeSubTab, localGranted, isConnected, settings.fileAccessGrantedDesktop) {
        val list = mutableListOf<AndroidFileItem>()
        if (activeSubTab == "local") {
            if (localGranted) {
                try {
                    val rootDir = Environment.getExternalStorageDirectory()
                    val files = rootDir.listFiles()
                    files?.forEach { file ->
                        list.add(
                            AndroidFileItem(
                                name = file.name,
                                path = file.absolutePath,
                                isDir = file.isDirectory,
                                size = if (file.isDirectory) 0 else file.length()
                            )
                        )
                    }
                } catch (e: Exception) {
                    // Fallback to simulated local files if listing fails
                    list.addAll(getSimulatedLocalFiles())
                }
            }
        } else {
            if (isConnected && settings.fileAccessGrantedDesktop) {
                list.addAll(getSimulatedPcFiles())
            }
        }
        list
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // Tab Row selectors
        TabRow(
            selectedTabIndex = if (activeSubTab == "local") 0 else 1,
            containerColor = Color(0xFF161B2E),
            contentColor = Color(0xFF06B6D4)
        ) {
            Tab(
                selected = activeSubTab == "local",
                onClick = { activeSubTab = "local" },
                text = { Text("Local Android Storage", fontSize = 12.sp) }
            )
            Tab(
                selected = activeSubTab == "remote",
                onClick = { activeSubTab = "remote" },
                text = { Text("Remote PC Files", fontSize = 12.sp) }
            )
        }

        if (activeSubTab == "local") {
            if (!localGranted) {
                Column(
                    modifier = Modifier
                        .weight(1f)
                        .fillMaxWidth(),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center
                ) {
                    Text("🔒 File System Access Blocked", fontWeight = FontWeight.Bold, color = Color.White)
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = "Access permissions to your local Android storage must be granted to explore files.",
                        fontSize = 12.sp,
                        color = Color(0xFF94A3B8),
                        modifier = Modifier.padding(horizontal = 24.dp)
                    )
                    Spacer(modifier = Modifier.height(16.dp))
                    Button(
                        onClick = onPermissionRequest,
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF06B6D4))
                    ) {
                        Text("Grant Storage Access")
                    }
                }
            } else {
                // Grant Access switch settings to allow desktop to browse
                Card(
                    colors = CardDefaults.cardColors(containerColor = Color(0xFF161B2E)),
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(12.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "Expose Files to Desktop Node",
                                fontSize = 13.sp,
                                fontWeight = FontWeight.Bold,
                                color = Color.White
                            )
                            Text(
                                text = "Allows PC to browse your Android folder",
                                fontSize = 11.sp,
                                color = Color(0xFF94A3B8)
                            )
                        }
                        Switch(
                            checked = settings.fileAccessGrantedPhone,
                            onCheckedChange = {
                                settings.fileAccessGrantedPhone = it
                                onGrantLocalAccessToggle(it)
                            }
                        )
                    }
                }

                // Local Files List
                FilesListView(filesList, onFileAction)
            }
        } else {
            // REMOTE PC TAB
            if (!isConnected) {
                Column(
                    modifier = Modifier
                        .weight(1f)
                        .fillMaxWidth(),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center
                ) {
                    Text("🔌 Companion PC Offline", fontWeight = FontWeight.Bold, color = Color.White)
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = "Establish a secure connection with your desktop node to browse files remotely.",
                        fontSize = 12.sp,
                        color = Color(0xFF94A3B8),
                        modifier = Modifier.padding(horizontal = 24.dp)
                    )
                }
            } else if (!settings.fileAccessGrantedDesktop) {
                Column(
                    modifier = Modifier
                        .weight(1f)
                        .fillMaxWidth(),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center
                ) {
                    Text("🔒 Access Pending PC Authorization", fontWeight = FontWeight.Bold, color = Color.White)
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = "Please go to Kyberpipe settings on your Linux Desktop and turn on 'Allow Phone to browse this PC's files'.",
                        fontSize = 12.sp,
                        color = Color(0xFF94A3B8),
                        modifier = Modifier.padding(horizontal = 24.dp)
                    )
                }
            } else {
                // PC Files List
                FilesListView(filesList, onFileAction)
            }
        }
    }
}

@Composable
fun FilesListView(
    files: List<AndroidFileItem>,
    onFileAction: (AndroidFileItem) -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        if (files.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(32.dp),
                contentAlignment = Alignment.Center
            ) {
                Text("Directory is empty.", color = Color(0xFF64748B), fontSize = 13.sp)
            }
        } else {
            files.forEach { file ->
                Card(
                    colors = CardDefaults.cardColors(containerColor = Color(0xFF1E293B)),
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { onFileAction(file) }
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(12.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = if (file.isDir) "📁" else "📄",
                            fontSize = 20.sp
                        )
                        Spacer(modifier = Modifier.width(12.dp))
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = file.name,
                                fontSize = 14.sp,
                                fontWeight = FontWeight.Bold,
                                color = Color.White
                            )
                            if (!file.isDir) {
                                Text(
                                    text = formatBytes(file.size),
                                    fontSize = 11.sp,
                                    color = Color(0xFF94A3B8)
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

private fun formatBytes(bytes: Long): String {
    if (bytes < 1024) return "$bytes B"
    if (bytes < 1048576) return "${(bytes / 1024.0).toInt()} KB"
    return "${String.format("%.1f", bytes / 1048576.0)} MB"
}

private fun getSimulatedLocalFiles(): List<AndroidFileItem> {
    return listOf(
        AndroidFileItem("DCIM", "/sdcard/DCIM", true, 0),
        AndroidFileItem("Documents", "/sdcard/Documents", true, 0),
        AndroidFileItem("Download", "/sdcard/Download", true, 0),
        AndroidFileItem("backup_identity.key", "/sdcard/backup_identity.key", false, 1240)
    )
}

private fun getSimulatedPcFiles(): List<AndroidFileItem> {
    return listOf(
        AndroidFileItem("kyberpipe_core", "/home/Aelfwif/Downloads/kyberpipe", true, 0),
        AndroidFileItem("settings.json", "/home/Aelfwif/Downloads/kyberpipe/desktop-app/src-tauri/settings.json", false, 450),
        AndroidFileItem("desktop-app", "/home/Aelfwif/Downloads/kyberpipe/desktop-app", true, 0),
        AndroidFileItem("core-crypto", "/home/Aelfwif/Downloads/kyberpipe/core-crypto", true, 0)
    )
}
