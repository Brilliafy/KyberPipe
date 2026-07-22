package org.kyberpipe.client.components

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.Settings
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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.CloudOff
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Add
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import java.io.File
import kotlinx.coroutines.MainScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

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
    var useScopedStorage by remember { mutableStateOf(false) }
    var refreshKey by remember { mutableStateOf(0) }
    val context = LocalContext.current
    val localGranted = remember(refreshKey) { PermissionHelper.hasStoragePermissions(context) }

    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) {
                refreshKey++
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    val filesListKey = "$activeSubTab-$localGranted-$useScopedStorage-$isConnected-${settings.fileAccessGrantedDesktop}-$refreshKey"
    val filesList = remember(filesListKey) {
        val list = mutableListOf<AndroidFileItem>()
        if (activeSubTab == "local") {
            if (localGranted && !useScopedStorage) {
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
                    list.addAll(getSimulatedLocalFiles())
                }
            } else {
                try {
                    val scopedDir = context.getExternalFilesDir(null)
                    if (scopedDir != null) {
                        val files = scopedDir.listFiles()
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
                    }
                } catch (e: Exception) {
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

    val colors = MaterialTheme.colorScheme

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        TabRow(
            selectedTabIndex = if (activeSubTab == "local") 0 else 1,
            containerColor = colors.surface,
            contentColor = colors.primary
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
            if (!localGranted && !useScopedStorage) {
                Column(
                    modifier = Modifier
                        .weight(1f)
                        .fillMaxWidth(),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center
                ) {
                    Icon(
                        imageVector = Icons.Default.Lock,
                        contentDescription = null,
                        tint = colors.error,
                        modifier = Modifier.size(48.dp)
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    Text("File System Access Blocked", fontWeight = FontWeight.Bold, color = colors.onBackground)
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = "Grant full file access to browse all files, or use storage scopes for a specific folder only.",
                        fontSize = 12.sp,
                        color = colors.onBackground.copy(alpha = 0.6f),
                        modifier = Modifier.padding(horizontal = 24.dp)
                    )
                    Spacer(modifier = Modifier.height(16.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Button(
                            onClick = {
                                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                                    val intent = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION).apply {
                                        data = Uri.parse("package:${context.packageName}")
                                    }
                                    context.startActivity(intent)
                                } else {
                                    onPermissionRequest()
                                }
                                MainScope().launch {
                                    delay(1000)
                                    refreshKey++
                                }
                            },
                            modifier = Modifier.weight(1f),
                            colors = ButtonDefaults.buttonColors(containerColor = colors.primary)
                        ) {
                            Text("Grant Full File Access", maxLines = 1)
                        }
                        Button(
                            onClick = { useScopedStorage = true },
                            modifier = Modifier.weight(1f),
                            colors = ButtonDefaults.buttonColors(containerColor = colors.secondary)
                        ) {
                            Text("Use Storage Scopes", maxLines = 1)
                        }
                    }
                }
            } else {
                Card(
                    colors = CardDefaults.cardColors(containerColor = colors.surfaceVariant),
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
                                text = if (useScopedStorage) "Using Storage Scopes" else "Full Storage Access",
                                fontSize = 13.sp,
                                fontWeight = FontWeight.Bold,
                                color = colors.onSurface
                            )
                            Text(
                                text = if (useScopedStorage) "Showing app sandbox folder" else "All files accessible",
                                fontSize = 11.sp,
                                color = colors.onSurface.copy(alpha = 0.6f)
                            )
                        }
                        if (localGranted && useScopedStorage) {
                            Switch(
                                checked = false,
                                onCheckedChange = { useScopedStorage = false }
                            )
                        }
                    }
                }

                if (useScopedStorage) {
                    Button(
                        onClick = {
                            val intent = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION).apply {
                                data = Uri.parse("package:${context.packageName}")
                            }
                            context.startActivity(intent)
                            MainScope().launch {
                                delay(1000)
                                refreshKey++
                            }
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = colors.secondary),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Icon(Icons.Default.Add, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Add Folder to Storage Scopes")
                    }
                }

                FilesListView(filesList, onFileAction)
            }
        } else {
            if (!isConnected) {
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
                        text = "Establish a secure connection with your desktop node to browse files remotely.",
                        fontSize = 12.sp,
                        color = colors.onBackground.copy(alpha = 0.6f),
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
                    Icon(
                        imageVector = Icons.Default.Security,
                        contentDescription = null,
                        tint = colors.error,
                        modifier = Modifier.size(48.dp)
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    Text("Access Pending PC Authorization", fontWeight = FontWeight.Bold, color = colors.onBackground)
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = "Please go to KyberPipe settings on your Linux Desktop and allow phone to browse files.",
                        fontSize = 12.sp,
                        color = colors.onBackground.copy(alpha = 0.6f),
                        modifier = Modifier.padding(horizontal = 24.dp)
                    )
                }
            } else {
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
    val colors = MaterialTheme.colorScheme
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
                Text("Directory is empty.", color = colors.onBackground.copy(alpha = 0.4f), fontSize = 13.sp)
            }
        } else {
            files.forEach { file ->
                Card(
                    colors = CardDefaults.cardColors(containerColor = colors.surfaceVariant),
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
                        Icon(
                            imageVector = if (file.isDir) Icons.Default.Folder else Icons.Default.Description,
                            contentDescription = null,
                            tint = if (file.isDir) Color(0xFFF59E0B) else Color(0xFF38BDF8),
                            modifier = Modifier.size(24.dp)
                        )
                        Spacer(modifier = Modifier.width(12.dp))
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = file.name,
                                fontSize = 14.sp,
                                fontWeight = FontWeight.Bold,
                                color = colors.onSurface
                            )
                            if (!file.isDir) {
                                Text(
                                    text = formatBytes(file.size),
                                    fontSize = 11.sp,
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