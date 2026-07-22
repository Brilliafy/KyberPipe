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

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FileManagerTab(
    isConnected: Boolean,
    settings: SettingsManager,
    onPermissionRequest: () -> Unit,
    onGrantLocalAccessToggle: (Boolean) -> Unit,
    onFileAction: (AndroidFileItem) -> Unit
) {
    var activeSubTab by remember { mutableStateOf("local") }
    var refreshKey by remember { mutableStateOf(0) }
    var showAddDialog by remember { mutableStateOf(false) }
    val context = LocalContext.current

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

    val hasAllFiles = remember(refreshKey) { PermissionHelper.hasStoragePermissions(context) }
    val hasScopeFiles = remember(refreshKey) {
        try {
            context.getExternalFilesDir(null)?.exists() == true
        } catch (e: Exception) { false }
    }
    val useScope = remember { mutableStateOf(false) }
    val effectiveAllFiles = hasAllFiles && !useScope.value

    val filesListKey = "$activeSubTab-$effectiveAllFiles-$useScope.value-$isConnected-${settings.fileAccessGrantedDesktop}-$refreshKey"
    val filesList = remember(filesListKey) {
        val list = mutableListOf<AndroidFileItem>()
        if (activeSubTab == "local") {
            if (effectiveAllFiles) {
                try {
                    val rootDir = Environment.getExternalStorageDirectory()
                    rootDir.listFiles()?.forEach { file ->
                        list.add(AndroidFileItem(file.name, file.absolutePath, file.isDirectory, if (file.isDirectory) 0 else file.length()))
                    }
                } catch (e: Exception) {
                    list.addAll(getSimulatedLocalFiles())
                }
            } else if (useScope.value) {
                try {
                    context.getExternalFilesDir(null)?.listFiles()?.forEach { file ->
                        list.add(AndroidFileItem(file.name, file.absolutePath, file.isDirectory, if (file.isDirectory) 0 else file.length()))
                    }
                } catch (e: Exception) { }
            }
        } else if (isConnected && settings.fileAccessGrantedDesktop) {
            list.addAll(getSimulatedPcFiles())
        }
        list
    }

    val colors = MaterialTheme.colorScheme

    Column(
        modifier = Modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        TabRow(
            selectedTabIndex = if (activeSubTab == "local") 0 else 1,
            containerColor = colors.surface,
            contentColor = colors.primary
        ) {
            Tab(selected = activeSubTab == "local", onClick = { activeSubTab = "local" },
                text = { Text("Local Storage", fontSize = 12.sp) })
            Tab(selected = activeSubTab == "remote", onClick = { activeSubTab = "remote" },
                text = { Text("Remote PC Files", fontSize = 12.sp) })
        }

        if (activeSubTab == "local") {
            if (!hasAllFiles && !useScope.value) {
                Column(
                    modifier = Modifier.weight(1f).fillMaxWidth(),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center
                ) {
                    Icon(Icons.Default.Lock, contentDescription = null, tint = colors.error, modifier = Modifier.size(48.dp))
                    Spacer(Modifier.height(12.dp))
                    Text("No File Access", fontWeight = FontWeight.Bold, color = colors.onBackground)
                    Spacer(Modifier.height(8.dp))
                    Text("Choose how you want to access files on this device.", fontSize = 12.sp,
                        color = colors.onBackground.copy(alpha = 0.6f), modifier = Modifier.padding(horizontal = 24.dp))
                    Spacer(Modifier.height(16.dp))
                    Button(onClick = { showAddDialog = true }) {
                        Icon(Icons.Default.Add, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(6.dp))
                        Text("Add Files")
                    }
                }
            } else {
                if (filesList.isEmpty() && !effectiveAllFiles) {
                    Column(
                        modifier = Modifier.weight(1f).fillMaxWidth(),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.Center
                    ) {
                        Text("No files in current scope.", color = colors.onBackground.copy(alpha = 0.6f))
                        Spacer(Modifier.height(12.dp))
                        Button(onClick = { showAddDialog = true }) {
                            Icon(Icons.Default.Add, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(6.dp))
                            Text("Add Files")
                        }
                    }
                } else {
                    FilesListView(filesList, onFileAction)
                }
                Spacer(Modifier.height(8.dp))
                Button(onClick = { showAddDialog = true }, modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = colors.secondary)) {
                    Icon(Icons.Default.Add, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(6.dp))
                    Text(if (effectiveAllFiles) "Manage Storage Access" else "Manage Storage Scopes")
                }
            }
        } else {
            if (!isConnected) {
                Column(
                    modifier = Modifier.weight(1f).fillMaxWidth(),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center
                ) {
                    Icon(Icons.Default.CloudOff, contentDescription = null, tint = colors.onBackground.copy(alpha = 0.4f), modifier = Modifier.size(48.dp))
                    Spacer(Modifier.height(12.dp))
                    Text("Companion PC Offline", fontWeight = FontWeight.Bold, color = colors.onBackground)
                    Spacer(Modifier.height(8.dp))
                    Text("Establish a secure connection with your desktop node to browse files remotely.",
                        fontSize = 12.sp, color = colors.onBackground.copy(alpha = 0.6f), modifier = Modifier.padding(horizontal = 24.dp))
                }
            } else if (!settings.fileAccessGrantedDesktop) {
                Column(
                    modifier = Modifier.weight(1f).fillMaxWidth(),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center
                ) {
                    Icon(Icons.Default.Security, contentDescription = null, tint = colors.error, modifier = Modifier.size(48.dp))
                    Spacer(Modifier.height(12.dp))
                    Text("Access Pending PC Authorization", fontWeight = FontWeight.Bold, color = colors.onBackground)
                    Spacer(Modifier.height(8.dp))
                    Text("Please go to KyberPipe settings on your Linux Desktop and allow phone to browse files.",
                        fontSize = 12.sp, color = colors.onBackground.copy(alpha = 0.6f), modifier = Modifier.padding(horizontal = 24.dp))
                }
            } else {
                FilesListView(filesList, onFileAction)
            }
        }
    }

    if (showAddDialog) {
<<<<<<< HEAD
        showAddDialog = false
        useScope.value = false
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val intent = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION).apply {
                data = Uri.parse("package:${context.packageName}")
            }
            context.startActivity(intent)
        } else {
            onPermissionRequest()
        }
        MainScope().launch { delay(1500); refreshKey++ }
=======
        AlertDialog(
            onDismissRequest = { showAddDialog = false },
            title = { Text("Add File Access") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Choose how KyberPipe accesses your files:", fontSize = 14.sp)
                    Spacer(Modifier.height(8.dp))
                    Button(
                        onClick = {
                            showAddDialog = false
                            useScope.value = false
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                                val intent = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION).apply {
                                    data = Uri.parse("package:${context.packageName}")
                                }
                                context.startActivity(intent)
                            } else {
                                onPermissionRequest()
                            }
                            MainScope().launch { delay(1500); refreshKey++ }
                        },
                        modifier = Modifier.fillMaxWidth(),
                        colors = ButtonDefaults.buttonColors(containerColor = colors.primary)
                    ) { Text("Grant Full File Access") }
                    Spacer(Modifier.height(4.dp))
                    Button(
                        onClick = {
                            showAddDialog = false
                            useScope.value = true
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                                val intent = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION).apply {
                                    data = Uri.parse("package:${context.packageName}")
                                }
                                context.startActivity(intent)
                            } else {
                                onPermissionRequest()
                            }
                            MainScope().launch { delay(1500); refreshKey++ }
                        },
                        modifier = Modifier.fillMaxWidth(),
                        colors = ButtonDefaults.buttonColors(containerColor = colors.secondary)
                    ) { Text("Setup Storage Scopes") }
                }
            },
            confirmButton = {}
        )
>>>>>>> origin/main
    }
}

@Composable
fun FilesListView(files: List<AndroidFileItem>, onFileAction: (AndroidFileItem) -> Unit) {
    val colors = MaterialTheme.colorScheme
    Column(
        modifier = Modifier.fillMaxWidth().verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        if (files.isEmpty()) {
            Box(Modifier.fillMaxWidth().padding(32.dp), contentAlignment = Alignment.Center) {
                Text("No files.", color = colors.onBackground.copy(alpha = 0.4f), fontSize = 13.sp)
            }
        } else {
            files.forEach { file ->
                Card(
                    colors = CardDefaults.cardColors(containerColor = colors.surfaceVariant),
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier.fillMaxWidth().clickable { onFileAction(file) }
                ) {
                    Row(Modifier.fillMaxWidth().padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = if (file.isDir) Icons.Default.Folder else Icons.Default.Description,
                            contentDescription = null,
                            tint = if (file.isDir) Color(0xFFF59E0B) else Color(0xFF38BDF8),
                            modifier = Modifier.size(24.dp)
                        )
                        Spacer(Modifier.width(12.dp))
                        Column(Modifier.weight(1f)) {
                            Text(file.name, fontSize = 14.sp, fontWeight = FontWeight.Bold, color = colors.onSurface)
                            if (!file.isDir) Text(formatBytes(file.size), fontSize = 11.sp, color = colors.onSurface.copy(alpha = 0.6f))
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

private fun getSimulatedLocalFiles(): List<AndroidFileItem> = listOf(
    AndroidFileItem("DCIM", "/sdcard/DCIM", true, 0),
    AndroidFileItem("Documents", "/sdcard/Documents", true, 0),
    AndroidFileItem("Download", "/sdcard/Download", true, 0),
    AndroidFileItem("backup_identity.key", "/sdcard/backup_identity.key", false, 1240)
)

private fun getSimulatedPcFiles(): List<AndroidFileItem> = listOf(
    AndroidFileItem("kyberpipe_core", "/home/Aelfwif/Downloads/kyberpipe", true, 0),
    AndroidFileItem("settings.json", "/home/Aelfwif/Downloads/kyberpipe/desktop-app/src-tauri/settings.json", false, 450),
    AndroidFileItem("desktop-app", "/home/Aelfwif/Downloads/kyberpipe/desktop-app", true, 0),
    AndroidFileItem("core-crypto", "/home/Aelfwif/Downloads/kyberpipe/core-crypto", true, 0)
)