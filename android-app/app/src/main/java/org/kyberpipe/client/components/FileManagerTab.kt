package org.kyberpipe.client.components

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.Settings
import android.widget.Toast
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import kotlinx.coroutines.MainScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.kyberpipe.client.utils.PermissionHelper
import org.kyberpipe.client.utils.SettingsManager
import java.io.File

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
    var currentPath by remember { mutableStateOf("") }
    var contextMenuFile by remember { mutableStateOf<AndroidFileItem?>(null) }
    val context = LocalContext.current

    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) refreshKey++
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    val hasAllFiles = remember(refreshKey) { PermissionHelper.hasStoragePermissions(context) }
    val useScope = remember { mutableStateOf(false) }
    val effectiveAllFiles = hasAllFiles && !useScope.value

    LaunchedEffect(activeSubTab, effectiveAllFiles, useScope.value, refreshKey) {
        if (activeSubTab == "local") {
            val root = if (effectiveAllFiles) Environment.getExternalStorageDirectory().absolutePath
                       else context.getExternalFilesDir(null)?.absolutePath ?: ""
            if (currentPath.isEmpty() || !currentPath.startsWith(root)) {
                currentPath = root
            }
        }
    }

    val filesListKey = "$activeSubTab-$currentPath-$refreshKey-$isConnected-${settings.fileAccessGrantedDesktop}"
    val filesList = remember(filesListKey) {
        val list = mutableListOf<AndroidFileItem>()
        if (activeSubTab == "local" && currentPath.isNotEmpty()) {
            try {
                val dirFile = File(currentPath)
                if (dirFile.exists() && dirFile.isDirectory) {
                    dirFile.listFiles()?.forEach { file ->
                        list.add(AndroidFileItem(file.name, file.absolutePath, file.isDirectory, if (file.isDirectory) 0 else file.length()))
                    }
                }
            } catch (e: Exception) { }
        } else if (activeSubTab == "remote" && isConnected && settings.fileAccessGrantedDesktop) {
            list.addAll(getSimulatedPcFiles())
        }
        list.sortedByDescending { it.isDir }.sortedBy { it.name }
    }

    fun navigateToDir(path: String) {
        currentPath = path
    }

    fun navigateUp() {
        val parent = File(currentPath).parent
        if (parent != null) currentPath = parent
    }

    val colors = MaterialTheme.colorScheme

    Column(modifier = Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        TabRow(selectedTabIndex = if (activeSubTab == "local") 0 else 1,
            containerColor = colors.surface, contentColor = colors.primary) {
            Tab(selected = activeSubTab == "local", onClick = { activeSubTab = "local" },
                text = { Text("Local Storage", fontSize = 12.sp) })
            Tab(selected = activeSubTab == "remote", onClick = { activeSubTab = "remote" },
                text = { Text("Remote PC Files", fontSize = 12.sp) })
        }

        if (activeSubTab == "local") {
            if (!hasAllFiles && !useScope.value) {
                Column(Modifier.weight(1f).fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.Center) {
                    Icon(Icons.Default.Lock, null, tint = colors.error, modifier = Modifier.size(48.dp))
                    Spacer(Modifier.height(12.dp))
                    Text("No File Access", fontWeight = FontWeight.Bold, color = colors.onBackground)
                    Spacer(Modifier.height(8.dp))
                    Text("Tap Add Files to choose access method.", fontSize = 12.sp, color = colors.onBackground.copy(alpha = 0.6f))
                    Spacer(Modifier.height(16.dp))
                    Button(onClick = { showAddDialog = true }) { Text("Add Files") }
                }
            } else {
                Card(colors = CardDefaults.cardColors(containerColor = colors.surfaceVariant), shape = RoundedCornerShape(8.dp), modifier = Modifier.fillMaxWidth()) {
                    Row(Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                        if (File(currentPath).parent != null) {
                            IconButton(onClick = { navigateUp() }, modifier = Modifier.size(28.dp)) {
                                Icon(Icons.Default.ArrowBack, null, modifier = Modifier.size(16.dp))
                            }
                        }
                        Spacer(Modifier.width(6.dp))
                        Icon(Icons.Default.Folder, null, tint = colors.primary, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(6.dp))
                        Text(File(currentPath).name, fontSize = 12.sp, fontWeight = FontWeight.Bold, color = colors.onSurface, maxLines = 1)
                    }
                }

                if (filesList.isEmpty()) {
                    Box(Modifier.weight(1f).fillMaxWidth(), contentAlignment = Alignment.Center) {
                        Text("This folder is empty.", color = colors.onBackground.copy(alpha = 0.4f))
                    }
                } else {
                    Box(Modifier.weight(1f).fillMaxWidth()) {
                        FilesListView(filesList, colors, contextMenuFile, { contextMenuFile = it }, {
                            if (it.isDir) navigateToDir(it.path)
                            else contextMenuFile = it
                        }, onFileAction)
                    }
                }

                Spacer(Modifier.height(4.dp))
                // Bottom bar with Add and Manage buttons
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = { showAddDialog = true }, modifier = Modifier.weight(1f)) {
                        Icon(Icons.Default.Add, null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(4.dp))
                        Text("Add Files", fontSize = 13.sp)
                    }
                    OutlinedButton(onClick = {
                        val intent = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION).apply {
                            data = Uri.parse("package:${context.packageName}")
                        }
                        context.startActivity(intent)
                        MainScope().launch { delay(1500); refreshKey++ }
                    }, modifier = Modifier.weight(1f)) {
                        Icon(Icons.Default.Settings, null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(4.dp))
                        Text("Manage", fontSize = 13.sp)
                    }
                }
            }
        } else {
            if (!isConnected) {
                Column(Modifier.weight(1f).fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.Center) {
                    Icon(Icons.Default.CloudOff, null, tint = colors.onBackground.copy(alpha = 0.4f), modifier = Modifier.size(48.dp))
                    Spacer(Modifier.height(12.dp))
                    Text("Companion PC Offline", fontWeight = FontWeight.Bold)
                    Spacer(Modifier.height(8.dp))
                    Text("Connect your desktop node to browse files remotely.", fontSize = 12.sp, color = colors.onBackground.copy(alpha = 0.6f))
                }
            } else if (!settings.fileAccessGrantedDesktop) {
                Column(Modifier.weight(1f).fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.Center) {
                    Icon(Icons.Default.Security, null, tint = colors.error, modifier = Modifier.size(48.dp))
                    Spacer(Modifier.height(12.dp))
                    Text("PC Authorization Required", fontWeight = FontWeight.Bold)
                    Spacer(Modifier.height(8.dp))
                    Text("Allow phone access in KyberPipe desktop settings.", fontSize = 12.sp, color = colors.onBackground.copy(alpha = 0.6f))
                }
            } else {
                Box(Modifier.weight(1f).fillMaxWidth()) {
                    FilesListView(filesList, colors, contextMenuFile, { contextMenuFile = it }, {
                        if (it.isDir) navigateToDir(it.path)
                        else contextMenuFile = it
                    }, onFileAction)
                }
            }
        }
    }

    if (showAddDialog) {
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
    }

    // Context menu dropdown
    contextMenuFile?.let { file ->
        AlertDialog(
            onDismissRequest = { contextMenuFile = null },
            title = { Text(file.name, fontSize = 16.sp) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    if (isConnected) {
                        TextButton(onClick = {
                            Toast.makeText(context, "Copying ${file.name} to PC...", Toast.LENGTH_SHORT).show()
                            contextMenuFile = null
                        }, modifier = Modifier.fillMaxWidth()) {
                            Icon(Icons.Default.Computer, null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(8.dp))
                            Text("Copy to PC")
                        }
                        TextButton(onClick = {
                            Toast.makeText(context, "Moving ${file.name} to PC...", Toast.LENGTH_SHORT).show()
                            contextMenuFile = null
                        }, modifier = Modifier.fillMaxWidth()) {
                            Icon(Icons.Default.Computer, null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(8.dp))
                            Text("Move to PC")
                        }
                        HorizontalDivider()
                    }
                    TextButton(onClick = {
                        Toast.makeText(context, "Deleted ${file.name}", Toast.LENGTH_SHORT).show()
                        contextMenuFile = null
                    }, modifier = Modifier.fillMaxWidth(), colors = ButtonDefaults.textButtonColors(contentColor = Color(0xFFEF4444))) {
                        Icon(Icons.Default.Delete, null, tint = Color(0xFFEF4444), modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(8.dp))
                        Text("Delete", color = Color(0xFFEF4444))
                    }
                }
            },
            confirmButton = { TextButton(onClick = { contextMenuFile = null }) { Text("Cancel") } }
        )
    }
}

@Composable
fun FilesListView(
    files: List<AndroidFileItem>,
    colors: androidx.compose.material3.ColorScheme,
    contextMenuFile: AndroidFileItem?,
    onContextMenu: (AndroidFileItem) -> Unit,
    onTap: (AndroidFileItem) -> Unit,
    onFileAction: (AndroidFileItem) -> Unit
) {
    Box(Modifier.fillMaxWidth()) {
        Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(6.dp)) {
        files.forEach { file ->
            Card(
                colors = CardDefaults.cardColors(containerColor = colors.surfaceVariant),
                shape = RoundedCornerShape(10.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = if (file.isDir) Icons.Default.Folder else Icons.Default.Description,
                        null,
                        tint = if (file.isDir) Color(0xFFF59E0B) else Color(0xFF38BDF8),
                        modifier = Modifier.size(22.dp)
                    )
                    Spacer(Modifier.width(12.dp))
                    Column(Modifier.weight(1f).clickable { onTap(file) }) {
                        Text(file.name, fontSize = 14.sp, fontWeight = FontWeight.Bold, color = colors.onSurface, maxLines = 1)
                        if (!file.isDir) {
                            Text(formatBytes(file.size), fontSize = 11.sp, color = colors.onSurface.copy(alpha = 0.5f))
                        }
                    }
                    IconButton(onClick = { onContextMenu(file) }, modifier = Modifier.size(28.dp)) {
                        Icon(Icons.Default.MoreVert, null, tint = colors.onSurface.copy(alpha = 0.5f), modifier = Modifier.size(18.dp))
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

private fun getSimulatedPcFiles(): List<AndroidFileItem> = listOf(
    AndroidFileItem("kyberpipe_core", "/home/Aelfwif/Downloads/kyberpipe", true, 0),
    AndroidFileItem("settings.json", "/home/Aelfwif/Downloads/kyberpipe/desktop-app/src-tauri/settings.json", false, 450),
    AndroidFileItem("desktop-app", "/home/Aelfwif/Downloads/kyberpipe/desktop-app", true, 0),
    AndroidFileItem("core-crypto", "/home/Aelfwif/Downloads/kyberpipe/core-crypto", true, 0)
)
