package org.kyberpipe.client.components

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.util.Base64
import androidx.compose.foundation.Image
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
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CameraAlt
import androidx.compose.material.icons.filled.Warning
import org.kyberpipe.client.utils.SettingsManager
import org.kyberpipe.client.utils.sendPostRequestAsync
import uniffi.core_crypto.PqKeyPair
import java.io.ByteArrayOutputStream

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsTab(
    settings: SettingsManager,
    keyPair: PqKeyPair?,
    pairingConfigInput: String,
    onPairingConfigChange: (String) -> Unit,
    onTriggerHandshake: () -> Unit,
    onAvatarPickerClick: () -> Unit,
    onSaveSettings: () -> Unit,
    wifiDirectActive: Boolean,
    lanActive: Boolean,
    wireguardActive: Boolean,
    onWifiDirectToggled: (Boolean) -> Unit,
    onLanToggled: (Boolean) -> Unit,
    onWireguardToggled: (Boolean) -> Unit,
    localLogs: List<String> = emptyList(),
    onCopyStacktrace: () -> Unit = {},
    onExportDiagnosticLogs: () -> Unit = {},
    onExportCrashLog: () -> Unit = {},
    hasCrashLog: Boolean = false,
    onPanicTriggered: () -> Unit = {}
) {
    var devName by remember { mutableStateOf(settings.deviceName) }
    var ddnsHost by remember { mutableStateOf(settings.ddnsHostname) }
    var upnpEnabled by remember { mutableStateOf(settings.enableUpnp) }
    var ddnsEnabled by remember { mutableStateOf(settings.enableDdns) }
    var themeState by remember { mutableStateOf(settings.themeMode) }
    var amoledState by remember { mutableStateOf(settings.amoledMode) }

    val colors = MaterialTheme.colorScheme

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Local Device Profile Nickname & Avatar Picker card
        Card(
            colors = CardDefaults.cardColors(containerColor = colors.surface),
            shape = RoundedCornerShape(16.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    text = "Local Companion Profile",
                    fontSize = 15.sp,
                    fontWeight = FontWeight.Bold,
                    color = colors.primary
                )
                Spacer(modifier = Modifier.height(12.dp))
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(16.dp)
                ) {
                    Box(
                        modifier = Modifier
                            .size(70.dp)
                            .background(colors.onSurface.copy(alpha = 0.1f), shape = RoundedCornerShape(35.dp))
                            .clickable { onAvatarPickerClick() },
                        contentAlignment = Alignment.Center
                    ) {
                        val bitmap = remember(settings.devicePicture) {
                            decodeBase64ToBitmap(settings.devicePicture)
                        }
                        if (bitmap != null) {
                            Image(
                                bitmap = bitmap.asImageBitmap(),
                                contentDescription = "Avatar",
                                modifier = Modifier.size(70.dp).background(Color.Transparent, shape = RoundedCornerShape(35.dp)),
                                contentScale = ContentScale.Crop
                            )
                        } else {
                            Icon(
                                imageVector = Icons.Default.CameraAlt,
                                contentDescription = "Select Avatar",
                                tint = colors.onSurface,
                                modifier = Modifier.size(24.dp)
                            )
                        }
                    }

                    Column(modifier = Modifier.weight(1f)) {
                        OutlinedTextField(
                            value = devName,
                            onValueChange = {
                                devName = it
                                settings.deviceName = it
                                onSaveSettings()
                            },
                            label = { Text("Device Name", fontSize = 11.sp) },
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedTextColor = colors.onSurface,
                                unfocusedTextColor = colors.onSurface,
                                focusedBorderColor = colors.primary,
                                unfocusedBorderColor = colors.onSurface.copy(alpha = 0.2f)
                            ),
                            modifier = Modifier.fillMaxWidth()
                        )
                    }
                }
            }
        }

        // Theme Visual Properties Card
        Card(
            colors = CardDefaults.cardColors(containerColor = colors.surface),
            shape = RoundedCornerShape(16.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    text = "Theme Visual Properties",
                    fontSize = 15.sp,
                    fontWeight = FontWeight.Bold,
                    color = colors.primary
                )
                Spacer(modifier = Modifier.height(10.dp))
                
                Text("Select Application Theme Mode:", fontSize = 11.sp, color = colors.onSurface.copy(alpha = 0.6f))
                Spacer(modifier = Modifier.height(6.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    val themeModes = listOf("light" to "Light", "dark" to "Dark", "auto" to "System Auto")
                    themeModes.forEach { (mode, label) ->
                        val selected = themeState == mode
                        Button(
                            onClick = {
                                themeState = mode
                                settings.themeMode = mode
                                onSaveSettings()
                            },
                            colors = ButtonDefaults.buttonColors(
                                containerColor = if (selected) colors.primary else colors.surfaceVariant
                            ),
                            contentPadding = PaddingValues(horizontal = 10.dp, vertical = 2.dp),
                            modifier = Modifier.weight(1f).height(32.dp)
                        ) {
                            Text(label, fontSize = 11.sp, color = if (selected) colors.onPrimary else colors.onSurfaceVariant)
                        }
                    }
                }
                
                Spacer(modifier = Modifier.height(12.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "True AMOLED/OLED Mode",
                            fontSize = 13.sp,
                            fontWeight = FontWeight.Bold,
                            color = colors.onSurface
                        )
                        Text(
                            text = "Enforce pure black backgrounds to optimize power",
                            fontSize = 11.sp,
                            color = colors.onSurface.copy(alpha = 0.6f)
                        )
                    }
                    Switch(
                        checked = amoledState,
                        onCheckedChange = {
                            amoledState = it
                            settings.amoledMode = it
                            onSaveSettings()
                        }
                    )
                }

                Spacer(modifier = Modifier.height(12.dp))
                HorizontalDivider(color = colors.onSurface.copy(alpha = 0.05f))
                Spacer(modifier = Modifier.height(12.dp))

                Text(
                    text = "Auto-Purge History",
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Bold,
                    color = colors.onSurface
                )
                Text(
                    text = "Purge notifications and logs older than designated days to conserve device storage.",
                    fontSize = 11.sp,
                    color = colors.onSurface.copy(alpha = 0.6f)
                )
                Spacer(modifier = Modifier.height(6.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    val purgeDaysOptions = listOf(3, 7, 14, 30)
                    var selectedPurgeDays by remember { mutableStateOf(settings.purgeDays) }
                    purgeDaysOptions.forEach { days ->
                        val selected = selectedPurgeDays == days
                        Button(
                            onClick = {
                                selectedPurgeDays = days
                                settings.purgeDays = days
                                onSaveSettings()
                            },
                            colors = ButtonDefaults.buttonColors(
                                containerColor = if (selected) colors.primary else colors.surfaceVariant
                            ),
                            contentPadding = PaddingValues(horizontal = 10.dp, vertical = 2.dp),
                            modifier = Modifier.weight(1f).height(32.dp)
                        ) {
                            Text("$days Days", fontSize = 11.sp, color = if (selected) colors.onPrimary else colors.onSurfaceVariant)
                        }
                    }
                }
            }
        }

        // Connectivity Hierarchy Card
        Card(
            colors = CardDefaults.cardColors(containerColor = colors.surface),
            shape = RoundedCornerShape(16.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    text = "Connectivity hierarchy",
                    fontSize = 15.sp,
                    fontWeight = FontWeight.Bold,
                    color = colors.primary
                )
                Spacer(modifier = Modifier.height(10.dp))
                Text(
                    text = "Rearrange pathway priorities. Connection fallback adapts dynamically.",
                    fontSize = 11.sp,
                    color = colors.onSurface.copy(alpha = 0.6f)
                )
                Spacer(modifier = Modifier.height(12.dp))

                var orderList by remember(settings.pathwayOrder) {
                    mutableStateOf(settings.pathwayOrder.split(",").toMutableList())
                }

                val pathwayNames = mapOf(
                    "wifi_direct" to "Wi-Fi Direct P2P Radio",
                    "mdns_lan" to "Local Network (mDNS LAN)",
                    "wireguard_wan" to "WireGuard WAN Tunnel Overlay"
                )

                val pathwayToggles = mapOf(
                    "wifi_direct" to wifiDirectActive,
                    "mdns_lan" to lanActive,
                    "wireguard_wan" to wireguardActive
                )

                fun togglePathway(key: String, checked: Boolean) {
                    val activeCount = listOf(wifiDirectActive, lanActive, wireguardActive).count { it }
                    if (!checked && activeCount <= 1) {
                        return
                    }
                    when (key) {
                        "wifi_direct" -> onWifiDirectToggled(checked)
                        "mdns_lan" -> onLanToggled(checked)
                        "wireguard_wan" -> onWireguardToggled(checked)
                    }
                    onSaveSettings()
                }

                orderList.forEachIndexed { index, pathKey ->
                    val isActive = pathwayToggles[pathKey] ?: false
                    Card(
                        colors = CardDefaults.cardColors(
                            containerColor = if (isActive) colors.surfaceVariant else colors.surface.copy(alpha = 0.5f)
                        ),
                        shape = RoundedCornerShape(12.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 12.dp, vertical = 8.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Checkbox(
                                        checked = isActive,
                                        onCheckedChange = { togglePathway(pathKey, it) },
                                        modifier = Modifier.size(24.dp)
                                    )
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Column {
                                        Text(
                                            text = "${index + 1}. ${pathwayNames[pathKey] ?: pathKey}",
                                            fontSize = 13.sp,
                                            fontWeight = if (isActive) FontWeight.Bold else FontWeight.Normal,
                                            color = if (isActive) colors.onSurface else colors.onSurface.copy(alpha = 0.5f)
                                        )
                                    }
                                }
                            }
                            Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                                Button(
                                    onClick = {
                                        if (index > 0) {
                                            val mutable = orderList.toMutableList()
                                            val temp = mutable[index]
                                            mutable[index] = mutable[index - 1]
                                            mutable[index - 1] = temp
                                            orderList = mutable
                                            settings.pathwayOrder = mutable.joinToString(",")
                                            onSaveSettings()
                                        }
                                    },
                                    enabled = index > 0,
                                    contentPadding = PaddingValues(horizontal = 4.dp, vertical = 2.dp),
                                    modifier = Modifier.height(28.dp)
                                ) {
                                    Text("▲", fontSize = 10.sp)
                                }
                                Button(
                                    onClick = {
                                        if (index < orderList.size - 1) {
                                            val mutable = orderList.toMutableList()
                                            val temp = mutable[index]
                                            mutable[index] = mutable[index + 1]
                                            mutable[index + 1] = temp
                                            orderList = mutable
                                            settings.pathwayOrder = mutable.joinToString(",")
                                            onSaveSettings()
                                        }
                                    },
                                    enabled = index < orderList.size - 1,
                                    contentPadding = PaddingValues(horizontal = 4.dp, vertical = 2.dp),
                                    modifier = Modifier.height(28.dp)
                                ) {
                                    Text("▼", fontSize = 10.sp)
                                }
                            }
                        }
                    }
                }
            }
        }

        // Connection Handshake config pasting card
        if (settings.isPaired) {
            Card(
                colors = CardDefaults.cardColors(containerColor = colors.surface),
                shape = RoundedCornerShape(16.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "Paired PC Connection",
                        fontSize = 15.sp,
                        fontWeight = FontWeight.Bold,
                        color = colors.primary
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = "Device Name: ${settings.pairedDeviceName ?: "Linux Desktop Node"}",
                        fontSize = 13.sp,
                        color = colors.onSurface
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "Trust Status: Cryptographically Pinned",
                        fontSize = 12.sp,
                        color = colors.onSurface.copy(alpha = 0.6f)
                    )
                    Spacer(modifier = Modifier.height(16.dp))

                    var showUnpairConfirm by remember { mutableStateOf(false) }

                    if (showUnpairConfirm) {
                        Text(
                            text = "Are you sure you want to delete this connection? Symmetric keys and data channels will be purged.",
                            color = Color.Red,
                            fontSize = 12.sp,
                            fontWeight = FontWeight.SemiBold
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Button(
                                onClick = {
                                    val hostIp = settings.pairedHostIp
                                    if (hostIp.isNotEmpty()) {
                                        sendPostRequestAsync("http://$hostIp:23520/api/unpair", "{}")
                                    }

                                    settings.isPaired = false
                                    settings.pairedDeviceName = ""
                                    onPairingConfigChange("")
                                    showUnpairConfirm = false
                                },
                                colors = ButtonDefaults.buttonColors(containerColor = Color.Red),
                                modifier = Modifier.weight(1f)
                            ) {
                                Text("Delete Connection", color = Color.White)
                            }
                            OutlinedButton(
                                onClick = { showUnpairConfirm = false },
                                modifier = Modifier.weight(1f)
                            ) {
                                Text("Cancel")
                            }
                        }
                    } else {
                        Button(
                            onClick = { showUnpairConfirm = true },
                            colors = ButtonDefaults.buttonColors(containerColor = colors.error),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text("Delete Connection & Unpair", color = colors.onError)
                        }
                    }
                }
            }
        } else {
            Card(
                colors = CardDefaults.cardColors(containerColor = colors.surface),
                shape = RoundedCornerShape(16.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "Establish Pairing Link",
                        fontSize = 15.sp,
                        fontWeight = FontWeight.Bold,
                        color = colors.primary
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    PairingInputSection(
                        pairingConfigInput = pairingConfigInput,
                        onPairingConfigChange = onPairingConfigChange,
                        onTriggerHandshake = onTriggerHandshake
                    )
                }
            }
        }

        // Fallbacks toggles: UPnP & DDNS
        Card(
            colors = CardDefaults.cardColors(containerColor = colors.surface),
            shape = RoundedCornerShape(16.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    text = "WAN Fallback Protocols",
                    fontSize = 15.sp,
                    fontWeight = FontWeight.Bold,
                    color = colors.primary
                )
                Spacer(modifier = Modifier.height(12.dp))
                
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text("Enable UPnP IGDP Mapping", fontSize = 13.sp, color = colors.onSurface)
                    Switch(
                        checked = upnpEnabled,
                        onCheckedChange = {
                            upnpEnabled = it
                            settings.enableUpnp = it
                            onSaveSettings()
                        }
                    )
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text("Enable Dynamic DNS Lookup", fontSize = 13.sp, color = colors.onSurface)
                    Switch(
                        checked = ddnsEnabled,
                        onCheckedChange = {
                            ddnsEnabled = it
                            settings.enableDdns = it
                            onSaveSettings()
                        }
                    )
                }

                if (ddnsEnabled) {
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedTextField(
                        value = ddnsHost,
                        onValueChange = {
                            ddnsHost = it
                            settings.ddnsHostname = it
                            onSaveSettings()
                        },
                        label = { Text("DDNS Hostname address", fontSize = 11.sp) },
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedTextColor = colors.onSurface,
                            unfocusedTextColor = colors.onSurface,
                            focusedBorderColor = colors.primary,
                            unfocusedBorderColor = colors.onSurface.copy(alpha = 0.2f)
                        ),
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            }
        }

        // Cryptographic keys vault display card
        keyPair?.let { pair ->
            Card(
                colors = CardDefaults.cardColors(containerColor = colors.surface),
                shape = RoundedCornerShape(16.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "Companion Key Vault",
                        fontSize = 15.sp,
                        fontWeight = FontWeight.Bold,
                        color = colors.primary
                    )
                    Spacer(modifier = Modifier.height(10.dp))
                    Text("NIST ML-KEM-768 PK (Hex):", fontSize = 11.sp, color = colors.onSurface.copy(alpha = 0.6f))
                    Text(
                        text = pair.mlkemPkHex.take(48) + "...",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFFC084FC)
                    )
                    Spacer(modifier = Modifier.height(10.dp))
                    Text("X25519 Ephemeral PK (Hex):", fontSize = 11.sp, color = colors.onSurface.copy(alpha = 0.6f))
                    Text(
                        text = pair.x25519PkHex.take(48) + "...",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFFC084FC)
                    )
                }
            }
        }

        // Zero-Trust Local Diagnostics & Logs Card
        Card(
            colors = CardDefaults.cardColors(containerColor = colors.surface),
            shape = RoundedCornerShape(16.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    text = "Zero-Trust Local Diagnostics & Logs",
                    fontSize = 15.sp,
                    fontWeight = FontWeight.Bold,
                    color = colors.primary
                )
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = "Diagnostic Logs:",
                    fontSize = 11.sp,
                    color = colors.onSurface.copy(alpha = 0.6f)
                )
                Spacer(modifier = Modifier.height(4.dp))
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(120.dp)
                        .background(colors.background, shape = RoundedCornerShape(8.dp))
                        .padding(8.dp)
                ) {
                    val scrollState = rememberScrollState()
                    Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .verticalScroll(scrollState)
                    ) {
                        localLogs.forEach { log ->
                            Text(
                                text = log,
                                fontSize = 10.sp,
                                color = Color(0xFF38BDF8),
                                fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace
                            )
                        }
                    }
                }
                Spacer(modifier = Modifier.height(12.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Button(
                        onClick = onCopyStacktrace,
                        enabled = hasCrashLog,
                        colors = ButtonDefaults.buttonColors(
                            containerColor = colors.surfaceVariant
                        ),
                        modifier = Modifier.weight(1f).height(36.dp),
                        contentPadding = PaddingValues(horizontal = 4.dp, vertical = 2.dp)
                    ) {
                        Text("Copy Stacktrace", fontSize = 10.sp, color = if (hasCrashLog) colors.onSurfaceVariant else colors.onSurfaceVariant.copy(alpha = 0.4f))
                    }
                    Button(
                        onClick = onExportDiagnosticLogs,
                        colors = ButtonDefaults.buttonColors(
                            containerColor = colors.primary
                        ),
                        modifier = Modifier.weight(1f).height(36.dp),
                        contentPadding = PaddingValues(horizontal = 4.dp, vertical = 2.dp)
                    ) {
                        Text("Export Logs", fontSize = 10.sp, color = colors.onPrimary)
                    }
                    Button(
                        onClick = onExportCrashLog,
                        enabled = hasCrashLog,
                        colors = ButtonDefaults.buttonColors(
                            containerColor = if (hasCrashLog) colors.error else colors.surfaceVariant
                        ),
                        modifier = Modifier.weight(1f).height(36.dp),
                        contentPadding = PaddingValues(horizontal = 4.dp, vertical = 2.dp)
                    ) {
                        Text("Export Anon Crash", fontSize = 10.sp, color = if (hasCrashLog) colors.onPrimary else colors.onSurfaceVariant.copy(alpha = 0.4f))
                    }
                }
            }
        }

        // Emergency Panic Self-Destruct Card (Moved here from Home tab)
        Card(
            colors = CardDefaults.cardColors(containerColor = colors.error.copy(alpha = 0.1f)),
            shape = RoundedCornerShape(16.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Default.Warning,
                        contentDescription = null,
                        tint = colors.error,
                        modifier = Modifier.size(20.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "Emergency Panic Destruction",
                        fontSize = 16.sp,
                        fontWeight = FontWeight.Bold,
                        color = colors.error
                    )
                }
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "Instantly zeroizes active ratchet memory and purges TEE/StrongBox master keys.",
                    fontSize = 12.sp,
                    color = colors.onErrorContainer
                )
                Spacer(modifier = Modifier.height(12.dp))
                Button(
                    onClick = onPanicTriggered,
                    colors = ButtonDefaults.buttonColors(containerColor = colors.error),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("PURGE MASTER KEYS & ZEROIZE RAM", color = colors.onError, fontWeight = FontWeight.Bold)
                }
            }
        }
    }
}

private fun decodeBase64ToBitmap(base64Str: String): Bitmap? {
    if (base64Str.isEmpty()) return null
    return try {
        val pureBase64 = if (base64Str.contains(",")) base64Str.substringAfter(",") else base64Str
        val decodedBytes = Base64.decode(pureBase64, Base64.DEFAULT)
        BitmapFactory.decodeByteArray(decodedBytes, 0, decodedBytes.size)
    } catch (e: Exception) {
        null
    }
}
