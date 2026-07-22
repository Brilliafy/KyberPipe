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
import org.kyberpipe.client.utils.SettingsManager
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
    onSaveSettings: () -> Unit
) {
    var devName by remember { mutableStateOf(settings.deviceName) }
    var ddnsHost by remember { mutableStateOf(settings.ddnsHostname) }
    var upnpEnabled by remember { mutableStateOf(settings.enableUpnp) }
    var ddnsEnabled by remember { mutableStateOf(settings.enableDdns) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Local Device Profile Nickname & Avatar Picker card
        Card(
            colors = CardDefaults.cardColors(containerColor = Color(0xFF161B2E)),
            shape = RoundedCornerShape(16.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    text = "Local Companion Profile",
                    fontSize = 15.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFF06B6D4)
                )
                Spacer(modifier = Modifier.height(12.dp))
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(16.dp)
                ) {
                    // Modern circle with camera on click
                    Box(
                        modifier = Modifier
                            .size(70.dp)
                            .background(Color(0xFF334155), shape = RoundedCornerShape(35.dp))
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
                            Text("📷", fontSize = 24.sp)
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
                                focusedTextColor = Color.White,
                                unfocusedTextColor = Color.White,
                                focusedBorderColor = Color(0xFF06B6D4),
                                unfocusedBorderColor = Color(0xFF334155)
                            ),
                            modifier = Modifier.fillMaxWidth()
                        )
                    }
                }
            }
        }

        // Connection Handshake config pasting card
        Card(
            colors = CardDefaults.cardColors(containerColor = Color(0xFF161B2E)),
            shape = RoundedCornerShape(16.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    text = "Establish Pairing Link",
                    fontSize = 15.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFF06B6D4)
                )
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = pairingConfigInput,
                    onValueChange = onPairingConfigChange,
                    label = { Text("Paste PC Pairing Config JSON", fontSize = 11.sp) },
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedTextColor = Color.White,
                        unfocusedTextColor = Color.White,
                        focusedBorderColor = Color(0xFF06B6D4),
                        unfocusedBorderColor = Color(0xFF334155)
                    ),
                    modifier = Modifier.fillMaxWidth(),
                    maxLines = 4
                )
                Spacer(modifier = Modifier.height(12.dp))
                Button(
                    onClick = onTriggerHandshake,
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF06B6D4)),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Complete PQC Handshake & Connect")
                }
            }
        }

        // Fallbacks toggles: UPnP & DDNS
        Card(
            colors = CardDefaults.cardColors(containerColor = Color(0xFF161B2E)),
            shape = RoundedCornerShape(16.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    text = "WAN Fallback Protocols",
                    fontSize = 15.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFF06B6D4)
                )
                Spacer(modifier = Modifier.height(12.dp))
                
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text("Enable UPnP IGDP Mapping", fontSize = 13.sp, color = Color.White)
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
                    Text("Enable Dynamic DNS Lookup", fontSize = 13.sp, color = Color.White)
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
                            focusedTextColor = Color.White,
                            unfocusedTextColor = Color.White,
                            focusedBorderColor = Color(0xFF06B6D4),
                            unfocusedBorderColor = Color(0xFF334155)
                        ),
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            }
        }

        // Cryptographic keys vault display card
        keyPair?.let { pair ->
            Card(
                colors = CardDefaults.cardColors(containerColor = Color(0xFF161B2E)),
                shape = RoundedCornerShape(16.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "Companion Key Vault",
                        fontSize = 15.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFF06B6D4)
                    )
                    Spacer(modifier = Modifier.height(10.dp))
                    Text("NIST ML-KEM-768 PK (Hex):", fontSize = 11.sp, color = Color(0xFF94A3B8))
                    Text(
                        text = pair.mlkemPkHex.take(48) + "...",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFFC084FC)
                    )
                    Spacer(modifier = Modifier.height(10.dp))
                    Text("X25519 Ephemeral PK (Hex):", fontSize = 11.sp, color = Color(0xFF94A3B8))
                    Text(
                        text = pair.x25519PkHex.take(48) + "...",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFFC084FC)
                    )
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
