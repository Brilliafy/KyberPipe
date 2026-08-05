package org.kyberpipe.client.components

import android.util.Log
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.kyberpipe.client.utils.SettingsManager

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun SettingsPairingSection(
    settings: SettingsManager,
    pairingConfigInput: String,
    onPairingConfigChange: (String) -> Unit,
    onTriggerHandshake: () -> Unit
) {
    val context = LocalContext.current
    val unpairScope = rememberCoroutineScope()

    val colors = MaterialTheme.colorScheme

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
                                // Audit finding F9: the unpair QUIC call is
                                // block_on_sync — run it off the Main thread.
                                unpairScope.launch {
                                    withContext(Dispatchers.IO) {
                                        val hostIp = settings.pairedHostIp
                                        if (hostIp.isNotEmpty()) {
                                            try {
                                                uniffi.core_crypto.quicSendAndRecv(0x05.toUByte(), "{}")
                                            } catch (e: Exception) {
                                                Log.e("KyberpipeSettings", "QUIC unpair failed: ${e.message}")
                                            }
                                        }
                                    }
                                    // Audit finding F7: release every Rust-side
                                    // pairing handle (keypair, KEM, session key).
                                    org.kyberpipe.client.PairingManager.destroyPairingHandles(context)
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
}
