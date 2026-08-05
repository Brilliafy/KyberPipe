package org.kyberpipe.client.components

import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Hearing
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay


@Composable
internal fun OverviewUnpairedSection(
    pairingConfigInput: String,
    onPairingConfigChange: (String) -> Unit,
    onTriggerHandshake: () -> Unit,
    onPairMockDevice: (String) -> Unit
) {
    val colors = MaterialTheme.colorScheme

    // OVERVIEW PAGE PROMPT TO CONNECT (FILLS THE ENTIRE SCREEN)
    var selectedMethod by remember { mutableStateOf("manual") } // "manual", "qr", "audio"
    var isScanning by remember { mutableStateOf(false) }
    var isListening by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(20.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Icon(
            imageVector = Icons.Default.Info,
            contentDescription = null,
            tint = colors.primary,
            modifier = Modifier.size(56.dp)
        )
        Spacer(modifier = Modifier.height(12.dp))
        Text(
            text = "Connect Your Device",
            fontSize = 20.sp,
            fontWeight = FontWeight.Bold,
            color = colors.onBackground
        )
        Spacer(modifier = Modifier.height(6.dp))
        Text(
            text = "To establish a secure post-quantum connection, pair this phone with your KyberPipe desktop client.",
            fontSize = 12.sp,
            color = colors.onBackground.copy(alpha = 0.6f),
            textAlign = androidx.compose.ui.text.style.TextAlign.Center,
            modifier = Modifier.padding(horizontal = 16.dp)
        )
        Spacer(modifier = Modifier.height(24.dp))

        // Pairing Method Selectors
        TabRow(
            selectedTabIndex = when (selectedMethod) {
                "qr" -> 1
                "audio" -> 2
                else -> 0
            },
            containerColor = colors.surface,
            contentColor = colors.primary,
            modifier = Modifier.clip(RoundedCornerShape(10.dp))
        ) {
            Tab(
                selected = selectedMethod == "manual",
                onClick = { selectedMethod = "manual" },
                text = { Text("Code", fontSize = 11.sp) }
            )
            Tab(
                selected = selectedMethod == "qr",
                onClick = { selectedMethod = "qr" },
                text = { Text("QR Scan", fontSize = 11.sp) }
            )
            Tab(
                selected = selectedMethod == "audio",
                onClick = { selectedMethod = "audio" },
                text = { Text("Audio", fontSize = 11.sp) }
            )
        }

        Spacer(modifier = Modifier.height(20.dp))

        when (selectedMethod) {
            "manual" -> {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 4.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Card(
                        colors = CardDefaults.cardColors(containerColor = colors.surfaceVariant),
                        shape = RoundedCornerShape(16.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(
                            modifier = Modifier.padding(16.dp)
                        ) {
                            Text(
                                text = "Enter Pairing Code",
                                fontSize = 13.sp,
                                fontWeight = FontWeight.Bold,
                                color = colors.onSurface
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
            "qr" -> {
                Card(
                    colors = CardDefaults.cardColors(containerColor = colors.surfaceVariant),
                    shape = RoundedCornerShape(16.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        if (!isScanning) {
                            Icon(
                                imageVector = Icons.Default.QrCodeScanner,
                                contentDescription = null,
                                tint = colors.primary,
                                modifier = Modifier.size(64.dp)
                            )
                            Spacer(modifier = Modifier.height(12.dp))
                            Text(
                                text = "QR Code Scanner",
                                fontSize = 13.sp,
                                fontWeight = FontWeight.Bold,
                                color = colors.onSurface
                            )
                            Spacer(modifier = Modifier.height(12.dp))
                            Button(
                                onClick = { isScanning = true },
                                colors = ButtonDefaults.buttonColors(containerColor = colors.primary),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text("Start QR Scanner")
                            }
                        } else {
                            QrCodeScannerView(
                                onQrScanned = { raw ->
                                    isScanning = false
                                    onPairingConfigChange(raw)
                                    onTriggerHandshake()
                                },
                                onClose = { isScanning = false }
                            )
                        }
                    }
                }
            }
            "audio" -> {
                Card(
                    colors = CardDefaults.cardColors(containerColor = colors.surfaceVariant),
                    shape = RoundedCornerShape(16.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        if (!isListening) {
                            Icon(
                                imageVector = Icons.Default.Hearing,
                                contentDescription = null,
                                tint = colors.primary,
                                modifier = Modifier.size(64.dp)
                            )
                            Spacer(modifier = Modifier.height(12.dp))
                            Text(
                                text = "Ultrasonic Handshake",
                                fontSize = 13.sp,
                                fontWeight = FontWeight.Bold,
                                color = colors.onSurface
                            )
                            Spacer(modifier = Modifier.height(6.dp))
                            Text(
                                text = "Captures pairing credentials encoded in an inaudible 19.5 kHz audio beacon broadcasted by the PC.",
                                fontSize = 11.sp,
                                color = colors.onSurface.copy(alpha = 0.6f),
                                textAlign = androidx.compose.ui.text.style.TextAlign.Center
                            )
                            Spacer(modifier = Modifier.height(12.dp))
                            Button(
                                onClick = { isListening = true },
                                colors = ButtonDefaults.buttonColors(containerColor = colors.primary),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text("Listen for Beacon")
                            }
                        } else {
                            val infiniteTransition = rememberInfiniteTransition()
                            val pulse by infiniteTransition.animateFloat(
                                initialValue = 10f,
                                targetValue = 60f,
                                animationSpec = infiniteRepeatable(
                                    animation = tween(1200, easing = FastOutSlowInEasing),
                                    repeatMode = RepeatMode.Restart
                                )
                            )

                            LaunchedEffect(Unit) {
                                delay(3000)
                                onPairMockDevice("Ultrasonic Node")
                            }

                            Box(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(160.dp)
                                    .background(colors.surface, shape = RoundedCornerShape(8.dp)),
                                contentAlignment = Alignment.Center
                            ) {
                                Box(
                                    modifier = Modifier
                                        .size(pulse.dp)
                                        .background(colors.primary.copy(alpha = 0.3f), shape = RoundedCornerShape(100.dp))
                                )
                                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                    Text("Listening for 19.5kHz soundwaves...", color = colors.primary, fontSize = 11.sp)
                                    Spacer(modifier = Modifier.height(4.dp))
                                    Text("Spectral spike detected at 19,531 Hz", color = Color.Green, fontSize = 9.sp, fontWeight = FontWeight.Bold)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
