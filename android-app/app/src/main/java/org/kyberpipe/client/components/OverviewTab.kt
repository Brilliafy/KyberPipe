package org.kyberpipe.client.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.kyberpipe.client.utils.SettingsManager

@Composable
fun OverviewTab(
    connectionStatus: String,
    connectionMethod: String,
    connectionColor: Color,
    ambientLux: Float,
    isPaired: Boolean,
    settings: SettingsManager,
    onRetryConnection: () -> Unit,
    onPanicTriggered: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Status indicator card
        Card(
            colors = CardDefaults.cardColors(containerColor = Color(0xFF161B2E)),
            shape = RoundedCornerShape(16.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text(
                        text = "Connection Status",
                        fontSize = 12.sp,
                        color = Color(0xFF94A3B8)
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = connectionStatus,
                        fontSize = 18.sp,
                        fontWeight = FontWeight.Bold,
                        color = connectionColor
                    )
                    if (connectionStatus == "ACTIVE" && connectionMethod.isNotEmpty()) {
                        Text(
                            text = "Linked via: $connectionMethod",
                            fontSize = 11.sp,
                            color = Color(0xFF06B6D4)
                        )
                    }
                }
                if (connectionColor == Color.Red) {
                    IconButton(onClick = onRetryConnection) {
                        Text("🔄", fontSize = 20.sp)
                    }
                }
            }
        }

        // Active paired PC node card
        if (isPaired) {
            Card(
                colors = CardDefaults.cardColors(containerColor = Color(0xFF161B2E)),
                shape = RoundedCornerShape(16.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(
                        modifier = Modifier
                            .size(50.dp)
                            .background(Color(0xFF06B6D4), shape = RoundedCornerShape(25.dp)),
                        contentAlignment = Alignment.Center
                    ) {
                        Text("PC", color = Color.White, fontWeight = FontWeight.Bold)
                    }
                    Spacer(modifier = Modifier.width(16.dp))
                    Column {
                        Text(
                            text = "Connected Node",
                            fontSize = 12.sp,
                            color = Color(0xFF94A3B8)
                        )
                        Text(
                            text = settings.pairedDeviceName.ifEmpty { "Kyberpipe Desktop Node" },
                            fontSize = 16.sp,
                            fontWeight = FontWeight.Bold,
                            color = Color.White
                        )
                    }
                }
            }
        }

        // Dynamic Ambient Light Sensor Gauge Card
        Card(
            colors = CardDefaults.cardColors(containerColor = Color(0xFF161B2E)),
            shape = RoundedCornerShape(16.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    text = "💡 Dynamic Ambient Light Visualizer",
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFFF59E0B)
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "Real-time debounced lux level ($ambientLux lux)",
                    fontSize = 12.sp,
                    color = Color(0xFF94A3B8)
                )
                Spacer(modifier = Modifier.height(8.dp))
                LinearProgressIndicator(
                    progress = (ambientLux / 1000.0f).coerceIn(0.0f, 1.0f),
                    modifier = Modifier.fillMaxWidth().height(8.dp),
                    color = Color(0xFFF59E0B),
                    trackColor = Color(0xFF334155)
                )
            }
        }

        // Emergency Panic Self-Destruct Card
        Card(
            colors = CardDefaults.cardColors(containerColor = Color(0x33EF4444)),
            shape = RoundedCornerShape(16.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    text = "⚠️ Emergency Panic Destruction",
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFFEF4444)
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "Instantly zeroizes active ratchet memory and purges TEE/StrongBox master keys.",
                    fontSize = 12.sp,
                    color = Color(0xFFFCA5A5)
                )
                Spacer(modifier = Modifier.height(12.dp))
                Button(
                    onClick = onPanicTriggered,
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFDC2626)),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("PURGE MASTER KEYS & ZEROIZE RAM", color = Color.White, fontWeight = FontWeight.Bold)
                }
            }
        }
    }
}
