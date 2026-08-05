package org.kyberpipe.client.components

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.scaleOut
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Surface
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
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties


@Composable
internal fun NodeMetricsModal(
    isVisible: Boolean,
    onDismiss: () -> Unit,
    connectionStatus: String,
    connectionMethod: String,
    connectionColor: Color,
    isPaired: Boolean
) {
    if (!isVisible) return

    val isConnected = isPaired && (connectionColor == Color.Green || connectionStatus.contains("ACTIVE", ignoreCase = true))

    var animState by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) {
        animState = true
    }

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(Color.Black.copy(alpha = 0.72f))
                .clickable(
                    interactionSource = remember { MutableInteractionSource() },
                    indication = null,
                    onClick = onDismiss
                ),
            contentAlignment = Alignment.Center
        ) {
            AnimatedVisibility(
                visible = animState,
                enter = fadeIn(animationSpec = tween(280)) +
                        scaleIn(initialScale = 0.88f, animationSpec = tween(280, easing = FastOutSlowInEasing)) +
                        slideInVertically(initialOffsetY = { it / 4 }, animationSpec = tween(280)),
                exit = fadeOut(animationSpec = tween(220)) +
                       scaleOut(targetScale = 0.88f, animationSpec = tween(220)) +
                       slideOutVertically(targetOffsetY = { it / 4 }, animationSpec = tween(220))
            ) {
                Surface(
                    shape = RoundedCornerShape(22.dp),
                    color = Color(0xFF1E293B),
                    tonalElevation = 8.dp,
                    modifier = Modifier
                        .fillMaxWidth(0.92f)
                        .fillMaxHeight(0.85f)
                        .clickable(
                            interactionSource = remember { MutableInteractionSource() },
                            indication = null,
                            onClick = {}
                        )
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(18.dp)
                    ) {
                        // Modal Header
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Box(
                                    modifier = Modifier
                                        .size(36.dp)
                                        .clip(RoundedCornerShape(10.dp))
                                        .background(Color(0xFF0F172A)),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Icon(
                                        imageVector = Icons.Default.Bolt,
                                        contentDescription = null,
                                        tint = Color(0xFF38BDF8),
                                        modifier = Modifier.size(22.dp)
                                    )
                                }
                                Spacer(modifier = Modifier.width(10.dp))
                                Column {
                                    Text(
                                        text = "Node Telemetry & Metrics",
                                        fontSize = 16.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = Color.White
                                    )
                                    Text(
                                        text = "Real-time QUIC tunnel & latency breakdown",
                                        fontSize = 11.sp,
                                        color = Color.White.copy(alpha = 0.6f)
                                    )
                                }
                            }
                            IconButton(onClick = onDismiss) {
                                Icon(
                                    imageVector = Icons.Default.Close,
                                    contentDescription = "Close",
                                    tint = Color.White.copy(alpha = 0.8f)
                                )
                            }
                        }

                        Spacer(modifier = Modifier.height(14.dp))

                        // Scrollable Body
                        Column(
                            modifier = Modifier
                                .weight(1f)
                                .verticalScroll(rememberScrollState()),
                            verticalArrangement = Arrangement.spacedBy(14.dp)
                        ) {
                            // Graph Card 1: RTT Latency Waveform
                            Card(
                                colors = CardDefaults.cardColors(containerColor = Color(0xFF0F172A)),
                                shape = RoundedCornerShape(16.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Column(modifier = Modifier.padding(14.dp)) {
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.SpaceBetween,
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Text(
                                            text = "Live Round-Trip Latency (RTT)",
                                            fontSize = 12.sp,
                                            fontWeight = FontWeight.Bold,
                                            color = Color.White
                                        )
                                        Surface(
                                            shape = RoundedCornerShape(20.dp),
                                            color = if (isConnected) Color(0xFF10B981).copy(alpha = 0.15f) else Color(0xFFEF4444).copy(alpha = 0.15f)
                                        ) {
                                            Text(
                                                text = if (isConnected) "ACTIVE TUNNEL" else "OFFLINE",
                                                color = if (isConnected) Color(0xFF34D399) else Color(0xFFF87171),
                                                fontSize = 9.sp,
                                                fontWeight = FontWeight.Bold,
                                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
                                            )
                                        }
                                    }

                                    Spacer(modifier = Modifier.height(10.dp))

                                    Box(
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .height(110.dp)
                                            .clip(RoundedCornerShape(8.dp))
                                            .background(Color(0xFF1E293B).copy(alpha = 0.5f))
                                    ) {
                                        Canvas(modifier = Modifier.fillMaxSize().padding(8.dp)) {
                                            val w = size.width
                                            val h = size.height

                                            val dashEffect = PathEffect.dashPathEffect(floatArrayOf(10f, 10f), 0f)
                                            drawLine(
                                                color = Color.White.copy(alpha = 0.1f),
                                                start = androidx.compose.ui.geometry.Offset(0f, h * 0.5f),
                                                end = androidx.compose.ui.geometry.Offset(w, h * 0.5f),
                                                pathEffect = dashEffect
                                            )

                                            drawLine(
                                                color = Color.Gray.copy(alpha = 0.4f),
                                                start = androidx.compose.ui.geometry.Offset(0f, h),
                                                end = androidx.compose.ui.geometry.Offset(w, h),
                                                strokeWidth = 2.dp.toPx()
                                            )
                                        }
                                        Text(
                                            text = if (isConnected) "Capturing RTT..." else "OFFLINE",
                                            modifier = Modifier.align(Alignment.Center),
                                            color = Color.Gray.copy(alpha = 0.5f),
                                            fontSize = 14.sp
                                        )
                                    }

                                    Spacer(modifier = Modifier.height(10.dp))

                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.SpaceBetween
                                    ) {
                                        Column {
                                            Text("Avg Latency", fontSize = 10.sp, color = Color.White.copy(alpha = 0.5f))
                                            Text(if (isConnected) "Measuring..." else "N/A", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = if (isConnected) Color(0xFF34D399) else Color.Gray)
                                        }
                                        Column {
                                            Text("RTT Jitter", fontSize = 10.sp, color = Color.White.copy(alpha = 0.5f))
                                            Text("N/A", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = Color.White)
                                        }
                                        Column {
                                            Text("Packet Loss", fontSize = 10.sp, color = Color.White.copy(alpha = 0.5f))
                                            Text("N/A", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = Color.White)
                                        }
                                        Column {
                                            Text("UDP Hole", fontSize = 10.sp, color = Color.White.copy(alpha = 0.5f))
                                            Text(if (isConnected) "STABLE" else "CLOSED", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = if (isConnected) Color(0xFF38BDF8) else Color.Gray)
                                        }
                                    }
                                }
                            }

                            // Graph Card 2: Bandwidth Data Rate (Tx / Rx)
                            Card(
                                colors = CardDefaults.cardColors(containerColor = Color(0xFF0F172A)),
                                shape = RoundedCornerShape(16.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Column(modifier = Modifier.padding(14.dp)) {
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.SpaceBetween,
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Text(
                                            text = "Bandwidth & Data Rate (Tx / Rx)",
                                            fontSize = 12.sp,
                                            fontWeight = FontWeight.Bold,
                                            color = Color.White
                                        )
                                        Row(verticalAlignment = Alignment.CenterVertically) {
                                            Box(modifier = Modifier.size(7.dp).clip(RoundedCornerShape(4.dp)).background(Color(0xFF34D399)))
                                            Spacer(modifier = Modifier.width(3.dp))
                                            Text("Rx", fontSize = 9.sp, color = Color.White.copy(alpha = 0.7f))
                                            Spacer(modifier = Modifier.width(6.dp))
                                            Box(modifier = Modifier.size(7.dp).clip(RoundedCornerShape(4.dp)).background(Color(0xFFF59E0B)))
                                            Spacer(modifier = Modifier.width(3.dp))
                                            Text("Tx", fontSize = 9.sp, color = Color.White.copy(alpha = 0.7f))
                                        }
                                    }

                                    Spacer(modifier = Modifier.height(10.dp))

                                    Box(
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .height(95.dp)
                                            .clip(RoundedCornerShape(8.dp))
                                            .background(Color(0xFF1E293B).copy(alpha = 0.5f))
                                    ) {
                                        Canvas(modifier = Modifier.fillMaxSize().padding(8.dp)) {
                                            val w = size.width
                                            val h = size.height

                                            drawLine(
                                                color = Color.Gray.copy(alpha = 0.3f),
                                                start = androidx.compose.ui.geometry.Offset(0f, h),
                                                end = androidx.compose.ui.geometry.Offset(w, h),
                                                strokeWidth = 2.dp.toPx()
                                            )
                                        }
                                        Text(
                                            text = if (isConnected) "Capturing bandwidth..." else "OFFLINE",
                                            modifier = Modifier.align(Alignment.Center),
                                            color = Color.Gray.copy(alpha = 0.5f),
                                            fontSize = 14.sp
                                        )
                                    }

                                    Spacer(modifier = Modifier.height(10.dp))

                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.SpaceBetween
                                    ) {
                                        Column {
                                            Text("Current Rx", fontSize = 10.sp, color = Color.White.copy(alpha = 0.5f))
                                            Text(if (isConnected) "Measuring..." else "0 B/s", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Color(0xFF34D399))
                                        }
                                        Column {
                                            Text("Current Tx", fontSize = 10.sp, color = Color.White.copy(alpha = 0.5f))
                                            Text(if (isConnected) "Measuring..." else "0 B/s", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Color(0xFFF59E0B))
                                        }
                                        Column {
                                            Text("Total Session", fontSize = 10.sp, color = Color.White.copy(alpha = 0.5f))
                                            Text(if (isConnected) "Measuring..." else "0 B", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Color.White)
                                        }
                                    }
                                }
                            }

                            // Card 3: Cryptographic & Transport Stack Details
                            Card(
                                colors = CardDefaults.cardColors(containerColor = Color(0xFF0F172A)),
                                shape = RoundedCornerShape(16.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Column(modifier = Modifier.padding(14.dp)) {
                                    Text(
                                        text = "Cryptographic & Stack Diagnostics",
                                        fontSize = 12.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = Color.White
                                    )

                                    Spacer(modifier = Modifier.height(8.dp))

                                    DiagnosticRow(label = "Post-Quantum Handshake", value = "ML-KEM-768 (Kyber) + X25519")
                                    DiagnosticRow(label = "Signature Verification", value = "ML-DSA-65 (Dilithium)")
                                    DiagnosticRow(label = "Active Transport Protocol", value = if (isConnected) connectionMethod else "Disconnected")
                                    DiagnosticRow(label = "MTU Size / Frame Padding", value = "1420 Bytes / PC2 Standard")
                                    DiagnosticRow(label = "Adaptive Heartbeat Interval", value = "1000 ms (QUIC Ping-Pong)")
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
internal fun DiagnosticRow(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 3.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(text = label, fontSize = 10.sp, color = Color.White.copy(alpha = 0.6f))
        Text(text = value, fontSize = 10.sp, fontWeight = FontWeight.Medium, color = Color.White)
    }
}
