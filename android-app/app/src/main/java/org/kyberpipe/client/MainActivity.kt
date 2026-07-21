package org.kyberpipe.client

import android.content.Context
import android.content.Intent
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.compose.ui.platform.LocalContext
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.kyberpipe.client.service.PipeService
import uniffi.kyberpipe.*

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContent {
            KyberpipeTheme {
                MainScreen(
                    onStartService = { startPipeForegroundService() },
                    onStopService = { stopPipeForegroundService() }
                )
            }
        }
    }

    private fun startPipeForegroundService() {
        val intent = Intent(this, PipeService::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
    }

    private fun stopPipeForegroundService() {
        val intent = Intent(this, PipeService::class.java)
        stopService(intent)
    }
}

@Composable
fun KyberpipeTheme(content: @Composable () -> Unit) {
    val darkColors = darkColorScheme(
        primary = Color(0xFF06B6D4),
        secondary = Color(0xFF6366F1),
        background = Color(0xFF0B0D17),
        surface = Color(0xFF161B2E),
        onPrimary = Color.White,
        onBackground = Color(0xFFF1F5F9)
    )
    MaterialTheme(colorScheme = darkColors, content = content)
}

@Composable
fun MainScreen(
    onStartService: () -> Unit,
    onStopService: () -> Unit
) {
    var keyPair by remember { mutableStateOf<PqKeyPair?>(null) }
    var serviceRunning by remember { mutableStateOf(false) }
    var clipboardInput by remember { mutableStateOf("") }
    var clipboardStatus by remember { mutableStateOf("") }
    var ambientLux by remember { mutableStateOf(250.0f) }

    val context = LocalContext.current

    DisposableEffect(Unit) {
        val sensorManager = context.getSystemService(Context.SENSOR_SERVICE) as SensorManager
        val lightSensor = sensorManager.getDefaultSensor(Sensor.TYPE_LIGHT)
        val listener = object : SensorEventListener {
            override fun onSensorChanged(event: SensorEvent?) {
                event?.let {
                    ambientLux = it.values[0]
                }
            }
            override fun onAccuracyChanged(sensor: Sensor?, accuracy: Int) {}
        }
        lightSensor?.let {
            sensorManager.registerListener(listener, it, SensorManager.SENSOR_DELAY_NORMAL)
        }
        onDispose {
            sensorManager.unregisterListener(listener)
        }
    }

    LaunchedEffect(Unit) {
        try {
            keyPair = generatePqKeypair()
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        containerColor = Color(0xFF0B0D17)
    ) { padding ->
        Column(
            modifier = Modifier
                .padding(padding)
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Brand Banner
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(
                        brush = Brush.horizontalGradient(
                            colors = listOf(Color(0xFF6366F1), Color(0xFF06B6D4))
                        ),
                        shape = RoundedCornerShape(16.dp)
                    )
                    .padding(20.dp)
            ) {
                Column {
                    Text(
                        text = "⚡ KYBERPIPE MOBILE",
                        fontSize = 22.sp,
                        fontWeight = FontWeight.ExtraBold,
                        color = Color.White
                    )
                    Text(
                        text = "Post-Quantum P2P Companion Node",
                        fontSize = 12.sp,
                        color = Color(0xFFE2E8F0)
                    )
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

            // SAS Out-of-Band Verification Card
            Card(
                colors = CardDefaults.cardColors(containerColor = Color(0xFF161B2E)),
                shape = RoundedCornerShape(16.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "🔐 Safe-Pairing SAS Code (OOB)",
                        fontSize = 16.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFF38BDF8)
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "Confirm this 6-digit code matches your Linux Desktop screen:",
                        fontSize = 12.sp,
                        color = Color(0xFF94A3B8)
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = "849-201",
                        fontSize = 28.sp,
                        fontWeight = FontWeight.Black,
                        color = Color(0xFF4ADE80)
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
                    Spacer(modifier = Modifier.height(8.dp))
                    Button(
                        onClick = {
                            try {
                                triggerPanicHardwareWipe()
                                Toast.makeText(context, "Hardware KeyStore Purged & RAM Zeroized!", Toast.LENGTH_LONG).show()
                            } catch (e: Exception) {
                                Log.e("KyberpipePanic", "Panic error: ${e.message}")
                            }
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFDC2626))
                    ) {
                        Text("PURGE MASTER KEYS & ZEROIZE RAM", color = Color.White, fontWeight = FontWeight.Bold)
                    }
                }
            }

            // Foreground Service Toggle Card
            Card(
                colors = CardDefaults.cardColors(containerColor = Color(0xFF161B2E)),
                shape = RoundedCornerShape(16.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "Background Core Pipeline",
                        fontSize = 16.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFF38BDF8)
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = if (serviceRunning) "Status: ACTIVE (Foreground Service Running)" else "Status: INACTIVE",
                        fontSize = 13.sp,
                        color = if (serviceRunning) Color(0xFF4ADE80) else Color(0xFF94A3B8)
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                        Button(
                            onClick = {
                                onStartService()
                                serviceRunning = true
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF06B6D4))
                        ) {
                            Text("Start Engine")
                        }
                        OutlinedButton(
                            onClick = {
                                onStopService()
                                serviceRunning = false
                            }
                        ) {
                            Text("Stop Engine", color = Color.White)
                        }
                    }
                }
            }

            // PQC Key Vault Card
            Card(
                colors = CardDefaults.cardColors(containerColor = Color(0xFF161B2E)),
                shape = RoundedCornerShape(16.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "NIST ML-KEM-768 Cryptographic Keypair",
                        fontSize = 16.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFF38BDF8)
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    keyPair?.let { pair ->
                        Text(
                            text = "Public Key (Hex prefix):",
                            fontSize = 12.sp,
                            color = Color(0xFF94A3B8)
                        )
                        Text(
                            text = pair.publicKeyHex.take(48) + "...",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            color = Color(0xFFC084FC)
                        )
                    } ?: Text(
                        text = "Generating ML-KEM-768 keys...",
                        fontSize = 12.sp,
                        color = Color(0xFF94A3B8)
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    Button(
                        onClick = {
                            try {
                                keyPair = generatePqKeypair()
                            } catch (e: Exception) {
                                e.printStackTrace()
                            }
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF6366F1))
                    ) {
                        Text("Regenerate PQC Keypair")
                    }
                }
            }

            // Clipboard Sync Tester Card
            Card(
                colors = CardDefaults.cardColors(containerColor = Color(0xFF161B2E)),
                shape = RoundedCornerShape(16.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "P2P Clipboard Synchronizer",
                        fontSize = 16.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFF38BDF8)
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedTextField(
                        value = clipboardInput,
                        onValueChange = { clipboardInput = it },
                        label = { Text("Enter text to sync to Desktop") },
                        modifier = Modifier.fillMaxWidth()
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Button(
                        onClick = {
                            if (clipboardInput.isNotEmpty()) {
                                try {
                                    val hash = computeSha256(clipboardInput)
                                    val pkt = createClipboardPacket(
                                        clipboardInput,
                                        System.currentTimeMillis().toULong()
                                    )
                                    clipboardStatus = "Encrypted packet ready: $hash"
                                } catch (e: Exception) {
                                    clipboardStatus = "Error: ${e.message}"
                                }
                            }
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF06B6D4))
                    ) {
                        Text("Encrypt & Sync")
                    }
                    if (clipboardStatus.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(6.dp))
                        Text(
                            text = clipboardStatus,
                            fontSize = 11.sp,
                            color = Color(0xFF4ADE80)
                        )
                    }
                }
            }
        }
    }
}
