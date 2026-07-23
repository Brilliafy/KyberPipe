package org.kyberpipe.client.components

import android.Manifest
import android.content.pm.PackageManager
import android.graphics.ImageFormat
import android.graphics.YuvImage
import android.util.Log
import android.view.ViewGroup
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.BlendMode
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import com.google.zxing.BinaryBitmap
import com.google.zxing.MultiFormatReader
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import java.io.ByteArrayOutputStream
import java.util.concurrent.Executors

@Composable
fun QrCodeScannerView(
    onQrScanned: (String) -> Unit,
    onClose: () -> Unit
) {
    val context = LocalContext.current
    var hasCameraPermission by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.CAMERA
            ) == PackageManager.PERMISSION_GRANTED
        )
    }

    val launcher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission(),
        onResult = { granted ->
            hasCameraPermission = granted
        }
    )

    LaunchedEffect(key1 = true) {
        if (!hasCameraPermission) {
            launcher.launch(Manifest.permission.CAMERA)
        }
    }

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(280.dp)
            .background(Color.Black, shape = RoundedCornerShape(12.dp))
            .border(2.dp, MaterialTheme.colorScheme.primary, shape = RoundedCornerShape(12.dp)),
        contentAlignment = Alignment.Center
    ) {
        if (hasCameraPermission) {
            CameraPreview(onQrScanned = onQrScanned)
            
            // Premium Cutout Overlay with custom visual guidelines
            Canvas(modifier = Modifier.fillMaxSize()) {
                val squareSize = 160.dp.toPx()
                val left = (size.width - squareSize) / 2
                val top = (size.height - squareSize) / 2

                // 1. Draw solid overlay background
                drawRect(color = Color.Black.copy(alpha = 0.5f))

                // 2. Draw cutout rectangle with BlendMode.Clear
                drawRoundRect(
                    color = Color.Transparent,
                    topLeft = Offset(left, top),
                    size = Size(squareSize, squareSize),
                    cornerRadius = CornerRadius(12.dp.toPx(), 12.dp.toPx()),
                    blendMode = BlendMode.Clear
                )

                // 3. Draw a green frame border around the cutout
                drawRoundRect(
                    color = Color.Green,
                    topLeft = Offset(left, top),
                    size = Size(squareSize, squareSize),
                    cornerRadius = CornerRadius(12.dp.toPx(), 12.dp.toPx()),
                    style = Stroke(width = 2.dp.toPx())
                )
            }

            // Close button overlay
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(8.dp),
                contentAlignment = Alignment.TopEnd
            ) {
                Button(
                    onClick = onClose,
                    colors = ButtonDefaults.buttonColors(containerColor = Color.Black.copy(alpha = 0.6f)),
                    contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp),
                    modifier = Modifier.height(32.dp)
                ) {
                    Text("Close", color = Color.White, fontSize = 11.sp)
                }
            }

            // Instructional text overlay
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(bottom = 12.dp),
                contentAlignment = Alignment.BottomCenter
            ) {
                Text(
                    text = "Align QR Code inside the green frame",
                    color = Color.White,
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    textAlign = TextAlign.Center,
                    modifier = Modifier
                        .background(Color.Black.copy(alpha = 0.6f), shape = RoundedCornerShape(4.dp))
                        .padding(horizontal = 8.dp, vertical = 4.dp)
                )
            }
        } else {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center,
                modifier = Modifier.padding(16.dp)
            ) {
                Text(
                    text = "Camera permission is required to scan QR codes.",
                    color = Color.White,
                    fontSize = 13.sp,
                    textAlign = TextAlign.Center
                )
                Spacer(modifier = Modifier.height(12.dp))
                Button(onClick = { launcher.launch(Manifest.permission.CAMERA) }) {
                    Text("Grant Permission")
                }
            }
        }
    }
}

@Composable
fun CameraPreview(
    onQrScanned: (String) -> Unit
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val executor = remember { Executors.newSingleThreadExecutor() }
    val reader = remember { MultiFormatReader() }
    var previewView by remember { mutableStateOf<PreviewView?>(null) }

    DisposableEffect(Unit) {
        onDispose {
            executor.shutdown()
        }
    }

    AndroidView(
        factory = { ctx ->
            PreviewView(ctx).apply {
                layoutParams = ViewGroup.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.MATCH_PARENT
                )
                previewView = this
            }
        },
        modifier = Modifier.fillMaxSize(),
        update = { view ->
            val cameraProvider = try {
                ProcessCameraProvider.getInstance(context).get()
            } catch (e: Exception) {
                Log.e("QrCodeScanner", "Failed to get camera provider", e)
                null
            }
            if (cameraProvider != null) {
                val preview = Preview.Builder().build().also {
                    it.setSurfaceProvider(previewView?.surfaceProvider)
                }

                val imageAnalysis = ImageAnalysis.Builder()
                    .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                    .setTargetResolution(android.util.Size(1280, 720))
                    .build()

                imageAnalysis.setAnalyzer(executor) { imageProxy ->
                    val planes = imageProxy.planes
                    if (planes.isNotEmpty()) {
                        val yPlane = planes[0]
                        val buffer = yPlane.buffer
                        val rowStride = yPlane.rowStride
                        val width = imageProxy.width
                        val height = imageProxy.height
                        val yBytes = ByteArray(width * height)
                        for (row in 0 until height) {
                            buffer.position(row * rowStride)
                            buffer.get(yBytes, row * width, width)
                        }
                        try {
                            val source = PlanarYUVLuminanceSource(
                                yBytes, width, height,
                                0, 0, width, height,
                                false
                            )
                            val bitmap = BinaryBitmap(HybridBinarizer(source))
                            val result = reader.decodeWithState(bitmap)
                            val text = result.text
                            if (text != null && text.isNotEmpty()) {
                                Log.i("QrCodeScanner", "ZXing decoded OK (${text.length} chars)")
                                onQrScanned(text)
                            }
                        } catch (_: Exception) {
                            // No QR in this frame
                        }
                    }
                    imageProxy.close()
                }

                val cameraSelector = CameraSelector.DEFAULT_BACK_CAMERA

                try {
                    cameraProvider.unbindAll()
                    cameraProvider.bindToLifecycle(
                        lifecycleOwner,
                        cameraSelector,
                        preview,
                        imageAnalysis
                    )
                } catch (exc: Exception) {
                    Log.e("QrCodeScanner", "Use case binding failed", exc)
                }
            }
        }
    )
}
