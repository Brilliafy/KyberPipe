package org.kyberpipe.client.components

import android.Manifest
import android.content.pm.PackageManager
import android.util.Log
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageCapture
import androidx.camera.core.ImageCaptureException
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
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.NotFoundException
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.GlobalHistogramBinarizer
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.common.HybridBinarizer
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
            var scanReq by remember { mutableStateOf(false) }
            CameraPreview(onQrScanned = onQrScanned, scanRequested = scanReq, onScanComplete = { scanReq = false })
            
            Canvas(modifier = Modifier.fillMaxSize()) {
                val squareSize = 160.dp.toPx()
                val left = (size.width - squareSize) / 2
                val top = (size.height - squareSize) / 2

                drawRect(color = Color.Black.copy(alpha = 0.5f))

                drawRoundRect(
                    color = Color.Transparent,
                    topLeft = Offset(left, top),
                    size = Size(squareSize, squareSize),
                    cornerRadius = CornerRadius(12.dp.toPx(), 12.dp.toPx()),
                    blendMode = BlendMode.Clear
                )

                drawRoundRect(
                    color = Color.Green,
                    topLeft = Offset(left, top),
                    size = Size(squareSize, squareSize),
                    cornerRadius = CornerRadius(12.dp.toPx(), 12.dp.toPx()),
                    style = Stroke(width = 2.dp.toPx())
                )
            }

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

            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(bottom = 12.dp),
                contentAlignment = Alignment.BottomCenter
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text(
                        text = "Tap screen for high-res capture",
                        color = Color.White,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        textAlign = TextAlign.Center,
                        modifier = Modifier
                            .background(Color.Black.copy(alpha = 0.6f), shape = RoundedCornerShape(4.dp))
                            .padding(horizontal = 8.dp, vertical = 4.dp)
                    )
                    Spacer(modifier = Modifier.height(6.dp))
                    Button(
                        onClick = { scanReq = true },
                        colors = ButtonDefaults.buttonColors(containerColor = Color.White.copy(alpha = 0.9f)),
                        contentPadding = PaddingValues(horizontal = 20.dp, vertical = 6.dp),
                        modifier = Modifier.height(36.dp)
                    ) {
                        Text("Tap to Scan", color = Color.Black, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                    }
                }
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
    onQrScanned: (String) -> Unit,
    scanRequested: Boolean,
    onScanComplete: () -> Unit
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val previewView = remember { PreviewView(context) }
    val imageCapture = remember { ImageCapture.Builder().setCaptureMode(ImageCapture.CAPTURE_MODE_MAXIMIZE_QUALITY).build() }

    LaunchedEffect(scanRequested) {
        if (!scanRequested) return@LaunchedEffect
        Log.d("QrCodeScanner", "capturing photo for ZXing decode...")
        val exec = Executors.newSingleThreadExecutor()
        imageCapture.takePicture(exec, object : ImageCapture.OnImageCapturedCallback() {
            override fun onCaptureSuccess(proxy: androidx.camera.core.ImageProxy) {
                val img = proxy.image
                if (img != null) {
                    val w = proxy.width; val h = proxy.height
                    Log.w("QrCodeScanner", "photo: ${w}x${h}")
                    val yPlane = img.planes[0]
                    val yBuf = yPlane.buffer
                    val yStride = yPlane.rowStride
                    val stride = if (yStride >= w) yStride else w
                    yBuf.rewind()
                    val yRaw = ByteArray(stride * h)
                    yBuf.get(yRaw, 0, minOf(yBuf.remaining(), stride * h))

                    try {
                        Log.d("QrDebug", "stride=$yStride actual=$stride w=$w h=$h rot=${proxy.imageInfo.rotationDegrees}")
                        // Rotate byte array if 90/270 (portrait phone, landscape sensor)
                        val rot = proxy.imageInfo.rotationDegrees
                        val (rotated, rw, rh) = if (rot == 90) {
                            val r = ByteArray(w * h)
                            var i = 0
                            for (x in 0 until w)
                                for (y in h - 1 downTo 0)
                                    r[i++] = yRaw[y * stride + x]
                            Triple(r, h, w)
                        } else if (rot == 270) {
                            val r = ByteArray(w * h)
                            var i = 0
                            for (x in w - 1 downTo 0)
                                for (y in 0 until h)
                                    r[i++] = yRaw[y * stride + x]
                            Triple(r, h, w)
                        } else {
                            Triple(yRaw, stride, h)
                        }

                        val source = PlanarYUVLuminanceSource(rotated, rw, rh, 0, 0, rw, rh, false)
                        val hints = mapOf(
                            DecodeHintType.TRY_HARDER to true,
                            DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE)
                        )
                        val reader = MultiFormatReader().apply { setHints(hints) }
                        val result = try {
                            reader.decode(BinaryBitmap(HybridBinarizer(source)))
                        } catch (_: NotFoundException) {
                            reader.decode(BinaryBitmap(GlobalHistogramBinarizer(source)))
                        }
                        val text = result.text
                        if (text != null && text.isNotEmpty()) {
                            Log.w("QrCodeScanner", "ZXing DECODED ${text.length} chars")
                            onQrScanned(text)
                        }
                    } catch (e: Exception) {
                        Log.e("QrCodeScanner", "ZXing ${e::class.simpleName}: ${e.message}")
                    }
                }
                proxy.close()
                onScanComplete()
                exec.shutdown()
            }
            override fun onError(e: ImageCaptureException) {
                Log.e("QrCodeScanner", "photo capture error", e)
                onScanComplete()
                exec.shutdown()
            }
        })
    }

    DisposableEffect(Unit) {
        Log.d("QrCodeScanner", "setting up camera")
        val cameraProviderFuture = ProcessCameraProvider.getInstance(context)
        cameraProviderFuture.addListener({
            val cameraProvider = cameraProviderFuture.get()
            Log.d("QrCodeScanner", "camera acquired")

            val preview = Preview.Builder().build().also {
                it.setSurfaceProvider(previewView.surfaceProvider)
            }

            try {
                cameraProvider.unbindAll()
                cameraProvider.bindToLifecycle(
                    lifecycleOwner, CameraSelector.DEFAULT_BACK_CAMERA,
                    preview, imageCapture
                )
                Log.d("QrCodeScanner", "bound (preview + imageCapture)")
            } catch (e: Exception) {
                Log.e("QrCodeScanner", "bind fail", e)
            }
        }, ContextCompat.getMainExecutor(context))

        onDispose {
            Log.d("QrCodeScanner", "dispose")
        }
    }

    AndroidView(
        factory = { previewView },
        modifier = Modifier.fillMaxSize()
    )
}