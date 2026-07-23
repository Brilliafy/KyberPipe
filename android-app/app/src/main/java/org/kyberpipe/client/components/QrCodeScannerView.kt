package org.kyberpipe.client.components

import android.Manifest
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.ImageFormat
import android.graphics.Rect
import android.graphics.YuvImage
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
import com.google.zxing.BinaryBitmap
import com.google.zxing.MultiFormatReader
import com.google.zxing.RGBLuminanceSource
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
                    Log.w("QrCodeScanner", "photo: ${proxy.width}x${proxy.height}")
                    // Convert YUV_420_888 to NV21 Bitmap for ZXing
                    val nv21 = yuv420toNv21(img, proxy.width, proxy.height)
                    val yuv = YuvImage(nv21, ImageFormat.NV21, proxy.width, proxy.height, null)
                    val jpeg = ByteArrayOutputStream()
                    yuv.compressToJpeg(Rect(0, 0, proxy.width, proxy.height), 100, jpeg)
                    val bitmap = BitmapFactory.decodeByteArray(jpeg.toByteArray(), 0, jpeg.size())
                    jpeg.close()
                    try {
                        val w = bitmap.width; val h = bitmap.height
                        val pixels = IntArray(w * h)
                        bitmap.getPixels(pixels, 0, w, 0, 0, w, h)
                        val source = RGBLuminanceSource(w, h, pixels)
                        val result = MultiFormatReader().decode(BinaryBitmap(HybridBinarizer(source)))
                        val text = result.text
                        if (text != null && text.isNotEmpty()) {
                            Log.w("QrCodeScanner", "ZXing DECODED ${text.length} chars")
                            onQrScanned(text)
                        }
                    } catch (e: Exception) {
                        Log.e("QrCodeScanner", "ZXing fail: ${e.message}")
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

private fun yuv420toNv21(image: android.media.Image, width: Int, height: Int): ByteArray {
    val planes = image.planes
    val yPlane = planes[0]
    val yBuf = yPlane.buffer
    val yStride = yPlane.rowStride
    // Tightly pack Y plane
    val yTight = ByteArray(width * height)
    for (row in 0 until height) {
        yBuf.position(row * yStride)
        yBuf.get(yTight, row * width, width)
    }
    if (planes.size <= 1) return yTight

    // For multi-plane, build NV21 with interleaved VU
    val uvCount = (width * height) / 4
    val nv21 = ByteArray(yTight.size + uvCount * 2)
    System.arraycopy(yTight, 0, nv21, 0, yTight.size)

    if (planes.size >= 3) {
        val uBuf = planes[1].buffer; val uArr = ByteArray(uBuf.remaining()); uBuf.get(uArr)
        val vBuf = planes[2].buffer; val vArr = ByteArray(vBuf.remaining()); vBuf.get(vArr)
        var off = yTight.size
        val len = minOf(uArr.size, vArr.size, uvCount)
        for (i in 0 until len) {
            nv21[off++] = if (i < vArr.size) vArr[i] else 128.toByte()
            nv21[off++] = if (i < uArr.size) uArr[i] else 128.toByte()
        }
    } else if (planes.size >= 2) {
        val uvBuf = planes[1].buffer
        val uvArr = ByteArray(uvBuf.remaining()); uvBuf.get(uvArr)
        System.arraycopy(uvArr, 0, nv21, yTight.size, minOf(uvArr.size, uvCount * 2))
    }
    return nv21
}