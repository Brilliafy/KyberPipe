package org.kyberpipe.client.components

import android.Manifest
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Point
import android.graphics.Rect
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.util.Size
import android.view.MotionEvent
import android.view.ScaleGestureDetector
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.Camera
import androidx.camera.core.CameraSelector
import androidx.camera.core.FocusMeteringAction
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageCapture
import androidx.camera.core.ImageCaptureException
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CenterFocusWeak
import androidx.compose.material.icons.filled.FlashOff
import androidx.compose.material.icons.filled.FlashOn
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size as GeometrySize
import androidx.compose.ui.graphics.BlendMode
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import com.google.mlkit.vision.barcode.BarcodeScannerOptions
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.kyberpipe.client.QrNative
import java.util.concurrent.Executors
import kotlin.math.abs
import kotlin.math.atan2

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

    var triggerManualScan by remember { mutableStateOf(false) }
    var isLoading by remember { mutableStateOf(false) }

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(420.dp)
            .background(Color.Black, shape = RoundedCornerShape(16.dp))
            .border(2.dp, MaterialTheme.colorScheme.primary, shape = RoundedCornerShape(16.dp)),
        contentAlignment = Alignment.Center
    ) {
        if (hasCameraPermission) {
            CameraPreview(
                onQrScanned = onQrScanned,
                manualScanRequested = triggerManualScan,
                onTriggerManualScan = { triggerManualScan = true },
                onScanComplete = { triggerManualScan = false },
                onLoading = { isLoading = it },
                onClose = onClose
            )

            if (isLoading) {
                Column(
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center,
                    modifier = Modifier
                        .fillMaxSize()
                        .background(Color.Black.copy(alpha = 0.75f))
                ) {
                    CircularProgressIndicator(color = Color(0xFF00FFCC))
                    Spacer(modifier = Modifier.height(12.dp))
                    Text("Scanning high-res capture with 3 models...", color = Color.White, fontSize = 13.sp, fontWeight = FontWeight.Bold)
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
    manualScanRequested: Boolean,
    onTriggerManualScan: () -> Unit,
    onScanComplete: () -> Unit,
    onLoading: (Boolean) -> Unit,
    onClose: () -> Unit
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val previewView = remember { PreviewView(context) }
    val coroutineScope = rememberCoroutineScope()
    var camera by remember { mutableStateOf<Camera?>(null) }

    var isTorchOn by remember { mutableStateOf(false) }
    var zoomRatio by remember { mutableFloatStateOf(1f) }
    var guidanceText by remember { mutableStateOf("Point camera at desktop QR code") }
    var detectedBox by remember { mutableStateOf<Rect?>(null) }
    var detectedCorners by remember { mutableStateOf<Array<Point>?>(null) }
    var frameWidth by remember { mutableFloatStateOf(1080f) }
    var frameHeight by remember { mutableFloatStateOf(1920f) }
    var isScanned by remember { mutableStateOf(false) }

    // Touch-to-Focus & Press-and-Hold Progress Circle (0% -> 100%)
    var touchFocusOffset by remember { mutableStateOf<Offset?>(null) }
    var holdProgress by remember { mutableFloatStateOf(0f) }
    var holdJob by remember { mutableStateOf<Job?>(null) }

    // Resizable green viewfinder state
    var customSquareSize by remember { mutableFloatStateOf(0f) }
    var isResizingFrame by remember { mutableStateOf(false) }

    val imageCapture = remember {
        ImageCapture.Builder()
            .setCaptureMode(ImageCapture.CAPTURE_MODE_MAXIMIZE_QUALITY)
            .build()
    }

    val imageAnalysis = remember {
        ImageAnalysis.Builder()
            .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
            .setOutputImageFormat(ImageAnalysis.OUTPUT_IMAGE_FORMAT_YUV_420_888)
            .build()
    }

    // Two-finger pinch to zoom gesture detector
    val scaleDetector = remember {
        ScaleGestureDetector(context, object : ScaleGestureDetector.SimpleOnScaleGestureListener() {
            override fun onScale(detector: ScaleGestureDetector): Boolean {
                val factor = detector.scaleFactor
                val newZoom = (zoomRatio * factor).coerceIn(1f, 5f)
                zoomRatio = newZoom
                camera?.cameraControl?.setZoomRatio(newZoom)
                return true
            }
        })
    }

    // Real-time continuous ML Kit barcode scanner
    LaunchedEffect(Unit) {
        val options = BarcodeScannerOptions.Builder()
            .setBarcodeFormats(Barcode.FORMAT_QR_CODE)
            .build()
        val scanner = BarcodeScanning.getClient(options)
        val analysisExec = Executors.newSingleThreadExecutor()

        imageAnalysis.setAnalyzer(analysisExec) { imageProxy ->
            if (isScanned) {
                imageProxy.close()
                return@setAnalyzer
            }
            val mediaImage = imageProxy.image
            if (mediaImage != null) {
                val rot = imageProxy.imageInfo.rotationDegrees
                val inputImage = InputImage.fromMediaImage(mediaImage, rot)

                val (w, h) = if (rot == 90 || rot == 270) {
                    Pair(mediaImage.height.toFloat(), mediaImage.width.toFloat())
                } else {
                    Pair(mediaImage.width.toFloat(), mediaImage.height.toFloat())
                }
                frameWidth = w
                frameHeight = h

                scanner.process(inputImage)
                    .addOnSuccessListener { barcodes ->
                        if (barcodes.isNotEmpty()) {
                            val barcode = barcodes.first()
                            detectedBox = barcode.boundingBox
                            detectedCorners = barcode.cornerPoints

                            val rawValue = barcode.rawValue
                            if (!rawValue.isNullOrEmpty() && !isScanned) {
                                isScanned = true
                                guidanceText = "QR Code Recognized!"
                                Handler(Looper.getMainLooper()).post {
                                    onQrScanned(rawValue)
                                }
                            } else if (barcode.cornerPoints != null && barcode.cornerPoints!!.size >= 3) {
                                val corners = barcode.cornerPoints!!
                                val cp0 = corners[0]
                                val cp1 = corners[1]
                                val dx = (cp1.x - cp0.x).toDouble()
                                val dy = (cp1.y - cp0.y).toDouble()
                                val angle = Math.toDegrees(atan2(dy, dx))

                                if (abs(angle) > 15.0) {
                                    guidanceText = "Rotate phone to align horizontally"
                                } else {
                                    val box = barcode.boundingBox
                                    val ratio = if (box != null) (box.width().toFloat() * box.height().toFloat()) / (w * h) else 0.1f
                                    guidanceText = if (ratio < 0.04f) {
                                        "Pinch to zoom in or move closer"
                                    } else {
                                        "Hold steady — aligning corners"
                                    }
                                }
                            }
                        } else {
                            detectedBox = null
                            detectedCorners = null
                            guidanceText = "Point camera or press & hold to scan"
                        }
                    }
                    .addOnFailureListener {
                        detectedBox = null
                        detectedCorners = null
                    }
                    .addOnCompleteListener {
                        imageProxy.close()
                    }
            } else {
                imageProxy.close()
            }
        }
    }

    // Manual photo trigger handler (runs all 3 decoders)
    LaunchedEffect(manualScanRequested) {
        if (!manualScanRequested) return@LaunchedEffect
        onLoading(true)
        val exec = Executors.newSingleThreadExecutor()
        imageCapture.takePicture(exec, object : ImageCapture.OnImageCapturedCallback() {
            override fun onCaptureSuccess(proxy: androidx.camera.core.ImageProxy) {
                val rot = proxy.imageInfo.rotationDegrees
                runFallbackDecoders(proxy, rot) { result ->
                    Handler(Looper.getMainLooper()).post {
                        if (!result.isNullOrEmpty()) {
                            onQrScanned(result)
                        } else {
                            Toast.makeText(context, "No QR found in capture", Toast.LENGTH_SHORT).show()
                        }
                    }
                    proxy.close()
                    onLoading(false)
                    onScanComplete()
                    exec.shutdown()
                }
            }
            override fun onError(e: ImageCaptureException) {
                Handler(Looper.getMainLooper()).post {
                    Toast.makeText(context, "Camera error: ${e.message}", Toast.LENGTH_SHORT).show()
                }
                onLoading(false)
                onScanComplete()
                exec.shutdown()
            }
        })
    }

    DisposableEffect(Unit) {
        val cameraProviderFuture = ProcessCameraProvider.getInstance(context)
        cameraProviderFuture.addListener({
            val cameraProvider = cameraProviderFuture.get()
            val preview = Preview.Builder().build().also {
                it.setSurfaceProvider(previewView.surfaceProvider)
            }
            try {
                cameraProvider.unbindAll()
                camera = cameraProvider.bindToLifecycle(
                    lifecycleOwner,
                    CameraSelector.DEFAULT_BACK_CAMERA,
                    preview,
                    imageAnalysis,
                    imageCapture
                )
            } catch (e: Exception) {
                Log.e("QrCodeScanner", "bind fail", e)
            }
        }, ContextCompat.getMainExecutor(context))

        onDispose {
            Log.d("QrCodeScanner", "dispose camera preview")
        }
    }

    Box(modifier = Modifier.fillMaxSize()) {
        // Camera Preview with Pinch-to-Zoom & Press-and-Hold Focus/Scan Listener
        AndroidView(
            factory = {
                previewView.apply {
                    setOnTouchListener { view, event ->
                        scaleDetector.onTouchEvent(event)
                        if (scaleDetector.isInProgress) {
                            holdJob?.cancel()
                            holdProgress = 0f
                            return@setOnTouchListener true
                        }

                        val viewW = width.toFloat()
                        val viewH = height.toFloat()

                        // Default square size: as wide as possible (96% width/height, 1:1 aspect ratio)
                        val currentSquare = if (customSquareSize > 0f) customSquareSize else minOf(viewW, viewH) * 0.96f
                        val left = (viewW - currentSquare) / 2
                        val top = (viewH - currentSquare) / 2
                        val right = left + currentSquare
                        val bottom = top + currentSquare

                        when (event.action) {
                            MotionEvent.ACTION_DOWN -> {
                                val tx = event.x
                                val ty = event.y
                                val handleRadius = 60f
                                val isNearCorner = (abs(tx - left) < handleRadius || abs(tx - right) < handleRadius) &&
                                        (abs(ty - top) < handleRadius || abs(ty - bottom) < handleRadius)

                                if (isNearCorner) {
                                    isResizingFrame = true
                                } else {
                                    // Trigger hardware AF, AE, and AWB (Auto-Focus / Auto-Exposure / White-Balance)
                                    val factory = previewView.meteringPointFactory
                                    val point = factory.createPoint(event.x, event.y)
                                    val action = FocusMeteringAction.Builder(
                                        point,
                                        FocusMeteringAction.FLAG_AF or FocusMeteringAction.FLAG_AE or FocusMeteringAction.FLAG_AWB
                                    ).setAutoCancelDuration(4, java.util.concurrent.TimeUnit.SECONDS).build()

                                    camera?.cameraControl?.startFocusAndMetering(action)
                                    touchFocusOffset = Offset(event.x, event.y)
                                    holdProgress = 0f

                                    // Start 0% -> 100% circular progress animation over 1.6 seconds of press & hold
                                    holdJob?.cancel()
                                    holdJob = coroutineScope.launch {
                                        val startTime = System.currentTimeMillis()
                                        val duration = 1600L
                                        while (true) {
                                            val elapsed = System.currentTimeMillis() - startTime
                                            val p = (elapsed.toFloat() / duration).coerceIn(0f, 1f)
                                            holdProgress = p
                                            if (p >= 1.0f) {
                                                // 100% reached -> Execute 3-model high-res capture!
                                                onTriggerManualScan()
                                                delay(500)
                                                touchFocusOffset = null
                                                holdProgress = 0f
                                                break
                                            }
                                            delay(16)
                                        }
                                    }
                                }
                            }
                            MotionEvent.ACTION_MOVE -> {
                                if (isResizingFrame) {
                                    val centerX = viewW / 2
                                    val centerY = viewH / 2
                                    val dist = maxOf(abs(event.x - centerX), abs(event.y - centerY)) * 2f
                                    val minSize = 250f
                                    val maxSize = minOf(viewW, viewH) * 0.98f
                                    customSquareSize = dist.coerceIn(minSize, maxSize)
                                    return@setOnTouchListener true
                                }
                            }
                            MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> {
                                if (isResizingFrame) {
                                    isResizingFrame = false
                                    return@setOnTouchListener true
                                }
                                // If released before 100%, cancel hold animation but keep focus point
                                if (holdProgress < 1.0f) {
                                    holdJob?.cancel()
                                    holdProgress = 0f
                                    Handler(Looper.getMainLooper()).postDelayed({
                                        touchFocusOffset = null
                                    }, 1200)
                                }
                                view.performClick()
                            }
                        }
                        true
                    }
                }
            },
            modifier = Modifier.fillMaxSize()
        )

        // Computer Vision AR Overlay: Neon Guiding Lines, 3 Finder Pattern Reticles & Resizable Box
        Canvas(modifier = Modifier.fillMaxSize()) {
            val canvasW = size.width
            val canvasH = size.height

            // Maximize 1:1 square width by default (96% of available width/height)
            val squareSize = if (customSquareSize > 0f) customSquareSize else minOf(canvasW, canvasH) * 0.96f
            val left = (canvasW - squareSize) / 2
            val top = (canvasH - squareSize) / 2

            // Dim outer region
            drawRect(color = Color.Black.copy(alpha = 0.45f))

            // Viewfinder cutout
            drawRoundRect(
                color = Color.Transparent,
                topLeft = Offset(left, top),
                size = GeometrySize(squareSize, squareSize),
                cornerRadius = CornerRadius(16.dp.toPx(), 16.dp.toPx()),
                blendMode = BlendMode.Clear
            )

            // Viewfinder border (Neon Green if QR detected, Cyan otherwise)
            val borderCol = if (detectedBox != null) Color(0xFF00FFCC) else Color.White.copy(alpha = 0.7f)
            drawRoundRect(
                color = borderCol,
                topLeft = Offset(left, top),
                size = GeometrySize(squareSize, squareSize),
                cornerRadius = CornerRadius(16.dp.toPx(), 16.dp.toPx()),
                style = Stroke(width = 3.dp.toPx())
            )

            // Resizable Frame Corner Drag Handles (4 glowing dots)
            val cornersList = listOf(
                Offset(left, top),
                Offset(left + squareSize, top),
                Offset(left + squareSize, top + squareSize),
                Offset(left, top + squareSize)
            )
            for (cornerPos in cornersList) {
                drawCircle(
                    color = Color(0xFF00FFCC),
                    radius = 8.dp.toPx(),
                    center = cornerPos
                )
                drawCircle(
                    color = Color.White,
                    radius = 4.dp.toPx(),
                    center = cornerPos
                )
            }

            // COMPUTER VISION AR OVERLAY: 4-Corner Neon Polygon + 3 Finder Pattern Target Reticles
            detectedCorners?.let { corners ->
                if (corners.size >= 4) {
                    val scaleX = canvasW / frameWidth
                    val scaleY = canvasH / frameHeight

                    val p0 = Offset(corners[0].x * scaleX, corners[0].y * scaleY) // Top-Left Finder
                    val p1 = Offset(corners[1].x * scaleX, corners[1].y * scaleY) // Top-Right Finder
                    val p2 = Offset(corners[2].x * scaleX, corners[2].y * scaleY) // Bottom-Right
                    val p3 = Offset(corners[3].x * scaleX, corners[3].y * scaleY) // Bottom-Left Finder

                    // 1. Draw Neon Laser Polygon connecting all 4 QR corners
                    val polyPath = Path().apply {
                        moveTo(p0.x, p0.y)
                        lineTo(p1.x, p1.y)
                        lineTo(p2.x, p2.y)
                        lineTo(p3.x, p3.y)
                        close()
                    }
                    drawPath(
                        path = polyPath,
                        color = Color(0xFF00E676),
                        style = Stroke(width = 3.dp.toPx(), cap = StrokeCap.Round)
                    )

                    // 2. Draw Translucent Center Crosshairs connecting diagonal corners
                    drawLine(
                        color = Color(0x8000FFCC),
                        start = p0,
                        end = p2,
                        strokeWidth = 1.5f.dp.toPx()
                    )
                    drawLine(
                        color = Color(0x8000FFCC),
                        start = p1,
                        end = p3,
                        strokeWidth = 1.5f.dp.toPx()
                    )

                    // 3. Draw Computer Vision Target Reticles on the 3 QR Finder Pattern Corners (p0, p1, p3)
                    listOf(p0, p1, p3).forEach { finderPos ->
                        drawCircle(
                            color = Color(0xFF00FFCC),
                            radius = 16.dp.toPx(),
                            center = finderPos,
                            style = Stroke(width = 2.dp.toPx())
                        )
                        drawCircle(
                            color = Color(0xFF00E676),
                            radius = 6.dp.toPx(),
                            center = finderPos
                        )
                    }
                }
            }

            // Draw Touch Focus Ring + 0% to 100% Loading Progress Sweep Circle
            touchFocusOffset?.let { offset ->
                val radius = 38.dp.toPx()

                // Outer translucent focus ring
                drawCircle(
                    color = Color.White.copy(alpha = 0.35f),
                    radius = radius,
                    center = offset,
                    style = Stroke(width = 3.dp.toPx())
                )

                // Animated sweep arc (fills 0° -> 360° over 1.6s of press & hold)
                if (holdProgress > 0f) {
                    val sweepAngle = holdProgress * 360f
                    drawArc(
                        color = Color(0xFF00FFCC),
                        startAngle = -90f,
                        sweepAngle = sweepAngle,
                        useCenter = false,
                        topLeft = Offset(offset.x - radius, offset.y - radius),
                        size = GeometrySize(radius * 2, radius * 2),
                        style = Stroke(width = 4.5f.dp.toPx(), cap = StrokeCap.Round)
                    )
                } else {
                    drawCircle(
                        color = Color(0xFF00FFCC),
                        radius = radius,
                        center = offset,
                        style = Stroke(width = 2.dp.toPx())
                    )
                }
            }
        }

        // Top Control Bar (Close & Flashlight toggle)
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            IconButton(
                onClick = {
                    isTorchOn = !isTorchOn
                    camera?.cameraControl?.enableTorch(isTorchOn)
                },
                modifier = Modifier
                    .background(Color.Black.copy(alpha = 0.6f), shape = CircleShape)
                    .size(36.dp)
            ) {
                Icon(
                    imageVector = if (isTorchOn) Icons.Default.FlashOn else Icons.Default.FlashOff,
                    contentDescription = "Toggle Torch",
                    tint = if (isTorchOn) Color(0xFFFFD700) else Color.White
                )
            }

            Button(
                onClick = onClose,
                colors = ButtonDefaults.buttonColors(containerColor = Color.Black.copy(alpha = 0.6f)),
                contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp),
                modifier = Modifier.height(32.dp)
            ) {
                Text("Close", color = Color.White, fontSize = 11.sp)
            }
        }

        // Bottom Controls: Computer Vision Guidance & Zoom Controls
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(bottom = 12.dp),
            verticalArrangement = Arrangement.Bottom,
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            // Live Computer Vision Guidance text
            Text(
                text = guidanceText,
                color = Color.White,
                fontSize = 11.sp,
                fontWeight = FontWeight.Bold,
                textAlign = TextAlign.Center,
                modifier = Modifier
                    .background(Color.Black.copy(alpha = 0.75f), shape = RoundedCornerShape(6.dp))
                    .padding(horizontal = 10.dp, vertical = 5.dp)
            )

            Spacer(modifier = Modifier.height(8.dp))

            // Quick Zoom Chips (1x, 1.5x, 2x, 3x) + Pinch Gesture indicator
            Row(
                horizontalArrangement = Arrangement.Center,
                verticalAlignment = Alignment.CenterVertically
            ) {
                listOf(1f, 1.5f, 2f, 3f).forEach { scale ->
                    val isSelected = (abs(zoomRatio - scale) < 0.2f)
                    Box(
                        modifier = Modifier
                            .padding(horizontal = 4.dp)
                            .background(
                                if (isSelected) Color(0xFF00FFCC) else Color.Black.copy(alpha = 0.6f),
                                shape = RoundedCornerShape(12.dp)
                            )
                            .clickable {
                                zoomRatio = scale
                                camera?.cameraControl?.setZoomRatio(scale)
                            }
                            .padding(horizontal = 10.dp, vertical = 4.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = "${scale}x",
                            color = if (isSelected) Color.Black else Color.White,
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }
            }
        }
    }
}

private fun decodeJpegToGrayscale(jpeg: ByteArray, sampleSize: Int): Triple<ByteArray, Int, Int>? {
    return try {
        val opts = BitmapFactory.Options().apply { inSampleSize = sampleSize }
        val bmp = BitmapFactory.decodeByteArray(jpeg, 0, jpeg.size, opts) ?: return null
        val bw = bmp.width
        val bh = bmp.height
        val px = IntArray(bw * bh)
        bmp.getPixels(px, 0, bw, 0, 0, bw, bh)
        bmp.recycle()
        val g = ByteArray(bw * bh)
        for (i in px.indices) {
            val p = px[i]
            g[i] = ((0.299 * ((p shr 16) and 0xFF) + 0.587 * ((p shr 8) and 0xFF) + 0.114 * (p and 0xFF)).toInt()).toByte()
        }
        Triple(g, bw, bh)
    } catch (e: Exception) {
        Log.e("QrCodeScanner", "decodeJpegToGrayscale error for sampleSize=$sampleSize", e)
        null
    }
}

private fun runFallbackDecoders(proxy: androidx.camera.core.ImageProxy, rot: Int, callback: (String?) -> Unit) {
    val img = proxy.image ?: return callback(null)
    try {
        // 1. Try ML Kit on high-res media image first
        val inputImage = InputImage.fromMediaImage(img, rot)
        val scanner = BarcodeScanning.getClient(
            BarcodeScannerOptions.Builder().setBarcodeFormats(Barcode.FORMAT_QR_CODE).build()
        )
        scanner.process(inputImage)
            .addOnSuccessListener { barcodes ->
                val mlResult = barcodes.firstOrNull()?.rawValue
                if (!mlResult.isNullOrEmpty()) {
                    Log.w("QrCodeScanner", "Captured photo MLKit DECODED ${mlResult.length} chars")
                    callback(mlResult)
                } else {
                    Log.d("QrCodeScanner", "Captured photo MLKit null, trying ZXing & rqrr...")
                    runZxingAndRqrrFallback(img, proxy, rot, callback)
                }
            }
            .addOnFailureListener {
                runZxingAndRqrrFallback(img, proxy, rot, callback)
            }
    } catch (e: Exception) {
        Log.e("QrCodeScanner", "MLKit capture error: ${e.message}", e)
        runZxingAndRqrrFallback(img, proxy, rot, callback)
    }
}

private fun runZxingAndRqrrFallback(img: android.media.Image, proxy: androidx.camera.core.ImageProxy, rot: Int, callback: (String?) -> Unit) {
    try {
        if (img.format == 256) {
            val buf = img.planes[0].buffer
            val jpeg = ByteArray(buf.remaining())
            buf.get(jpeg)

            val zxResult = decodeWithZxing(jpeg, 1) ?: decodeWithZxing(jpeg, 2)
            if (!zxResult.isNullOrEmpty()) {
                Log.w("QrCodeScanner", "Captured photo ZXing DECODED ${zxResult.length} chars")
                return callback(zxResult)
            }

            val fullRes = decodeJpegToGrayscale(jpeg, 1)
            if (fullRes != null) {
                val (gray, bw, bh) = fullRes
                val rqrrResult = QrNative.decodeQrCode(gray, bw, bh, bw, rot)
                if (!rqrrResult.isNullOrEmpty()) {
                    Log.w("QrCodeScanner", "Captured photo rqrr DECODED ${rqrrResult.length} chars")
                    return callback(rqrrResult)
                }
            }
        } else {
            val yPlane = img.planes[0]
            val yBuf = yPlane.buffer
            val yStride = yPlane.rowStride
            val stride = if (yStride >= proxy.width) yStride else proxy.width
            yBuf.rewind()
            val yRaw = ByteArray(stride * proxy.height)
            yBuf.get(yRaw, 0, minOf(yBuf.remaining(), stride * proxy.height))
            val rqrrResult = QrNative.decodeQrCode(yRaw, proxy.width, proxy.height, stride, rot)
            if (!rqrrResult.isNullOrEmpty()) {
                Log.w("QrCodeScanner", "Captured photo rqrr YUV DECODED ${rqrrResult.length} chars")
                return callback(rqrrResult)
            }
        }
    } catch (e: Exception) {
        Log.e("QrCodeScanner", "Zxing/rqrr fallback error", e)
    }
    callback(null)
}

private fun decodeWithZxing(jpeg: ByteArray, sampleSize: Int): String? {
    return try {
        val opts = BitmapFactory.Options().apply { inSampleSize = sampleSize }
        val bmp = BitmapFactory.decodeByteArray(jpeg, 0, jpeg.size, opts) ?: return null
        val bw = bmp.width; val bh = bmp.height
        val px = IntArray(bw * bh)
        bmp.getPixels(px, 0, bw, 0, 0, bw, bh)
        bmp.recycle()

        val source = RGBLuminanceSource(bw, bh, px)
        val binaryBmp = BinaryBitmap(HybridBinarizer(source))
        val hints = mapOf(
            DecodeHintType.TRY_HARDER to true,
            DecodeHintType.POSSIBLE_FORMATS to listOf(com.google.zxing.BarcodeFormat.QR_CODE)
        )
        val reader = MultiFormatReader()
        reader.setHints(hints)
        reader.decode(binaryBmp).text
    } catch (_: Exception) {
        null
    }
}