package com.kira.pawlocker.ui.platform

import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.theme.MiuixTheme
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Android 二维码扫描视图。
 *
 * 实现选择：CameraX + zxing 纯软件解码，而不是 ML Kit。
 *  - ML Kit 的扫码依赖 Google Play 服务，部分设备上不可用，包体也大一截
 *  - 二维码是高对比度的结构化图案，zxing 软件解码在 720p 单帧上耗时个位数毫秒，
 *    完全跟得上预览帧率
 *
 * 一次扫描会话只投递第一个成功解码的结果，避免同一次配对连续触发多遍网络请求。
 */
@Composable
actual fun QrScanView(
    onDecoded: (String) -> Unit,
    modifier: Modifier,
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val currentOnDecoded by rememberUpdatedState(onDecoded)

    val delivered = remember { AtomicBoolean(false) }

    val previewView = remember {
        PreviewView(context).apply {
            scaleType = PreviewView.ScaleType.FILL_CENTER
            // COMPATIBLE 模式走 TextureView，兼容性好于 SurfaceView 的层级裁剪行为
            implementationMode = PreviewView.ImplementationMode.COMPATIBLE
        }
    }

    DisposableEffect(lifecycleOwner) {
        val mainExecutor = ContextCompat.getMainExecutor(context)
        val analysisExecutor = Executors.newSingleThreadExecutor()
        var boundProvider: ProcessCameraProvider? = null

        val future = ProcessCameraProvider.getInstance(context)
        future.addListener({
            runCatching {
                val cameraProvider = future.get()
                boundProvider = cameraProvider

                val preview = Preview.Builder().build().also {
                    it.surfaceProvider = previewView.surfaceProvider
                }

                val analysis = ImageAnalysis.Builder()
                    // 只要最新帧：排队等旧帧会让「对准二维码」的反馈明显延迟
                    .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                    .build()
                    .also {
                        it.setAnalyzer(
                            analysisExecutor,
                            ZxingQrAnalyzer(delivered, currentOnDecoded),
                        )
                    }

                cameraProvider.unbindAll()
                cameraProvider.bindToLifecycle(
                    lifecycleOwner,
                    CameraSelector.DEFAULT_BACK_CAMERA,
                    preview,
                    analysis,
                )
            }
        }, mainExecutor)

        onDispose {
            runCatching { boundProvider?.unbindAll() }
            analysisExecutor.shutdown()
        }
    }

    Box(modifier = modifier, contentAlignment = Alignment.Center) {
        AndroidView(
            factory = { previewView },
            modifier = Modifier.fillMaxSize(),
        )

        Box(
            modifier = Modifier.fillMaxSize(),
            contentAlignment = Alignment.BottomCenter,
        ) {
            Text(
                text = "把电脑屏幕上显示的二维码放进取景框",
                style = MiuixTheme.textStyles.body2,
                // 相机预览不是主题表面，这里的对比度只能自己保证
                color = Color.White,
                modifier = Modifier.padding(bottom = 32.dp),
            )
        }
    }
}

/** 单帧 zxing 解码器。 */
private class ZxingQrAnalyzer(
    private val delivered: AtomicBoolean,
    private val onDecoded: (String) -> Unit,
) : ImageAnalysis.Analyzer {

    private val reader = QRCodeReader()
    private val hints = mapOf(
        DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
        DecodeHintType.TRY_HARDER to true,
    )

    override fun analyze(image: ImageProxy) {
        try {
            if (delivered.get()) return

            val plane = image.planes.firstOrNull() ?: return
            val buffer = plane.buffer
            val data = ByteArray(buffer.remaining())
            buffer.get(data)

            // ImageAnalysis 默认输出 YUV_420_888，第一平面就是亮度平面，
            // 直接喂给 zxing，省掉一次 YUV→RGB 转换
            val source = PlanarYUVLuminanceSource(
                data,
                image.width,
                image.height,
                0,
                0,
                image.width,
                image.height,
                false,
            )

            val result = runCatching {
                reader.decode(BinaryBitmap(HybridBinarizer(source)), hints)
            }.getOrNull() ?: return

            if (delivered.compareAndSet(false, true)) {
                val text = result.text
                android.os.Handler(android.os.Looper.getMainLooper()).post { onDecoded(text) }
            }
        } catch (_: Throwable) {
            // 单帧解码失败是常态（对焦中、角度偏、反光），静默跳过
        } finally {
            image.close()
        }
    }
}
