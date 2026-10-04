package com.kira.pawlocker.ui.platform

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
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
import top.yukonga.miuix.kmp.basic.Button
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.Card
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
 *
 * ⚠️ 相机权限必须**运行时申请**。清单里声明 `android.permission.CAMERA` 只是
 * 「这台设备允许有这个功能」，API 23 起系统仍然会直接拒绝未申请的访问 ——
 * 表现是 CameraX 抛 SecurityException，预览全黑，且如果异常被吞掉，
 * 用户看到的就是「点了扫码，什么都没发生」。
 */
@Composable
actual fun QrScanView(
    onDecoded: (String) -> Unit,
    modifier: Modifier,
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val currentOnDecoded by rememberUpdatedState(onDecoded)

    var granted by remember { mutableStateOf(context.hasCameraPermission()) }
    var permanentlyDenied by remember { mutableStateOf(false) }
    var cameraError by remember { mutableStateOf<String?>(null) }
    var bindAttempt by remember { mutableStateOf(0) }

    val permissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission(),
    ) { result ->
        granted = result
        // 被拒之后如果系统不再允许弹窗，就只能引导去设置页手动开
        permanentlyDenied = !result && !context.shouldShowCameraRationale()
    }

    // 进入页面时若已有权限（用户之前授过），不打扰；否则立刻发起一次申请
    LaunchedEffect(Unit) {
        if (!granted) permissionLauncher.launch(Manifest.permission.CAMERA)
    }

    if (!granted) {
        CameraPermissionPane(
            permanentlyDenied = permanentlyDenied,
            onRequest = { permissionLauncher.launch(Manifest.permission.CAMERA) },
            onOpenSettings = { context.openAppSettings() },
            modifier = modifier,
        )
        return
    }

    Box(modifier = modifier, contentAlignment = Alignment.Center) {
        if (cameraError == null) {
            CameraPreview(
                context = context,
                lifecycleOwner = lifecycleOwner,
                bindAttempt = bindAttempt,
                onDecoded = currentOnDecoded,
                onFailure = { message -> cameraError = message },
            )
        } else {
            CameraErrorPane(
                message = cameraError.orEmpty(),
                onRetry = {
                    cameraError = null
                    bindAttempt += 1
                },
            )
        }
    }
}

/** 把相机预览与分析的绑定抽出来，`bindAttempt` 变化时重建。 */
@Composable
private fun CameraPreview(
    context: Context,
    lifecycleOwner: androidx.lifecycle.LifecycleOwner,
    bindAttempt: Int,
    onDecoded: (String) -> Unit,
    onFailure: (String) -> Unit,
) {
    val currentOnDecoded by rememberUpdatedState(onDecoded)
    val currentOnFailure by rememberUpdatedState(onFailure)

    val delivered = remember(bindAttempt) { AtomicBoolean(false) }

    val previewView = remember(bindAttempt) {
        PreviewView(context).apply {
            scaleType = PreviewView.ScaleType.FILL_CENTER
            // COMPATIBLE 模式走 TextureView，兼容性好于 SurfaceView 的层级裁剪行为
            implementationMode = PreviewView.ImplementationMode.COMPATIBLE
        }
    }

    DisposableEffect(lifecycleOwner, bindAttempt) {
        val mainExecutor = ContextCompat.getMainExecutor(context)
        val analysisExecutor = Executors.newSingleThreadExecutor()
        var boundProvider: ProcessCameraProvider? = null

        val future = ProcessCameraProvider.getInstance(context)
        future.addListener({
            // 这里不再用 runCatching 静默吞掉：相机绑定失败必须让用户看见原因，
            // 否则表现就是「取景框一片黑，扫了半天没动静」。
            try {
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
            } catch (error: Throwable) {
                currentOnFailure(describeCameraFailure(error))
            }
        }, mainExecutor)

        onDispose {
            runCatching { boundProvider?.unbindAll() }
            analysisExecutor.shutdown()
        }
    }

    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
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

/** 相机权限没拿到时的替代表面 —— 必须给一个能点的下一步，而不是一块黑。 */
@Composable
private fun CameraPermissionPane(
    permanentlyDenied: Boolean,
    onRequest: () -> Unit,
    onOpenSettings: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Card(modifier = modifier.padding(12.dp)) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(20.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                text = "需要相机权限才能扫码",
                style = MiuixTheme.textStyles.title4,
                color = MiuixTheme.colorScheme.onSurface,
                textAlign = TextAlign.Center,
            )
            Text(
                text = if (permanentlyDenied) {
                    "系统已不再询问。请到「系统设置 → 应用 → PawLocker → 权限」里允许使用相机，" +
                        "然后返回本页。"
                } else {
                    "配对二维码里带着电脑地址与公钥，用相机扫一下最省事。" +
                        "不想给相机权限的话，也可以切到「手动输入」。"
                },
                style = MiuixTheme.textStyles.footnote1,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                textAlign = TextAlign.Center,
            )

            Button(
                onClick = if (permanentlyDenied) onOpenSettings else onRequest,
                colors = ButtonDefaults.buttonColorsPrimary(),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(if (permanentlyDenied) "去系统设置" else "授予相机权限")
            }
        }
    }
}

/** 相机绑定失败的提示 —— 与权限失败分开，这里的问题重试往往有效。 */
@Composable
private fun CameraErrorPane(
    message: String,
    onRetry: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth().padding(12.dp)) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(20.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                text = "相机打不开",
                style = MiuixTheme.textStyles.title4,
                color = MiuixTheme.colorScheme.onSurface,
                textAlign = TextAlign.Center,
            )
            Text(
                text = message,
                style = MiuixTheme.textStyles.footnote1,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                textAlign = TextAlign.Center,
            )
            Text(
                text = "也可以切到「手动输入」，用电脑上显示的地址、端口与 6 位配对码完成配对。",
                style = MiuixTheme.textStyles.footnote2,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                textAlign = TextAlign.Center,
            )

            Button(
                onClick = onRetry,
                colors = ButtonDefaults.buttonColorsPrimary(),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("重试")
            }
        }
    }
}

private fun Context.hasCameraPermission(): Boolean =
    ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) ==
        PackageManager.PERMISSION_GRANTED

/**
 * 系统还会不会再弹权限框。
 *
 * 注意判断的是 `CAMERA` 而不是 `shouldShowRequestPermissionRationale` 本身 ——
 * 那个方法只回答「这次该不该解释」，不回答「还能不能再问」。
 */
private fun Context.shouldShowCameraRationale(): Boolean =
    (this as? android.app.Activity)?.shouldShowRequestPermissionRationale(
        Manifest.permission.CAMERA,
    ) ?: true

private fun Context.openAppSettings() {
    runCatching {
        startActivity(
            Intent(
                Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                Uri.fromParts("package", packageName, null),
            ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
        )
    }
}

/** 把相机异常翻译成用户能照做的说法，而不是把 `java.lang.SecurityException` 甩出去。 */
private fun describeCameraFailure(error: Throwable): String = when (error) {
    is SecurityException -> "系统拒绝了相机访问。请到系统设置里确认 PawLocker 的相机权限已开启。"
    is IllegalStateException -> "相机正被其它应用占用。关掉相机类应用后重试。"
    else -> error.message?.takeIf { it.isNotBlank() } ?: "相机初始化失败（${error::class.simpleName}）"
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
