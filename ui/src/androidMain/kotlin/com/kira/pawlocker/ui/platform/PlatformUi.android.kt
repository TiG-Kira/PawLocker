package com.kira.pawlocker.ui.platform

import android.content.Context
import android.os.Build
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume

/**
 * Android 生物识别实现。
 *
 * 允许的组合是 `BIOMETRIC_STRONG or DEVICE_CREDENTIAL`：
 *  - 指纹 / 3D 人脸走 BIOMETRIC_STRONG（Class 3，可解锁密钥库）
 *  - 只有 2D 人脸或没有生物硬件的设备，退回设备 PIN / 图案 / 密码
 *
 * 不把 DEVICE_CREDENTIAL 当成「降级到不安全」—— 它的安全级别依然远高于
 * 「App 内输一个 4 位口令」，而且这是系统级认证，PawLocker 拿不到原始凭据。
 */
private class AndroidBiometricGate(private val context: Context) : BiometricGate {

    private val allowedAuthenticators =
        BiometricManager.Authenticators.BIOMETRIC_STRONG or
            BiometricManager.Authenticators.DEVICE_CREDENTIAL

    private val availability: Int = BiometricManager.from(context)
        .canAuthenticate(allowedAuthenticators)

    override val isAvailable: Boolean =
        availability == BiometricManager.BIOMETRIC_SUCCESS

    override val description: String = when (availability) {
        BiometricManager.BIOMETRIC_SUCCESS -> "指纹 / 面容 / 设备 PIN"
        BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> "本机没有可用的生物识别硬件"
        BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> "生物识别硬件暂时不可用"
        BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> "尚未录入指纹或设备 PIN"
        else -> "生物识别不可用"
    }

    override suspend fun authenticate(title: String, subtitle: String): BiometricResult {
        val activity = context as? FragmentActivity
            ?: return BiometricResult.Unavailable(
                "宿主 Activity 必须是 FragmentActivity（BiometricPrompt 的硬性要求）",
            )

        if (!isAvailable) return BiometricResult.Unavailable(description)

        return suspendCancellableCoroutine { continuation ->
            val executor = ContextCompat.getMainExecutor(context)
            val prompt = BiometricPrompt(
                activity,
                executor,
                object : BiometricPrompt.AuthenticationCallback() {

                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        if (continuation.isActive) continuation.resume(BiometricResult.Success)
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        if (!continuation.isActive) return
                        val result = when (errorCode) {
                            BiometricPrompt.ERROR_USER_CANCELED,
                            BiometricPrompt.ERROR_NEGATIVE_BUTTON,
                            BiometricPrompt.ERROR_CANCELED,
                            -> BiometricResult.Cancelled

                            BiometricPrompt.ERROR_LOCKOUT -> BiometricResult.Failed(
                                "尝试次数过多，系统已临时锁定。请稍后重试，或用设备 PIN 解锁",
                            )

                            BiometricPrompt.ERROR_LOCKOUT_PERMANENT -> BiometricResult.Failed(
                                "生物识别已被系统永久锁定，请先用设备 PIN 解锁一次",
                            )

                            else -> BiometricResult.Failed(errString.toString())
                        }
                        continuation.resume(result)
                    }

                    @Deprecated("BiometricPrompt 已不再回调该方法", ReplaceWith(""))
                    override fun onAuthenticationFailed() = Unit
                },
            )

            val info = BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .setSubtitle(subtitle)
                // 允许 DEVICE_CREDENTIAL 时不能设置 negativeButtonText，否则会抛异常
                .setAllowedAuthenticators(allowedAuthenticators)
                .setConfirmationRequired(true)
                .build()

            continuation.invokeOnCancellation { prompt.cancelAuthentication() }
            prompt.authenticate(info)
        }
    }
}

@Composable
actual fun rememberBiometricGate(): BiometricGate {
    val context = LocalContext.current
    return remember(context) { AndroidBiometricGate(context) }
}

actual fun renderQrCode(content: String, sizePx: Int): ImageBitmap? = runCatching {
    val matrix = com.google.zxing.MultiFormatWriter().encode(
        content,
        com.google.zxing.BarcodeFormat.QR_CODE,
        sizePx,
        sizePx,
        mapOf(com.google.zxing.EncodeHintType.MARGIN to 1),
    )
    val pixels = IntArray(sizePx * sizePx) { index ->
        val x = index % sizePx
        val y = index / sizePx
        if (matrix[x, y]) 0xFF000000.toInt() else 0xFFFFFFFF.toInt()
    }
    android.graphics.Bitmap
        .createBitmap(pixels, sizePx, sizePx, android.graphics.Bitmap.Config.ARGB_8888)
        .asImageBitmap()
}.getOrNull()

actual object PlatformInfo {

    actual val displayName: String = "Android"

    /** 与 androidApp 模块的 versionName 保持一致。 */
    actual val version: String = "0.1.0"

    actual val deviceModel: String = "${Build.MANUFACTURER} ${Build.MODEL}".trim()

    actual val systemDescription: String =
        "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})"
}
