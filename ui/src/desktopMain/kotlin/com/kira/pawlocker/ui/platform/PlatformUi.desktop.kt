package com.kira.pawlocker.ui.platform

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.toComposeImageBitmap
import org.jetbrains.skia.ColorAlphaType
import org.jetbrains.skia.ColorType
import org.jetbrains.skia.Image
import org.jetbrains.skia.ImageInfo

/**
 * Windows 侧的生物识别闸门 —— 直接通过。
 *
 * 这不是偷懒：PawLocker 的信任模型是「手机持有者必须过生物识别」。
 * 电脑这一侧需要证明的是「用户已登录且在场」，那由 Windows 会话本身保证 ——
 * 没登录的人压根进不了管理页，也就开不了配对窗口。
 */
private object AutoApproveGate : BiometricGate {
    override val isAvailable: Boolean = true
    override val description: String = "无需验证（Windows 侧由登录会话本身保证）"

    override suspend fun authenticate(title: String, subtitle: String): BiometricResult =
        BiometricResult.Success
}

@Composable
actual fun rememberBiometricGate(): BiometricGate = remember { AutoApproveGate }

/**
 * 用 zxing 生成二维码，转成 Compose 可绘制的 [ImageBitmap]。
 *
 * 生成的是 32 位 BGRA 位图。纯黑白两色，所以不做抗锯齿 ——
 * 二维码的抗锯齿反而会让解码器在低对比度屏幕上读不出来。
 */
actual fun renderQrCode(content: String, sizePx: Int): ImageBitmap? = runCatching {
    val matrix = com.google.zxing.MultiFormatWriter().encode(
        content,
        com.google.zxing.BarcodeFormat.QR_CODE,
        sizePx,
        sizePx,
        mapOf(com.google.zxing.EncodeHintType.MARGIN to 1),
    )

    // BGRA_8888：Skia 在小端机器上的原生顺序，省一次通道重排
    val bytes = ByteArray(sizePx * sizePx * 4)
    for (y in 0 until sizePx) {
        for (x in 0 until sizePx) {
            val offset = (y * sizePx + x) * 4
            val value: Byte = if (matrix[x, y]) 0x00 else 0xFF.toByte()
            bytes[offset] = value     // B
            bytes[offset + 1] = value // G
            bytes[offset + 2] = value // R
            bytes[offset + 3] = 0xFF.toByte() // A
        }
    }

    val imageInfo = ImageInfo(sizePx, sizePx, ColorType.BGRA_8888, ColorAlphaType.OPAQUE)
    Image.makeRaster(imageInfo, bytes, sizePx * 4).toComposeImageBitmap()
}.getOrNull()

actual object PlatformInfo {

    actual val displayName: String = "Windows"

    actual val version: String = "0.1.0"

    actual val deviceModel: String =
        (System.getenv("COMPUTERNAME") ?: "Windows PC").trim()

    actual val systemDescription: String =
        "${System.getProperty("os.name")} ${System.getProperty("os.version")} / JVM ${System.getProperty("java.version")}"
}
