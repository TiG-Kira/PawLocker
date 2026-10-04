package com.kira.pawlocker.ui.platform

import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.ImageBitmap

/**
 * 本机生物识别闸门。
 *
 * Android 端用 `BiometricPrompt`（指纹 / 人脸 / 设备 PIN）；
 * Windows 端不需要 —— 电脑侧的「用户在场」由配对确认框与解锁动作本身承担，
 * 所以桌面实现是「直接通过」。
 *
 * ## 为什么把生物识别放在客户端而不是服务端
 *
 * 服务端（Windows）只认密码学凭据。手机是不是「机主本人在操作」，
 * 只有手机上能判断。所以这里的分工是：
 * 手机本地做生物识别 → 通过后才用身份密钥签名 → Windows 验签。
 * 攻击者拿到手机但过不了生物识别，就签不出有效指令。
 */
interface BiometricGate {

    val isAvailable: Boolean

    /** 展示给用户看的说明，例如「指纹 / 面容 / 设备 PIN」。 */
    val description: String

    suspend fun authenticate(title: String, subtitle: String): BiometricResult
}

sealed interface BiometricResult {

    data object Success : BiometricResult

    data object Cancelled : BiometricResult

    data class Failed(val message: String) : BiometricResult

    data class Unavailable(val message: String) : BiometricResult
}

@Composable
expect fun rememberBiometricGate(): BiometricGate

/**
 * 相机取景 + 二维码识别。
 *
 * Android 端用 CameraX + zxing 解码；Windows 端没有摄像头取景需求
 * （电脑是**展示**二维码的一方），所以实现是一个说明性占位。
 *
 * [onDecoded] 回调里拿到的是二维码的原始文本（即 `pawlocker://pair?d=...`）。
 * 同一个码只会回调一次 —— 由调用方自己保证去重。
 */
@Composable
expect fun QrScanView(
    onDecoded: (String) -> Unit,
    modifier: Modifier,
)

/**
 * 二维码渲染。Windows 端生成，Android 端只需要展示（配对页的预览）。
 *
 * @return 编码失败（内容过长等）返回 null
 */
expect fun renderQrCode(content: String, sizePx: Int): ImageBitmap?

/** 平台信息，用于设置页展示与排障。 */
expect object PlatformInfo {
    val displayName: String
    val version: String
    val deviceModel: String
    /** 例如 "Android 14 (API 34)" / "Windows 11 22631" */
    val systemDescription: String
}
