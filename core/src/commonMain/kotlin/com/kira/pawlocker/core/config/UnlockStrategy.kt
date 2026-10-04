package com.kira.pawlocker.core.config

import com.kira.pawlocker.core.platform.PlatformEnv
import kotlinx.serialization.Serializable

/**
 * Windows 解锁执行策略。
 *
 * 放在 `commonMain` 而非 `desktopMain`：它本质是一份**配置**，
 * 设置页（共享 UI 层）需要读写它，而具体执行器才是平台相关的。
 */
@Serializable
enum class WindowsUnlockStrategy(val displayName: String, val description: String) {

    /** 只唤醒显示器 / 关掉屏保，不做登录。适合「人在电脑前，只是屏幕黑了」。 */
    WAKE_ONLY(
        "仅唤醒屏幕",
        "把显示器点亮并退出屏保；已锁屏时不会完成登录",
    ),

    /**
     * 通过 PawLocker Credential Provider 完成真实登录。
     * 需要额外安装 `PawLockerProvider.dll` 并注册到 Winlogon。
     */
    CREDENTIAL_PROVIDER(
        "凭据提供程序",
        "在锁屏界面出现 PawLocker 磁贴；收到解锁信号后用本机保存的凭据完成登录。需要安装配套的 PawLockerProvider.dll",
    ),

    /** 执行用户自定义命令。适合已经自建了解锁方案、或想接第三方工具的场景。 */
    CUSTOM_COMMAND(
        "自定义命令",
        "收到解锁指令时执行指定命令，例如调用第三方解锁工具或脚本",
    ),

    /** 只记录日志，不做任何实际动作。用于首次部署时的链路自测。 */
    DRY_RUN(
        "仅记录日志（自测）",
        "不执行任何动作，只在日志里记录收到了解锁指令。用于验证手机到电脑的链路是否通畅",
    ),
}

/**
 * 本机凭据，用于 [WindowsUnlockStrategy.CREDENTIAL_PROVIDER]：
 * 用户在配置向导里输入一次 Windows 账户密码，由 PawLocker 用 DPAPI 加密保存，
 * 锁屏时由 Credential Provider 提交给 Winlogon。
 *
 * ⚠️ 安全提示：这等价于把密码交给 PawLocker 保管（DPAPI 加密，仅当前用户可解）。
 * 不接受这个前提的话，请选择「仅唤醒屏幕」或「自定义命令」。
 */
@Serializable
data class WindowsCredential(
    val userName: String,
    val domain: String = ".",
    val password: String,
    /** 该账户在系统中的 SID，用于 Credential Provider 精确匹配磁贴。 */
    val userSid: String = "",
)

object WindowsCredentialStore {

    private const val FILE = "windows-credential.json"

    private val json = kotlinx.serialization.json.Json {
        encodeDefaults = true
        ignoreUnknownKeys = false
    }

    fun load(): WindowsCredential? {
        val raw = PlatformEnv.readSecure(FILE) ?: return null
        return runCatching {
            json.decodeFromString(WindowsCredential.serializer(), raw.decodeToString())
        }.getOrNull()
    }

    fun save(credential: WindowsCredential) {
        PlatformEnv.writeSecure(
            FILE,
            json.encodeToString(WindowsCredential.serializer(), credential).encodeToByteArray(),
        )
    }

    fun clear() = PlatformEnv.deleteSecure(FILE)

    fun exists(): Boolean = load() != null
}
