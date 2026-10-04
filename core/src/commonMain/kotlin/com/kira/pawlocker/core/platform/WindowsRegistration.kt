package com.kira.pawlocker.core.platform

import com.kira.pawlocker.core.config.WindowsUnlockStrategy

/**
 * 「本机的解锁方式有没有向 Windows 注册好」的体检结果。
 *
 * 这一组检查存在的意义：**解锁动作能不能生效，取决于一堆 Windows 侧的注册状态**，
 * 而这些状态在应用界面里平时是看不到的。用户遇到「手机点了解锁但电脑没反应」时，
 * 十有八九是这里某一项没配 —— 与其让他去猜，不如直接把体检结果摆出来。
 */
data class RegistrationState(
    /** 当前可执行文件路径，用于注册开机启动项。 */
    val executablePath: String? = null,

    /** `PawLockerProvider.dll` 是否已注册为凭据提供程序。 */
    val credentialProviderRegistered: Boolean = false,
    /** 已注册的 DLL 路径；注册了但文件不存在说明装到了别处或被删了。 */
    val credentialProviderDllPath: String? = null,
    /** 已注册的 DLL 文件当前是否真实存在。 */
    val credentialProviderDllPresent: Boolean = false,

    /** 开机启动项是否已写入（HKCU\...\Run）。 */
    val autoStartRegistered: Boolean = false,

    /** 放行监听端口的入站防火墙规则是否存在。 */
    val firewallRulePresent: Boolean = false,
    val firewallRuleName: String = "",
    /** 体检所用的端口号，展示待办文案时要用。 */
    val port: Int = 0,

    /** 本机是否具备执行注册所需的管理员权限（仅作展示，实际操作会自行提权）。 */
    val elevationHint: String = "",
) {

    /**
     * 当前策略下「还差哪几步才算注册好」。
     *
     * 返回的是**可读的待办项**而不是布尔值：首次启动的注册向导要靠它逐条打勾，
     * 只给一个 `false` 用户根本不知道该点哪里。
     */
    fun pendingSteps(strategy: WindowsUnlockStrategy): List<PendingStep> = buildList {
        // 第一条就是「放行端口」：无论用哪种策略，手机连不进来都是白搭
        if (!firewallRulePresent) {
            add(
                PendingStep(
                    key = PendingStep.KEY_FIREWALL,
                    title = "放行监听端口",
                    detail = "允许手机通过 TCP $port 连入本机",
                ),
            )
        }

        when (strategy) {
            WindowsUnlockStrategy.CREDENTIAL_PROVIDER -> {
                if (!credentialProviderRegistered) {
                    add(
                        PendingStep(
                            key = PendingStep.KEY_CREDENTIAL_PROVIDER,
                            title = "注册凭据提供程序",
                            detail = "锁屏界面才会出现 PawLocker 磁贴；需要管理员权限",
                        ),
                    )
                } else if (!credentialProviderDllPresent) {
                    add(
                        PendingStep(
                            key = PendingStep.KEY_CREDENTIAL_PROVIDER,
                            title = "凭据提供程序 DLL 缺失",
                            detail = "注册表里有记录，但 ${credentialProviderDllPath ?: "DLL"} 不存在",
                        ),
                    )
                }
            }

            // 其余策略不需要额外的系统级注册
            WindowsUnlockStrategy.WAKE_ONLY,
            WindowsUnlockStrategy.CUSTOM_COMMAND,
            WindowsUnlockStrategy.DRY_RUN,
            -> Unit
        }

        if (!autoStartRegistered) {
            add(
                PendingStep(
                    key = PendingStep.KEY_AUTO_START,
                    title = "设置开机自动运行",
                    detail = "受信任的手机随时都能叫醒电脑，不用先手动开一次程序",
                ),
            )
        }
    }

    /** 是否已经「注册得差不多可以用了」。 */
    fun isUsable(strategy: WindowsUnlockStrategy): Boolean =
        pendingSteps(strategy).none { it.key == PendingStep.KEY_CREDENTIAL_PROVIDER }
}

/**
 * 注册向导里的一条待办。
 *
 * [key] 用常量而非枚举，是为了让 UI 能在不 import 平台包的情况下也能做分支
 * （比如只对 [KEY_CREDENTIAL_PROVIDER] 显示「需要管理员权限」的额外提示）。
 */
data class PendingStep(
    val key: String,
    val title: String,
    val detail: String,
) {
    companion object {
        const val KEY_FIREWALL = "firewall"
        const val KEY_CREDENTIAL_PROVIDER = "credential_provider"
        const val KEY_AUTO_START = "auto_start"
    }
}

/** 一次注册操作的结果。 */
sealed interface RegistrationResult {

    data object Success : RegistrationResult

    /** 用户在 UAC 弹窗上点了「否」，或提权被策略拦下。 */
    data object Cancelled : RegistrationResult

    data class Failed(val message: String) : RegistrationResult

    val isSuccess: Boolean get() = this is Success
}

/**
 * Windows 侧「把解锁方式注册进系统」的能力。
 *
 * 所有写操作都可能触发 UAC 提权。实现里**不缓存提权结果** ——
 * 每次操作都重新申请，因为 Windows 的提权是逐进程的一次性授权，
 * 缓存一个「已提权」的布尔值只会在用户切换策略后给出错误的安全感。
 */
interface WindowsRegistrar {

    /** Android 端为 false。 */
    val isSupported: Boolean

    /** 体检：读注册表与 netsh，不改动任何东西。 */
    fun inspect(port: Int): RegistrationState

    /**
     * 注册 Credential Provider。
     *
     * 只写注册表（`Credential Providers` + `CLSID\InprocServer32`）并**不搬运 DLL** ——
     * 把 DLL 放到哪里是用户的选择，程序不该擅自往 `C:\Windows` 里塞文件。
     */
    fun registerCredentialProvider(dllPath: String): RegistrationResult

    fun unregisterCredentialProvider(): RegistrationResult

    /** 放行 [port] 的 TCP 入站，让手机能连进来。 */
    fun ensureFirewallRule(port: Int): RegistrationResult

    fun removeFirewallRule(port: Int): RegistrationResult

    /** 写/删 `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` 项。不需要提权。 */
    fun setAutoStart(enabled: Boolean): RegistrationResult

    /** 建议的 DLL 位置，用于界面预填。 */
    fun suggestedCredentialProviderPath(): String
}

/** 取当前平台的注册器。Android 端拿到的是 [UnsupportedWindowsRegistrar]。 */
expect fun createWindowsRegistrar(): WindowsRegistrar

/**
 * 不支持注册的平台上的空实现。
 *
 * 放在 commonMain：它没有任何平台依赖，两个平台共享同一份代码。
 * 所有操作都返回明确的失败原因，而不是静默成功 ——
 * 界面上宁可显示「当前平台不支持」，也不要让用户以为已经注册好了。
 */
class UnsupportedWindowsRegistrar : WindowsRegistrar {

    override val isSupported: Boolean = false

    override fun inspect(port: Int): RegistrationState = RegistrationState(
        elevationHint = "当前平台不支持 Windows 注册项管理",
    )

    override fun registerCredentialProvider(dllPath: String): RegistrationResult = unsupported()

    override fun unregisterCredentialProvider(): RegistrationResult = unsupported()

    override fun ensureFirewallRule(port: Int): RegistrationResult = unsupported()

    override fun removeFirewallRule(port: Int): RegistrationResult = unsupported()

    override fun setAutoStart(enabled: Boolean): RegistrationResult = unsupported()

    override fun suggestedCredentialProviderPath(): String = ""

    private fun unsupported() = RegistrationResult.Failed("当前平台不支持 Windows 注册项管理")
}
