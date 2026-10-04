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

    /**
     * 已注册 DLL 的 Authenticode 签名状况。
     *
     * 为什么体检要管签名：[credentialProviderRegistered] 只说明「注册表里写了」，
     * 而 LogonUI 真正加载 DLL 时还会校验它的签名。证书没被本机信任时，
     * 加载会在锁屏上**静默失败** —— 桌面这边看不出任何异常，
     * 唯一症状是「手机点了解锁但电脑没反应」。所以必须在开始之前就查出来。
     */
    val credentialProviderSignature: DllSignature = DllSignature(),

    /** 开机启动项是否已写入（HKCU\...\Run）。 */
    val autoStartRegistered: Boolean = false,

    /**
     * 入站到 [port] 的流量当前是否真的被防火墙放行。
     *
     * 注意问的是「**放行状态**」，而不是「本程序创建的那条规则在不在」。
     * 这个区别解决了一个真实的误报：
     *
     * Windows 在应用第一次监听端口时会弹出「允许应用通过防火墙」，
     * 用户点「允许」后生成的是一条**按程序路径**的规则，显示名取自 MSI 的产品描述
     * （这里是「PawLocker —— 手机远程解锁 Windows」），且 `LocalPort=Any`。
     * 它和本程序自己创建的 `PawLocker (TCP $port)` 名字完全不同。
     *
     * 早先按名字精确匹配，于是体检**每次都报「防火墙未配置」**——
     * 而端口其实早就通了。用户被反复引向一个会重复建规则、
     * 还要过一次 UAC 的按钮，点了也「不生效」（因为检测逻辑本来就在看错的地方）。
     */
    val firewallRulePresent: Boolean = false,

    /**
     * 命中的这条规则是不是**本程序自己创建的**。
     *
     * 用途只有一个：决定界面要不要给「移除」按钮。
     * 因为 [WindowsRegistrar.removeFirewallRule] 是按名字删的，
     * 只能删掉自己建的那条；命中的若是 Windows 在首次监听时自动生成的按应用规则，
     * 按钮点下去会静默失败（删的规则不存在），而界面上「已就绪」依然亮着 ——
     * 用户会以为按钮坏了。与其给一个点了没反应的按钮，不如不给。
     */
    val firewallRuleOwned: Boolean = false,

    /** 命中的规则名，用于展示「是哪条规则在放行」。 */
    val firewallRuleName: String = "",

    /** 命中规则的配置文件（如 `Private, Public`）。未探到为空串。 */
    val firewallRuleProfiles: String = "",

    /**
     * 命中规则的本地端口范围。
     *
     * `Any` 是个值得让用户看见的值：它表示**该程序的所有端口**都被放行，
     * 而不是只开了监听用的那一个。排查「为什么这个端口能通」时，
     * 这条信息比规则本身更有解释力。
     */
    val firewallRuleLocalPorts: String = "",

    /**
     * 防火墙探测本身有没有跑成功。
     *
     * 与 [firewallRulePresent] 分开：后者说「放没放行」，这个说「我们有没有看出来」。
     * 探测失败时不能把 `false` 当成「没放行」——那会催用户去重复配置一个
     * 其实已经好的东西。遵循与签名探测相同的原则：宁可显示「无法确认」。
     */
    val firewallProbed: Boolean = false,

    /** 防火墙探测失败的原因，用于界面展示与排障。 */
    val firewallProbeError: String? = null,
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
                    title = if (firewallProbed) "放行监听端口" else "确认监听端口已放行",
                    detail = if (firewallProbed) {
                        "没有找到允许手机通过 TCP $port 连入本机的规则"
                    } else {
                        // 探测失败时把话说清楚：不能让用户以为「没找到 = 没配」。
                        // 这一步点下去要过一次 UAC，值得让他先知道我们其实没看出来。
                        "无法确认本机防火墙是否已放行 TCP $port" +
                            (firewallProbeError?.let { "（$it）" } ?: "") +
                            "；可以直接点下面的按钮补一条规则，或先忽略"
                    },
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
                } else {
                    // DLL 在位之后还有一道门槛：它得签名，而且签名证书得被本机信任。
                    // Windows 本身不强制凭据提供程序签名，但 WDAC / Smart App Control /
                    // 大多数 EDR 会拒绝加载未签名或证书不受信任的组件 ——
                    // 而拒绝发生在 LogonUI 内部，桌面上看不到任何提示。
                    when (credentialProviderSignature.status) {
                        DllSignatureStatus.NotSigned -> add(
                            PendingStep(
                                key = PendingStep.KEY_SIGN_DLL,
                                title = "给 DLL 做代码签名",
                                detail = "当前 DLL 没有 Authenticode 签名；这一步在仓库里用 sign.bat 完成",
                            ),
                        )

                        DllSignatureStatus.Untrusted -> add(
                            PendingStep(
                                key = PendingStep.KEY_TRUST_SIGNER,
                                title = "信任签名证书",
                                detail = "把下面这张证书装进本机受信任存储；需要管理员权限",
                            ),
                        )

                        // Trusted / Broken / Unprobed / ProbeFailed 都不在这里加待办：
                        // Broken 是「签名被改坏」，重签一遍即可，靠界面上的说明引导；
                        // 探测失败时更要谨慎 —— 不能因为「没看出来」就催用户去信任点什么
                        else -> Unit
                    }
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
 * 一个 DLL 的 Authenticode 签名状况。
 *
 * [status] 直接对应 Windows 自己的说法（`Get-AuthenticodeSignature` 的 `Status`），
 * 但收敛成几个「用户需要做什么」不同的桶 —— 原始的七八种取值里，
 * 好几种对用户而言是同一件事（比如各种 `UnknownError`），
 * 而界面上要区分的是「没签名 / 签名了但证书不信任 / 签名有效」这三态。
 */
data class DllSignature(
    val status: DllSignatureStatus = DllSignatureStatus.Unprobed,

    /** 签名证书的主体，例如 `CN=PawLocker Development, O=PawLocker`。 */
    val signerSubject: String? = null,

    /**
     * 签名证书的 SHA-1 指纹。
     *
     * 用户要拿它去 `certmgr.msc` 里核对，或者在撤销信任时定位到具体哪一张 ——
     * 显示主体名不够，同主体可以有多张证书。
     */
    val signerThumbprint: String? = null,

    /** 签名证书的到期时间（ISO-8601）。自签名开发证书过期后签名会自动失效。 */
    val signerNotAfter: String? = null,

    /**
     * Windows 自己给出的原始状态字符串（`Valid` / `NotSigned` / `UnknownError` …）。
     *
     * 保留原文是因为**不能靠它下判断**：实测 Windows PowerShell 5.1 在
     * 「签名没问题但证书不受信任」时返回的是 `UnknownError` 而不是 `NotTrusted`，
     * 所以「信任与否」只能靠 [signerTrustedOnMachine] 自己查证书存储得出结论。
     * 但把它原样显示出来，排障时很有价值 —— 用户搜索这个字符串能直接搜到官方文档。
     */
    val rawStatus: String? = null,

    /**
     * 系统的解释文本，例如
     * 「已处理证书链，但是在不受信任提供程序信任的根证书中终止」。
     *
     * 只用于展示，**绝不参与判断**：这句话是本地化的，在英文系统上完全是另一串文字，
     * 拿它做关键字匹配会在非中文环境上悄悄失效。
     */
    val statusMessage: String? = null,

    /** 这张证书是否已经在本机（`LocalMachine`）的受信任根或受信任发布者存储里。 */
    val signerTrustedOnMachine: Boolean = false,

    /**
     * 探测本身有没有跑成功。
     *
     * 与 [status] 分开：`status` 说的是「DLL 怎么样」，
     * 而这个说的是「我们有没有成功看出来」。探测失败时把
     * [status] 当成 `NotSigned` 会是危险的误报 —— 界面会劝用户去签名，
     * 而问题其实出在别处。所以宁可显示「无法确认」。
     */
    val probed: Boolean = false,

    /** 探测失败的原因，用于界面展示与排障。 */
    val probeError: String? = null,
) {
    /** 是否已经签过名（不论证书信不信任）。 */
    val isSigned: Boolean get() = status == DllSignatureStatus.Trusted ||
        status == DllSignatureStatus.Untrusted

    /** 签名有效，且证书链在本机受信任 —— 这才是「可以进锁屏」的状态。 */
    val isReady: Boolean get() = status == DllSignatureStatus.Trusted

    companion object {
        val Unprobed = DllSignature()
    }
}

/** [DllSignature.status] 的取值。刻意只有「用户要做的动作不同」的几档。 */
enum class DllSignatureStatus {
    /** 还没探测，或当前平台不支持探测。 */
    Unprobed,

    /** 探测过程本身失败了（文件读不到、PowerShell 起不来等）。 */
    ProbeFailed,

    /** DLL 没有 Authenticode 签名。 */
    NotSigned,

    /** 有签名，但签名证书不在本机受信任存储里。 */
    Untrusted,

    /** 有签名，证书受信任，且文件未被改动。 */
    Trusted,

    /** 有签名但校验不过：文件签名后被改过，或证书已过期。 */
    Broken,
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

        /** 给 DLL 做 Authenticode 签名（在仓库里用 `sign.bat`）。 */
        const val KEY_SIGN_DLL = "sign_dll"

        /** 把 DLL 的签名证书装进本机受信任存储。 */
        const val KEY_TRUST_SIGNER = "trust_signer"

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

    /**
     * 把 [thumbprint] 指定的证书装进本机受信任存储
     * （`LocalMachine\Root` + `LocalMachine\TrustedPublisher`）。
     *
     * 为什么传指纹而不是让实现自己去读 DLL：用户看到并确认的是**某一张特定证书**，
     * 写进去的就必须是那一张。实现会重新读一次 DLL 当前签名的证书指纹，
     * 与 [thumbprint] 不符时直接拒绝 —— 否则在「探测」到「用户点确认」这段
     * 时间窗里换掉 DLL，就能让用户为一张他没见过的证书签字。
     *
     * 必须用 `LocalMachine` 而不是 `CurrentUser`：DLL 由 LogonUI 加载，
     * 而 LogonUI 跑在 SYSTEM 上下文，看不到当前用户的证书存储。
     * 只信任给当前用户，在锁屏上依然会失败 —— 而且失败得毫无提示。
     */
    fun trustDllSignerCertificate(thumbprint: String): RegistrationResult

    /** 反向操作：把该证书从两个 `LocalMachine` 存储里移除。 */
    fun revokeDllSignerCertificate(thumbprint: String): RegistrationResult

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

    override fun trustDllSignerCertificate(thumbprint: String): RegistrationResult = unsupported()

    override fun revokeDllSignerCertificate(thumbprint: String): RegistrationResult = unsupported()

    override fun ensureFirewallRule(port: Int): RegistrationResult = unsupported()

    override fun removeFirewallRule(port: Int): RegistrationResult = unsupported()

    override fun setAutoStart(enabled: Boolean): RegistrationResult = unsupported()

    override fun suggestedCredentialProviderPath(): String = ""

    private fun unsupported() = RegistrationResult.Failed("当前平台不支持 Windows 注册项管理")
}
