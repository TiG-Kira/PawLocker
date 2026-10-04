package com.kira.pawlocker.core.platform

import kotlinx.serialization.Serializable

/**
 * 「本机当前交互式登录的账户」的身份。
 *
 * ## 为什么需要它
 *
 * PawLocker 的信任模型是**三元绑定**：
 *
 * ```
 *   [电脑设备] ── [Windows 账户] ── [手机设备]
 * ```
 *
 * 任何一个环节对不上都不允许解锁。缺了中间那一环，就会出现这种情况：
 * 家里的电脑有两个 Windows 账户（比如「Kira」和「孩子」），
 * 给「Kira」配对的手机会把「孩子」的账户也解开 —— 因为信任记录只绑了设备，没绑账户。
 *
 * 所以账户身份必须进入两个地方：
 *  1. **密钥派生**（[com.kira.pawlocker.core.crypto.PairSecret.derive]）——
 *     让「为账户 A 配对的密钥」在密码学上无法解开账户 B 的指令
 *  2. **解锁指令的 AAD 与签名** —— 使「目标是哪个账户」成为不可篡改的显式声明
 *
 * ## 为什么用 [bindingKey] 而不是直接用 [sid]
 *
 * SID 是权威标识（`S-1-5-21-<机器>-<RID>`，换账户名也不会变），
 * 但极小概率下取不到（无 `whoami`、受限环境）。这时退化为账户名，
 * 并加 `name:` 前缀 —— 前缀保证两种形态**永远不会意外相等**，
 * 避免「取不到 SID 的环境」和「SID 恰好等于某个账户名」的碰撞。
 */
@Serializable
data class UserIdentity(
    /** Windows 账户 SID，形如 `S-1-5-21-...-1001`。非 Windows 平台为空串。 */
    val sid: String = "",

    /** 账户名（SAM 名 / 本地别名），不含域前缀。 */
    val accountName: String = "",

    /** 展示用名称。 */
    val displayName: String = "",
) {

    /** 是否拿到了权威标识。 */
    val isResolved: Boolean get() = sid.isNotBlank()

    /**
     * 绑定链上用于比较与派生的稳定键。
     * 参与的三个东西（统一账户名的 SID、配对码、设备公钥）都由它串起来。
     */
    val bindingKey: String
        get() = if (isResolved) sid else "name:$accountName"

    /** 界面上「Kira（S-1-5-21-…-1001）」这类展示串。 */
    val description: String
        get() = when {
            displayName.isNotBlank() && isResolved -> "$displayName（$sid）"
            displayName.isNotBlank() -> displayName
            isResolved -> sid
            accountName.isNotBlank() -> accountName
            else -> "未识别的账户"
        }

    companion object {
        /** 平台不支持 / 取不到身份时的占位。绑定链会因此拒绝解锁，而不是静默放行。 */
        val Unknown = UserIdentity()
    }
}

/**
 * 本机当前账户身份。Windows 侧由 `whoami` 解析 SID；
 * Android 侧没有 Windows 账户概念，返回 [UserIdentity.Unknown]。
 */
expect fun currentUserIdentity(): UserIdentity

/** 跨平台一致的 SID 文本格式：`S-1-5-21-…`。 */
private val SID_PATTERN = Regex("""S-1-5-\d+(?:-\d+)+""")

/**
 * 从任意文本里抽出第一个 SID。
 *
 * 之所以只在公共代码里保留这一步解析、把「怎么拿到那段文本」留给各平台：
 * `whoami /user /fo csv /nh` 的输出形如 `"HOST\kira","S-1-5-21-…-1001"`，
 * 不同语言版本的外壳措辞可能不同，但 **SID 文本本身与语言无关** ——
 * 只抓这个比解析整行格式稳得多。解析逻辑可测，取数逻辑不值一测。
 */
fun extractSidFrom(text: String): String = SID_PATTERN.find(text)?.value.orEmpty()
