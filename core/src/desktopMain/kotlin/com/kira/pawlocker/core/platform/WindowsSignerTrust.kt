package com.kira.pawlocker.core.platform

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.File

/**
 * 凭据提供程序 DLL 的**代码签名证书信任**。
 *
 * ## 这一步为什么必须存在
 *
 * Windows 并不强制要求凭据提供程序签名 —— 未签名的 DLL 在很多机器上照样能加载。
 * 但下面这些情况会**拒绝**加载它：
 *
 *  - WDAC / AppLocker / Device Guard 策略（任何被集中管理的机器都开着）
 *  - Smart App Control（Windows 11 22H2 起）
 *  - 大多数 EDR 产品
 *
 * 而拒绝发生在 `LogonUI.exe` 内部 —— 桌面侧看不到任何提示。唯一症状是
 * 「手机点了解锁但电脑没反应」。这类问题如果不挡在配置阶段，
 * 用户会去怀疑网络、怀疑配对、怀疑手机，唯独不会怀疑「DLL 根本没被加载」。
 *
 * ## 信任的是哪张证书
 *
 * 不需要用户去找 `.cer` 文件：证书就嵌在 DLL 的 Authenticode 签名里，
 * 从 `Get-AuthenticodeSignature` 的结果直接取出来。少一步「请找到某个文件」的引导，
 * 就少一整类「找错了文件」的支持问题。
 *
 * ## 往哪写
 *
 * `LocalMachine\Root` + `LocalMachine\TrustedPublisher`，**不是** `CurrentUser`：
 * DLL 由 `LogonUI.exe` 加载，它跑在 SYSTEM 上下文，看不到当前用户的证书存储。
 * 只信任给当前用户，在锁屏上依然会失败 —— 而且失败得毫无提示。
 */
internal object SignerTrust {

    /**
     * 本机受信任存储的名字。
     *
     * 两个都要写：
     *  - `TrustedPublisher` 是 Authenticode 发布者信任，签名校验直接查这里；
     *  - `Root` 是根证书存储，自签名证书的链要在这里终结才算通过。
     * 只写一个的话，`Get-AuthenticodeSignature` 仍然会返回「链终止于不受信任的根」。
     */
    private const val MACHINE_STORES = "'Root', 'TrustedPublisher'"

    private val json = Json { ignoreUnknownKeys = true }

    // ——————————————————————————————————————————————————————————
    // 对外
    // ——————————————————————————————————————————————————————————

    /**
     * 读一次 [dllPath] 的签名状况。不弹 UAC。
     *
     * 探测失败时返回 [DllSignatureStatus.ProbeFailed] 而不是猜一个值 ——
     * 把「没看出来」当成「没签名」会引导用户去重签，而重签一遍还是同样结果。
     */
    fun probe(dllPath: String?): DllSignature {
        if (dllPath.isNullOrBlank()) {
            return DllSignature(probeError = "注册表里没有 DLL 路径")
        }
        if (!File(dllPath).isFile) {
            return DllSignature(probeError = "DLL 不存在：$dllPath")
        }

        return try {
            val process = ProcessBuilder(
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                probeScript(dllPath),
            ).redirectErrorStream(true).start()

            val output = process.inputStream.readBytes().toString(Charsets.UTF_8)
            val exitCode = process.waitFor()

            if (exitCode != 0) {
                DllSignature(
                    status = DllSignatureStatus.ProbeFailed,
                    probeError = "签名探测退出码 $exitCode：${output.take(300).trim()}",
                )
            } else {
                interpret(output)
            }
        } catch (error: Throwable) {
            DllSignature(
                status = DllSignatureStatus.ProbeFailed,
                probeError = error.message ?: "无法启动签名探测",
            )
        }
    }

    /**
     * 把 DLL 当前签名证书装进本机受信任存储。
     *
     * 传 [thumbprint] 而不是让实现自己去读，是为了堵住「探测」到「用户点确认」
     * 之间的时间窗：脚本里会重新读一次 DLL 的签名证书并与 [thumbprint] 比对，
     * 对不上就直接失败。否则在这段窗口里换掉 DLL，就能让用户为一张
     * 他从未见过的证书签字。
     *
     * 成败由**重新探测的结果**判定，而不是提权进程的退出码 ——
     * 退出码只说明「脚本跑完了」，不说明「签名真的通过了校验」。
     */
    fun trust(dllPath: String, thumbprint: String): RegistrationResult {
        val expected = normalizeThumbprint(thumbprint)
        if (expected.isEmpty()) {
            return RegistrationResult.Failed("证书指纹为空，无法信任。请先重新体检。")
        }

        val elevated = runElevated(trustScript(dllPath, expected))
        if (elevated !is RegistrationResult.Success) return elevated

        val after = probe(dllPath)
        return if (after.isReady) {
            RegistrationResult.Success
        } else {
            RegistrationResult.Failed(
                buildString {
                    append("证书已写入，但签名仍未通过校验（状态 ")
                    append(after.rawStatus ?: "未知")
                    append("）。")
                    after.statusMessage?.let { append("系统说明：").append(it) }
                },
            )
        }
    }

    /** 反向操作：把该指纹对应的证书从两个 `LocalMachine` 存储里移除。 */
    fun revoke(dllPath: String?, thumbprint: String): RegistrationResult {
        val expected = normalizeThumbprint(thumbprint)
        if (expected.isEmpty()) {
            return RegistrationResult.Failed("证书指纹为空，无法移除。")
        }

        val elevated = runElevated(revokeScript(expected))
        if (elevated !is RegistrationResult.Success) return elevated

        return if (!probe(dllPath).signerTrustedOnMachine) {
            RegistrationResult.Success
        } else {
            RegistrationResult.Failed(
                "证书仍然在本机受信任存储里。可能是被组策略接管的存储，手动移除也会被系统加回来。",
            )
        }
    }

    // ——————————————————————————————————————————————————————————
    // 结果解读
    // ——————————————————————————————————————————————————————————

    /**
     * 把探测脚本的 JSON 输出翻译成 [DllSignature]。
     *
     * ## 为什么不能直接采信 PowerShell 给的 Status
     *
     * 实测（Windows PowerShell 5.1）：一个签名本身没问题、但**证书不受信任**的 DLL，
     * `Get-AuthenticodeSignature` 返回的 `Status` 是 `UnknownError`，
     * 而不是文档里那个看起来正合适的 `NotTrusted`。照字面映射会把「缺信任」
     * 误判成「签名坏了」，然后引导用户去重签 —— 而重签一遍还是 `UnknownError`，
     * 用户会陷进一个永远出不来的循环。
     *
     * 所以判断分两步：
     *  1. `Valid` 与 `NotSigned` 这两个取值是确定无疑的，直接采信；
     *  2. 其余情况一律**自己查证书存储**：签名证书已经在本机受信任存储里
     *     → 问题不是信任，归为 [DllSignatureStatus.Broken]；不在
     *     → 归为 [DllSignatureStatus.Untrusted]，这正是「点一下信任就能好」的那一档。
     */
    internal fun interpret(output: String): DllSignature {
        // 取最后一行以 `{` 开头的内容：脚本里万一有别的输出（警告、提示），
        // JSON 一定是最后那个完整对象
        val jsonText = output
            .removePrefix("\uFEFF")
            .lines()
            .map { it.trim() }
            .lastOrNull { it.startsWith("{") && it.endsWith("}") }
            ?: return DllSignature(
                status = DllSignatureStatus.ProbeFailed,
                probeError = "探测没有返回可解析的结果：${output.take(300)}",
            )

        val report = try {
            json.decodeFromString<SignatureProbeReport>(jsonText)
        } catch (error: Throwable) {
            return DllSignature(
                status = DllSignatureStatus.ProbeFailed,
                probeError = "无法解析探测结果：${error.message}",
            )
        }

        val base = DllSignature(
            signerSubject = report.subject,
            signerThumbprint = report.thumbprint,
            signerNotAfter = report.notAfter,
            signerTrustedOnMachine = report.trusted,
            rawStatus = report.status,
            statusMessage = report.statusMessage,
            probed = report.probed,
        )

        if (!report.probed) {
            return base.copy(
                status = DllSignatureStatus.ProbeFailed,
                probeError = report.error ?: "探测未成功",
            )
        }

        val status = when (report.status) {
            "NotSigned" -> DllSignatureStatus.NotSigned
            "Valid" -> DllSignatureStatus.Trusted
            else -> if (report.trusted) DllSignatureStatus.Broken else DllSignatureStatus.Untrusted
        }
        return base.copy(status = status)
    }

    // ——————————————————————————————————————————————————————————
    // 提权执行
    // ——————————————————————————————————————————————————————————

    /**
     * 以管理员身份跑一段 PowerShell 脚本，返回退出码映射后的结果。
     *
     * 脚本正文**直接内联进命令行**，不落地成文件。这一点是刻意的：
     * 把待提权执行的脚本写进 `%LOCALAPPDATA%` 这类当前用户可写的位置，
     * 等于给出一个本地提权窗口 —— 任何以普通权限运行的进程都能在
     * 「写完」和「提权读」之间把文件换掉。命令行的内容在
     * `CreateProcess` 那一刻就固定了，且 Windows 的完整性级别
     * 阻止中完整性进程写入高完整性进程的内存，比落盘安全得多。
     *
     * （本文件之外，凭据提供程序的注册仍走 `reg.exe` + 落盘 `.reg` 的老路，
     *   那里有同样的隐患，属于已知待收敛项。）
     */
    private fun runElevated(script: String): RegistrationResult {
        val argumentList = listOf(
            "'-NoProfile'",
            "'-NonInteractive'",
            "'-Command'",
            psQuote(script),
        ).joinToString(",")

        val wrapper = buildString {
            append("try { ")
            append("\$p = Start-Process -FilePath 'powershell.exe' -ArgumentList @(")
            append(argumentList)
            append(") -Verb RunAs -Wait -PassThru; ")
            append("exit \$p.ExitCode ")
            append("} catch { Write-Output \$_.Exception.Message; exit 1 }")
        }

        return try {
            val process = ProcessBuilder(
                "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", wrapper,
            ).redirectErrorStream(true).start()

            val output = process.inputStream.bufferedReader().readText().trim()
            val exitCode = process.waitFor()

            when {
                exitCode == 0 -> RegistrationResult.Success
                isCancelledByUser(output) -> RegistrationResult.Cancelled
                else -> RegistrationResult.Failed(
                    output.ifBlank { "提权操作失败，退出码 $exitCode（可能需要管理员权限）" },
                )
            }
        } catch (error: Throwable) {
            RegistrationResult.Failed(error.message ?: "无法启动提权进程")
        }
    }

    private fun isCancelledByUser(output: String): Boolean =
        output.contains("canceled", ignoreCase = true) ||
            output.contains("cancelled", ignoreCase = true) ||
            output.contains("取消", ignoreCase = true) ||
            output.contains("拒绝", ignoreCase = true)

    // ——————————————————————————————————————————————————————————
    // 脚本
    // ——————————————————————————————————————————————————————————

    /**
     * 探测脚本。
     *
     * 一次 PowerShell 调用问完所有问题，而不是让 Kotlin 侧分几次问：
     * 每次起 PowerShell 约 1 秒，而且这几项必须基于**同一时刻**的状态 ——
     * 分开查会引入「查完签名、DLL 被换掉、再查信任」的窗口。
     */
    internal fun probeScript(dllPath: String): String = """
        # 输出编码必须先于「把错误策略设成 Stop」那一行设置：某些宿主里这行会失败，
        # 而它失败不该让整个探测中断。JSON 里有中文的 StatusMessage，
        # 不设 UTF-8 就会被按 OEM 码页写出来，Kotlin 侧解出来是乱码。
        [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding ${'$'}false
        ${'$'}ErrorActionPreference = 'Stop'

        ${'$'}dll = ${psQuote(dllPath)}
        ${'$'}report = [ordered]@{
            probed        = ${'$'}false
            status        = 'ProbeFailed'
            statusMessage = ${'$'}null
            subject       = ${'$'}null
            thumbprint    = ${'$'}null
            notAfter      = ${'$'}null
            trusted       = ${'$'}false
            error         = ${'$'}null
        }

        try {
            ${'$'}sig = Get-AuthenticodeSignature -LiteralPath ${'$'}dll
            ${'$'}report.probed        = ${'$'}true
            ${'$'}report.status        = [string]${'$'}sig.Status
            ${'$'}report.statusMessage = [string]${'$'}sig.StatusMessage

            ${'$'}cert = ${'$'}sig.SignerCertificate
            if (${'$'}null -ne ${'$'}cert) {
                ${'$'}report.subject    = ${'$'}cert.Subject
                ${'$'}report.thumbprint = ${'$'}cert.Thumbprint
                ${'$'}report.notAfter   = ${'$'}cert.NotAfter.ToString('yyyy-MM-dd')

                foreach (${'$'}storeName in @($MACHINE_STORES)) {
                    ${'$'}store = New-Object System.Security.Cryptography.X509Certificates.X509Store(${'$'}storeName, 'LocalMachine')
                    try {
                        ${'$'}store.Open('ReadOnly')
                        foreach (${'$'}existing in ${'$'}store.Certificates) {
                            if (${'$'}existing.Thumbprint -eq ${'$'}report.thumbprint) {
                                ${'$'}report.trusted = ${'$'}true
                                break
                            }
                        }
                    } finally {
                        ${'$'}store.Close()
                    }
                    if (${'$'}report.trusted) { break }
                }
            }
        } catch {
            ${'$'}report.probed = ${'$'}false
            ${'$'}report.error  = ${'$'}error.Exception.Message
        }

        ${'$'}report | ConvertTo-Json -Compress
    """.trimIndent()

    /**
     * 写信任。
     *
     * 先删同指纹的旧条目再添加，而不是直接 `Add`：
     * 证书已经存在时 `X509Store.Add` 的行为在各版本上并不一致
     * （可能抛 `CryptographicException`，也可能静默重复添加）。
     * 先删后加在两种行为下都是幂等的，而这个操作经常被重复点。
     */
    internal fun trustScript(dllPath: String, thumbprint: String): String = """
        ${'$'}ErrorActionPreference = 'Stop'
        ${'$'}dll = ${psQuote(dllPath)}
        ${'$'}expected = ${psQuote(thumbprint)}

        ${'$'}sig = Get-AuthenticodeSignature -LiteralPath ${'$'}dll
        if (${'$'}null -eq ${'$'}sig.SignerCertificate) {
            throw 'The DLL is not Authenticode signed, so there is nothing to trust.'
        }
        ${'$'}cert = ${'$'}sig.SignerCertificate
        if (${'$'}cert.Thumbprint -ne ${'$'}expected) {
            throw ('The signer changed since it was inspected. Now: ' + ${'$'}cert.Thumbprint)
        }

        foreach (${'$'}storeName in @($MACHINE_STORES)) {
            ${'$'}store = New-Object System.Security.Cryptography.X509Certificates.X509Store(${'$'}storeName, 'LocalMachine')
            try {
                ${'$'}store.Open('ReadWrite')
                ${'$'}stale = @()
                foreach (${'$'}existing in ${'$'}store.Certificates) {
                    if (${'$'}existing.Thumbprint -eq ${'$'}expected) { ${'$'}stale += ${'$'}existing }
                }
                foreach (${'$'}old in ${'$'}stale) { ${'$'}store.Remove(${'$'}old) }
                ${'$'}store.Add(${'$'}cert)
            } finally {
                ${'$'}store.Close()
            }
        }
    """.trimIndent()

    internal fun revokeScript(thumbprint: String): String = """
        ${'$'}ErrorActionPreference = 'Stop'
        ${'$'}expected = ${psQuote(thumbprint)}

        foreach (${'$'}storeName in @($MACHINE_STORES)) {
            ${'$'}store = New-Object System.Security.Cryptography.X509Certificates.X509Store(${'$'}storeName, 'LocalMachine')
            try {
                ${'$'}store.Open('ReadWrite')
                ${'$'}stale = @()
                foreach (${'$'}existing in ${'$'}store.Certificates) {
                    if (${'$'}existing.Thumbprint -eq ${'$'}expected) { ${'$'}stale += ${'$'}existing }
                }
                foreach (${'$'}old in ${'$'}stale) { ${'$'}store.Remove(${'$'}old) }
            } finally {
                ${'$'}store.Close()
            }
        }
    """.trimIndent()

    // ——————————————————————————————————————————————————————————
    // 杂项
    // ——————————————————————————————————————————————————————————

    /**
     * 把指纹规整成可直接比较的形式。
     *
     * 指纹里可能有空格（`certutil` 就爱输出成 `A6 0E C4 …`），大小写也不统一。
     * 不做这一步，用户从别处复制过来的指纹会静默地比对不上 ——
     * 而失败信息只会说「指纹为空」，排查方向完全指错。
     */
    private fun normalizeThumbprint(raw: String): String =
        raw.filter { !it.isWhitespace() }.uppercase()

    /** 把值包成 PowerShell 单引号字符串，内部的 `'` 按 PowerShell 规则翻倍。 */
    private fun psQuote(value: String): String = "'" + value.replace("'", "''") + "'"
}

/**
 * 探测脚本的输出。字段名与脚本里 `[ordered]@{}` 的键一一对应。
 *
 * 全部给默认值：脚本在异常路径上只填一部分字段，
 * 缺字段时反序列化不该让整个探测失败。
 */
@Serializable
internal data class SignatureProbeReport(
    val probed: Boolean = false,
    val status: String? = null,
    val statusMessage: String? = null,
    val subject: String? = null,
    val thumbprint: String? = null,
    val notAfter: String? = null,
    val trusted: Boolean = false,
    val error: String? = null,
)
