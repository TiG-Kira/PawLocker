package com.kira.pawlocker.core.platform

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.File

/**
 * 「入站的解锁指令能不能进到本程序」——防火墙放行状态探测。
 *
 * ## 为什么不能只查本程序自己创建的那条规则
 *
 * Windows 在应用**第一次监听端口**时会弹一个「允许应用通过防火墙」的对话框。
 * 用户点了「允许」，系统生成的是一条**按程序路径**的规则，显示名取自安装包的
 * 产品描述（这里是「PawLocker —— 手机远程解锁 Windows」），而且 `LocalPort=Any`。
 *
 * 它和本程序自己创建的 `PawLocker (TCP 28900)` **名字完全不同**。
 * 早先的检测按名字精确匹配，于是体检每次都说「防火墙未配置」——
 * 可端口其实早就通了。代价是用户被反复引向一个会重复建规则、还要过一次 UAC
 * 的按钮，点了也没有任何变化（因为病根在检测逻辑看错了地方，不在规则上）。
 *
 * 所以这里问的是「**到目标端口的入站流量当前是否被放行**」，
 * 而不是「某条特定名字的规则存不存在」。
 *
 * ## 为什么不用「遍历所有规则再逐条看」
 *
 * 实测（本机 162 条入站允许规则，逐条 `Get-NetFirewallPortFilter`）：
 * **34 秒**。每条规则都要单独往防火墙提供程序走一次，纯开销。
 *
 * 两条快路都发生在提供程序侧，不经过 PowerShell 管道：
 *
 * | 查询方式 | 实测耗时 |
 * | --- | --- |
 * | `Get-NetFirewallApplicationFilter -Program <exe>` | 53–70 ms |
 * | `Get-NetFirewallRule -DisplayName '*关键字*'` | 约 1 060 ms |
 *
 * 所以主路走按程序路径查，查不到才退到按名字通配。
 *
 * ## 关于路径大小写
 *
 * 系统的规则里存的是 `C:\program files\pawlocker\pawlocker.exe`（全小写），
 * 而 `executablePath()` 拿到的通常是 `C:\Program Files\PawLocker\PawLocker.exe`。
 * 实测 `-Program` 参数**不区分大小写**，三种大小写写法都能命中，
 * 所以这里不需要做路径归一化。
 */
internal object FirewallProbe {

    private val json = Json { ignoreUnknownKeys = true }

    /**
     * 开发期运行时的宿主进程名。
     *
     * 通过 `gradle run` 启动时，`executablePath()` 拿到的是 `java.exe`，
     * 拿 "java" 去做显示名通配会匹配到一大堆无关的 Java 应用规则
     * （各种工具、IDE、游戏启动器），从而误报「已放行」。遇到这些名字时
     * 只走按程序路径查，不走关键字兜底。
     */
    private val GENERIC_HOST_EXES = setOf("java", "javaw", "gradle", "kotlin", "kotlinc")

    /**
     * 探一次防火墙。
     *
     * [exePath] 为空或文件不存在时不报错，只是跳过按程序路径的查询 ——
     * 「还没安装到固定位置」本身不是故障。
     */
    fun probe(port: Int, exePath: String?): FirewallCoverage {
        val exe = exePath?.takeIf { it.isNotBlank() && File(it).isFile }

        return try {
            val process = ProcessBuilder(
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                probeScript(port, exe),
            ).redirectErrorStream(true).start()

            val output = process.inputStream.readBytes().toString(Charsets.UTF_8)
            val exitCode = process.waitFor()

            if (exitCode != 0) {
                FirewallCoverage(
                    probeError = "防火墙探测退出码 $exitCode：${output.take(300).trim()}",
                )
            } else {
                interpret(output)
            }
        } catch (error: Throwable) {
            FirewallCoverage(probeError = error.message ?: "无法启动防火墙探测")
        }
    }

    /**
     * 把探测脚本的 JSON 输出翻译成 [FirewallCoverage]。
     *
     * 解析失败与「探测成功但没找到规则」是两件必须分开的事：
     * 前者要显示「无法确认」，后者才是「确实没放行」。
     * 混为一谈会让界面对着一个已经配好的机器催用户去重复配置。
     */
    internal fun interpret(output: String): FirewallCoverage {
        val jsonText = output
            .removePrefix("\uFEFF")
            .lines()
            .map { it.trim() }
            .lastOrNull { it.startsWith("{") && it.endsWith("}") }
            ?: return FirewallCoverage(
                probeError = "探测没有返回可解析的结果：${output.take(300)}",
            )

        val report = try {
            json.decodeFromString<FirewallProbeReport>(jsonText)
        } catch (error: Throwable) {
            return FirewallCoverage(probeError = "无法解析探测结果：${error.message}")
        }

        return FirewallCoverage(
            allowed = report.allowed,
            ruleName = report.rule.orEmpty(),
            profiles = report.profiles.orEmpty(),
            localPorts = report.localPorts.orEmpty(),
            probed = report.probed,
            probeError = report.error,
        )
    }

    /**
     * 探测脚本。
     *
     * 输出编码必须先于 `$ErrorActionPreference = 'Stop'` 设置：某些宿主里
     * 这一行本身会失败，而它失败不该让整个探测中断。规则显示名里有中文，
     * 不显式设 UTF-8 就会被按 OEM 码页写出来，Kotlin 侧解出来是乱码
     * （与 `SignerTrust` 里踩过的是同一个坑）。
     */
    internal fun probeScript(port: Int, exePath: String?): String = """
        [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding ${'$'}false
        ${'$'}ErrorActionPreference = 'Stop'

        ${'$'}port     = $port
        ${'$'}exe      = ${psQuote(exePath.orEmpty())}
        ${'$'}fallback = ${psQuote(keywordOf(exePath))}

        ${'$'}report = [ordered]@{
            probed     = ${'$'}false
            allowed    = ${'$'}false
            rule       = ${'$'}null
            profiles   = ${'$'}null
            localPorts = ${'$'}null
            error      = ${'$'}null
        }

        try {
            ${'$'}candidates = @()

            # 主路：按程序路径查。这条能同时覆盖「Windows 自动询问生成的按应用规则」
            # 和任何按端口创建的规则，且与规则叫什么名字无关。
            if (${'$'}exe -ne '') {
                foreach (${'$'}app in @(Get-NetFirewallApplicationFilter -Program ${'$'}exe -ErrorAction SilentlyContinue)) {
                    ${'$'}rule = ${'$'}app | Get-NetFirewallRule -ErrorAction SilentlyContinue
                    if (${'$'}null -ne ${'$'}rule) { ${'$'}candidates += ${'$'}rule }
                }
            }

            # 兜底：按显示名通配。只为覆盖「规则存在但 ApplicationFilter 关联不上」的少见情况。
            if (${'$'}candidates.Count -eq 0 -and ${'$'}fallback -ne '') {
                ${'$'}candidates = @(
                    Get-NetFirewallRule -DisplayName ("*" + ${'$'}fallback + "*") -ErrorAction SilentlyContinue
                )
            }

            foreach (${'$'}rule in ${'$'}candidates) {
                if (${'$'}null -eq ${'$'}rule) { continue }
                if ([string]${'$'}rule.Direction -ne 'Inbound') { continue }
                if ([string]${'$'}rule.Action    -ne 'Allow')   { continue }
                if ([string]${'$'}rule.Enabled   -ne 'True')    { continue }

                ${'$'}pf = ${'$'}rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
                if (${'$'}null -eq ${'$'}pf) { continue }

                ${'$'}proto = [string]${'$'}pf.Protocol
                if (${'$'}proto -ne 'TCP' -and ${'$'}proto -ne 'Any') { continue }

                # LocalPort 是字符串数组；'Any' 表示该程序在所有端口上都被放行。
                ${'$'}ports = @(${'$'}pf.LocalPort)
                if (-not (${'$'}ports -contains 'Any' -or ${'$'}ports -contains [string]${'$'}port)) { continue }

                ${'$'}report.allowed    = ${'$'}true
                ${'$'}report.rule       = [string]${'$'}rule.DisplayName
                ${'$'}report.profiles   = [string]${'$'}rule.Profile
                ${'$'}report.localPorts = (${'$'}ports -join '/')
                break
            }

            ${'$'}report.probed = ${'$'}true
        } catch {
            ${'$'}report.probed = ${'$'}false
            ${'$'}report.error  = ${'$'}error.Exception.Message
        }

        ${'$'}report | ConvertTo-Json -Compress
    """.trimIndent()

    /**
     * 从可执行文件名推导显示名关键字。
     *
     * MSI 安装后路径是 `C:\Program Files\PawLocker\PawLocker.exe`，
     * 拿到的关键字是 `PawLocker`，与防火墙规则的显示名（取自产品描述）对得上。
     *
     * 开发期跑在 `java.exe` 上，关键字会变成 `java` —— 那种情况下返回空串，
     * 让脚本跳过关键字兜底，避免把无关的 Java 应用规则误认成本程序。
     */
    internal fun keywordOf(exePath: String?): String {
        if (exePath.isNullOrBlank()) return ""
        val name = File(exePath).nameWithoutExtension
        return if (name.lowercase() in GENERIC_HOST_EXES) "" else name
    }

    /** 把值包成 PowerShell 单引号字符串，内部的 `'` 按 PowerShell 规则翻倍。 */
    private fun psQuote(value: String): String = "'" + value.replace("'", "''") + "'"
}

/**
 * 一次防火墙探测的结果。
 *
 * 字段与 [RegistrationState] 里那几个 `firewall*` 一一对应，
 * 由 `WindowsRegistrar` 摊平后填进去。
 */
internal data class FirewallCoverage(
    /** 到目标端口的入站 TCP 是否已被某条规则放行。 */
    val allowed: Boolean = false,
    val ruleName: String = "",
    val profiles: String = "",
    val localPorts: String = "",
    val probed: Boolean = false,
    val probeError: String? = null,
)

/**
 * 探测脚本的输出。字段名与脚本里 `[ordered]@{}` 的键一一对应。
 *
 * 全部给默认值：异常路径上脚本只填一部分字段，缺字段不该让反序列化失败。
 */
@Serializable
internal data class FirewallProbeReport(
    val probed: Boolean = false,
    val allowed: Boolean = false,
    val rule: String? = null,
    val profiles: String? = null,
    val localPorts: String? = null,
    val error: String? = null,
)
