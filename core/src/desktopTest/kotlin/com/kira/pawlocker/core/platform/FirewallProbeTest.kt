package com.kira.pawlocker.core.platform

import com.kira.pawlocker.core.protocol.Protocol
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * 防火墙放行状态探测的测试。
 *
 * 守两处最容易出错、错了之后症状又极具误导性的地方：
 *
 *  1. **「探测失败」与「确实没放行」必须分开**。
 *     混为一谈会让界面对着一台已经配好的机器催用户去重复配置，
 *     而那一步要过一次 UAC，点完还看不出任何变化。
 *
 *  2. **关键字兜底的适用范围**。
 *     开发期运行在 `java.exe` 上，拿 "java" 去做显示名通配会匹配到一大堆
 *     无关规则（IDE、构建工具、游戏启动器都带 Java 运行时），
 *     于是探测报「已放行」—— 而实际上一个相关端口都没开。
 *     这种**误报比漏报更坏**：用户会以为一切就绪，然后对着一个
 *     连不上的端口怎么都找不出原因。所以这类宿主进程必须主动放弃兜底。
 */
class FirewallProbeTest {

    // ——————————————————————————————————————————————————————————————
    // 结果解读
    // ——————————————————————————————————————————————————————————————

    @Test
    fun `已放行时带回规则名与放行范围`() {
        val coverage = FirewallProbe.interpret(
            """{"probed":true,"allowed":true,"rule":"PawLocker —— 手机远程解锁 Windows",""" +
                """"profiles":"Private, Public","localPorts":"Any","error":null}""",
        )

        assertTrue(coverage.probed)
        assertTrue(coverage.allowed)
        assertEquals("PawLocker —— 手机远程解锁 Windows", coverage.ruleName)
        assertEquals("Private, Public", coverage.profiles)
        assertEquals("Any", coverage.localPorts)
        assertEquals(null, coverage.probeError)
    }

    @Test
    fun `没找到规则是探测成功而不是失败`() {
        val coverage = FirewallProbe.interpret("""{"probed":true,"allowed":false}""")

        assertTrue(
            coverage.probed,
            "probed 说的是「有没有看出来」，与「放没放行」是两回事",
        )
        assertFalse(coverage.allowed)
        assertEquals(
            null,
            coverage.probeError,
            "仅仅「没找到规则」不构成探测错误 —— 界面上要显示成「待处理」而不是「无法确认」",
        )
        assertEquals("", coverage.ruleName)
        assertEquals("", coverage.localPorts)
    }

    @Test
    fun `探测自身的失败要原样带上系统给的错误`() {
        val coverage = FirewallProbe.interpret(
            """{"probed":false,"allowed":false,"error":"Access is denied."}""",
        )

        assertFalse(coverage.probed)
        assertFalse(coverage.allowed)
        assertEquals("Access is denied.", coverage.probeError)
    }

    @Test
    fun `输出不是 JSON 时算探测失败而不是没放行`() {
        val coverage = FirewallProbe.interpret("这不是 JSON，是 PowerShell 的报错文本")

        assertFalse(coverage.probed, "解析不出来就必须承认「没看出来」")
        assertFalse(
            coverage.allowed,
            "解析失败时绝不能报「已放行」—— 那会让用户跳过本该补的配置",
        )
        assertNotNull(coverage.probeError)
    }

    @Test
    fun `忽略脚本里的杂项输出只取最后一行 JSON`() {
        val coverage = FirewallProbe.interpret(
            """
            警告：某个 cmdlet 输出了额外内容
            另外一行噪声
            {"probed":true,"allowed":true,"rule":"R","localPorts":"28900"}
            """.trimIndent(),
        )

        assertTrue(coverage.allowed)
        assertEquals("R", coverage.ruleName)
        assertEquals("28900", coverage.localPorts)
    }

    @Test
    fun `缺字段时不抛异常而是走默认值`() {
        // 脚本的异常路径只会填一部分字段，缺字段不该让整个探测崩掉
        val coverage = FirewallProbe.interpret("""{"probed":true}""")

        assertTrue(coverage.probed)
        assertFalse(coverage.allowed)
        assertEquals("", coverage.ruleName)
        assertEquals("", coverage.profiles)
        assertEquals(null, coverage.probeError)
    }

    // ——————————————————————————————————————————————————————————————
    // 关键字兜底
    // ——————————————————————————————————————————————————————————————

    @Test
    fun `关键字从可执行文件名推导`() {
        assertEquals(
            "PawLocker",
            FirewallProbe.keywordOf(
                """C:\Program Files\PawLocker\PawLocker.exe""",
            ),
        )
        assertEquals("PawLocker", FirewallProbe.keywordOf("""D:\tools\PawLocker.EXE"""))
    }

    @Test
    fun `开发期宿主进程不参与关键字兜底`() {
        for (host in listOf("java", "javaw", "gradle", "kotlin")) {
            assertEquals(
                "",
                FirewallProbe.keywordOf("""D:\somewhere\$host.exe"""),
                "$host 是开发期宿主，不该拿去通配规则名",
            )
            assertEquals(
                "",
                FirewallProbe.keywordOf("""D:\somewhere\${host.uppercase()}.exe"""),
                "大小写也要认出来",
            )
        }
    }

    @Test
    fun `没有可用路径时不产生关键字`() {
        assertEquals("", FirewallProbe.keywordOf(null))
        assertEquals("", FirewallProbe.keywordOf(""))
        assertEquals("", FirewallProbe.keywordOf("   "))
    }

    // ——————————————————————————————————————————————————————————————
    // 脚本
    // ——————————————————————————————————————————————————————————————

    @Test
    fun `目标端口与 exe 路径都写进了脚本`() {
        val script = FirewallProbe.probeScript(28900, """C:\Program Files\PawLocker\PawLocker.exe""")

        assertTrue(script.contains("= 28900"), "端口要原样进脚本")
        assertTrue(script.contains("PawLocker.exe"), "exe 路径要进脚本，否则按程序路径的查询会退化")
        assertTrue(script.contains("Get-NetFirewallApplicationFilter"))
    }

    @Test
    fun `脚本里的单引号被按 PowerShell 规则转义`() {
        // 路径里带单引号在 Windows 上少见但合法（用户名里可以有）
        val script = FirewallProbe.probeScript(28900, """C:\Users\o'brien\PawLocker.exe""")

        assertTrue(
            script.contains("""'C:\Users\o''brien\PawLocker.exe'"""),
            "单引号要翻倍，否则脚本会在这里提前结束字符串并报语法错",
        )
    }

    @Test
    fun `没有 exe 路径时脚本不产生兜底关键字`() {
        val script = FirewallProbe.probeScript(28900, null)

        assertTrue(
            script.contains("${'$'}fallback = ''"),
            "拿不到 exe 路径时要让关键字为空，否则会去通配无关的规则名",
        )
    }

    @Test
    fun `生成的探测脚本都是合法的 PowerShell`() {
        val scripts = listOf(
            FirewallProbe.probeScript(28900, """C:\Program Files\PawLocker\PawLocker.exe"""),
            FirewallProbe.probeScript(9898, null),
            FirewallProbe.probeScript(28900, """C:\Users\o'brien\PawLocker.exe"""),
        )

        scripts.forEachIndexed { index, script ->
            val errors = powershellParseErrors(script)
            assertTrue(
                errors.isEmpty(),
                "第 ${index + 1} 个脚本语法有误：$errors",
            )
        }
    }

    // ——————————————————————————————————————————————————————————————
    // 真机探测（本机装了 PawLocker 时才真正验证）
    // ——————————————————————————————————————————————————————————————

    /**
     * 走一遍真实链路：起 PowerShell → 读 stdout → 解 JSON → 判定。
     *
     * 上面那些用例只测了「最后一跳的解读」，这一条测的是「能不能真的跑起来」。
     * 最容易翻车的正是**把多行脚本经 `-Command` 传进 PowerShell** ——
     * 换行、引号、`$` 号任何一处没处理对都表现为「探测失败」，
     * 而光看代码完全看不出问题（`SignerTrust` 当初就是在这里栽的）。
     *
     * 本机没装 PawLocker 时直接返回：这条测试的价值在开发机上，
     * 不该让一个干净的 clone 因为「没装过 MSI」而变红。
     */
    @Test
    fun `真实探测本机的防火墙放行状态`() {
        val exe = locateInstalledExe()
        if (exe == null) {
            println("[FirewallProbeTest] 本机未安装 PawLocker，跳过真机探测")
            return
        }

        val coverage = FirewallProbe.probe(Protocol.DEFAULT_PORT, exe.absolutePath)

        // 打印出来，让编码问题（中文变问号）在跑测试时就能被肉眼看到
        println("[FirewallProbeTest] 探测 $exe")
        println("[FirewallProbeTest]   端口      = ${Protocol.DEFAULT_PORT}")
        println("[FirewallProbeTest]   probed    = ${coverage.probed}")
        println("[FirewallProbeTest]   allowed   = ${coverage.allowed}")
        println("[FirewallProbeTest]   rule      = ${coverage.ruleName}")
        println("[FirewallProbeTest]   profiles  = ${coverage.profiles}")
        println("[FirewallProbeTest]   localPorts= ${coverage.localPorts}")
        println("[FirewallProbeTest]   error     = ${coverage.probeError}")

        assertTrue(
            coverage.probed,
            "探测没能跑通，说明脚本或进程调用有问题：${coverage.probeError}",
        )

        if (coverage.allowed) {
            assertTrue(
                coverage.ruleName.isNotBlank(),
                "说了「已放行」就必须说得出是哪条规则放行的",
            )
            assertTrue(
                coverage.localPorts.isNotBlank(),
                "放行范围是 Any 还是具体端口，必须能区分 —— 这两者暴露面差很多",
            )
        }
    }

    private fun locateInstalledExe(): File? = listOf(
        """C:\Program Files\PawLocker\PawLocker.exe""",
        """C:\Program Files (x86)\PawLocker\PawLocker.exe""",
    ).map(::File).firstOrNull { it.isFile }
}
