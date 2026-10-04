package com.kira.pawlocker.core.platform

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * 「卸载前清理」的行为约束。
 *
 * 重点守三件事：
 *
 * 1. **脚本必须语法合法** —— 它要过 UAC 才能跑，出错时代价极高（用户点了是、
 *    等了、结果什么都没清）。
 * 2. **开发期绝不能按程序路径删防火墙规则** —— 宿主进程是 `java.exe`，
 *    本机有一堆别的 Java 应用规则，误删的用户往往事后才发现。
 * 3. **解析失败必须报失败，不能报「全部已清」** —— 那比报错坏得多：
 *    用户会以为机器干净了就去卸载。
 */
class WindowsCleanupTest {

    private val script = WindowsCleanup.script(
        providerKey = DesktopWindowsRegistrar.CP_PROVIDER_KEY,
        clsidKey = DesktopWindowsRegistrar.CP_CLSID_KEY,
        thumbprint = "A60EC4C1A2B3C4D5E6F708192A3B4C5D6E7F8091",
        port = 28900,
        ownRuleName = "PawLocker (TCP 28900)",
        exePath = "C:\\Program Files\\PawLocker\\PawLocker.exe",
        deleteByProgram = true,
    )

    @Test
    fun `清理脚本语法合法`() {
        val errors = powershellParseErrors(script)
        assertTrue(errors.isEmpty(), "清理脚本有语法错误：${errors.joinToString("；")}")
    }

    @Test
    fun `开发期模式下语法同样合法`() {
        // 换成 null 指纹 + 关掉按程序路径删，走的是另一条分支
        val devScript = WindowsCleanup.script(
            providerKey = DesktopWindowsRegistrar.CP_PROVIDER_KEY,
            clsidKey = DesktopWindowsRegistrar.CP_CLSID_KEY,
            thumbprint = null,
            port = 28900,
            ownRuleName = "PawLocker (TCP 28900)",
            exePath = "C:\\Program Files\\Java\\jdk-21\\bin\\java.exe",
            deleteByProgram = false,
        )
        val errors = powershellParseErrors(devScript)
        assertTrue(errors.isEmpty(), "开发期脚本有语法错误：${errors.joinToString("；")}")
    }

    @Test
    fun `开发期模式下按程序路径的删除被开关拦住`() {
        // 断言的是「开关真的插进了脚本」而不是「脚本里没有那句」——
        // 后者在重构时太容易被绕过，前者能钉住意图。
        val devScript = WindowsCleanup.script(
            providerKey = "K1",
            clsidKey = "K2",
            thumbprint = null,
            port = 1,
            ownRuleName = "x",
            exePath = "C:\\Java\\java.exe",
            deleteByProgram = false,
        )
        assertTrue(
            devScript.contains("\$byProgram = False") ||
                devScript.contains("\$byProgram = \$False") ||
                devScript.contains("\$byProgram = false"),
            "deleteByProgram=false 必须插进脚本，而不是靠调用方自觉不传 exe",
        )
    }

    @Test
    fun `解析四项全成功`() {
        val output = """
            [{"key":"credential_provider","ok":true,"present":"before","message":"HKLM:\\A"},
             {"key":"credential_provider_clsid","ok":true,"present":"before","message":"HKLM:\\B"},
             {"key":"firewall","ok":true,"present":"before","message":"PawLocker (TCP 28900)"},
             {"key":"certificate","ok":true,"present":"before","message":"Root"}]
        """.trimIndent()

        val items = WindowsCleanup.parse(output, exitCode = 0)
        assertEquals(4, items.size)
        assertTrue(items.all { it.status == CleanupStatus.Done })
        assertEquals("锁屏凭据提供程序注册", items[0].label)
        assertEquals("DLL 类注册（CLSID）", items[1].label)
        assertEquals("入站防火墙规则", items[2].label)
        assertEquals("DLL 签名证书信任", items[3].label)
    }

    @Test
    fun `absent 记为跳过而不是成功`() {
        val output = """
            [{"key":"credential_provider","ok":true,"present":"absent","message":"HKLM:\\A"},
             {"key":"firewall","ok":true,"present":"before","message":"rule"}]
        """.trimIndent()

        val items = WindowsCleanup.parse(output, exitCode = 0)
        assertEquals(CleanupStatus.Skipped, items[0].status)
        assertEquals(CleanupStatus.Done, items[1].status)
    }

    @Test
    fun `单项失败不影响其它项`() {
        val output = """
            [{"key":"credential_provider","ok":false,"present":"before","message":"拒绝访问"},
             {"key":"credential_provider_clsid","ok":true,"present":"before","message":"HKLM:\\B"},
             {"key":"firewall","ok":true,"present":"absent","message":"none"},
             {"key":"certificate","ok":false,"present":"before","message":"仍在本机受信任存储里"}]
        """.trimIndent()

        val items = WindowsCleanup.parse(output, exitCode = 0)
        assertEquals(2, items.count { it.status == CleanupStatus.Failed })
        assertEquals(CleanupReport(items).outstanding.size, 2)
    }

    @Test
    fun `单元素时 PowerShell 输出对象而非数组也能解析`() {
        // ConvertTo-Json 对单元素集合的默认行为就是输出对象而不是单元素数组
        val output = """{"key":"firewall","ok":true,"present":"absent","message":"none"}"""
        val items = WindowsCleanup.parse(output, exitCode = 0)
        assertEquals(1, items.size)
        assertEquals("入站防火墙规则", items[0].label)
    }

    @Test
    fun `输出里混有非 JSON 行时仍能取到最后一段`() {
        // 提权脚本常伴随警告与噪声，解析必须只取 JSON 段
        val output = """
            WARNING: 某个无关的警告
            [{"key":"firewall","ok":true,"present":"before","message":"rule"}]
        """.trimIndent()

        val items = WindowsCleanup.parse(output, exitCode = 0)
        assertEquals(1, items.size)
        assertEquals(CleanupStatus.Done, items[0].status)
    }

    @Test
    fun `JSON 被换行折断时四项一个都不能丢`() {
        // 回归测试。早先的实现逐行找 JSON，输出一旦被折行
        // （管道缓冲、控制台宽度、重定向都会导致）就只能认到 1 项 ——
        // 而界面上会显示「已清理 1 项」，用户以为其余的都不用管。
        val folded = """
            [
              {"key":"credential_provider","ok":true,"present":"before","message":"a"},
              {"key":"credential_provider_clsid","ok":true,"present":"before","message":"b"},
              {"key":"firewall","ok":true,"present":"before","message":"c"},
              {"key":"certificate","ok":true,"present":"before","message":"d"}
            ]
        """.trimIndent()

        val items = WindowsCleanup.parse(folded, exitCode = 0)
        assertEquals(4, items.size)
        assertTrue(items.all { it.status == CleanupStatus.Done })
    }

    @Test
    fun `BOM 与尾部噪声都不影响解析`() {
        val output = "﻿" + """
            [{"key":"firewall","ok":true,"present":"absent","message":"none"}]
            The operation completed successfully.
        """.trimIndent()

        val items = WindowsCleanup.parse(output, exitCode = 0)
        assertEquals(1, items.size)
        assertEquals(CleanupStatus.Skipped, items[0].status)
    }

    @Test
    fun `解析不出结果时报失败而不是报空`() {
        val items = WindowsCleanup.parse("什么都不是", exitCode = 1)
        assertEquals(1, items.size)
        assertEquals(CleanupStatus.Failed, items[0].status)
        // 这是最关键的一条：报「空报告」会让界面显示「已清理干净」，
        // 而实际上一点都没动
        assertTrue(!items[0].isClean)
    }

    @Test
    fun `全部跳过时也算干净`() {
        val report = CleanupReport(
            listOf(
                CleanupItem("a", "", CleanupStatus.Skipped),
                CleanupItem("b", "", CleanupStatus.Skipped),
            ),
        )
        assertTrue(report.isClean)
        assertEquals("本机本来就没有 PawLocker 的系统痕迹", report.summary())
    }

    @Test
    fun `有失败时摘要点数并给出结论`() {
        val report = CleanupReport(
            listOf(
                CleanupItem("a", "", CleanupStatus.Done),
                CleanupItem("b", "", CleanupStatus.Skipped),
                CleanupItem("c", "", CleanupStatus.Failed),
            ),
        )
        assertTrue(!report.isClean)
        assertEquals(1, report.outstanding.size)
        assertEquals("已清理 2 项，1 项失败", report.summary())
    }

    @Test
    fun `取消与失败都算未清干净`() {
        val report = CleanupReport(listOf(CleanupItem("a", "", CleanupStatus.Cancelled)))
        assertTrue(!report.isClean)
        assertEquals("已清理 0 项，0 项失败、1 项被取消", report.summary())
    }
}
