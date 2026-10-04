package com.kira.pawlocker.core.platform

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import java.io.File

/**
 * 签名探测的结果解读。
 *
 * 这一组测试守的是一条从实测里踩出来的规则，而不是从文档里抄的：
 * Windows PowerShell 5.1 在「签名没问题、但证书不受信任」时返回
 * `Status = UnknownError`，**不是** `NotTrusted`。
 *
 * 如果哪天有人「顺手优化」成直接按 `Status` 字面匹配，
 * 这里就会红 —— 而线上（锁屏上）的表现是引导用户反复重签一个本来就
 * 签好的 DLL，永远走不出去。
 */
class SignerTrustTest {

    // ——————————————————————————————————————————————————————————————
    // 样例报文
    // ——————————————————————————————————————————————————————————————

    /**
     * 一份**真机采集**的探测输出：DLL 已签名，但证书不在本机受信任存储里。
     * 注意 `status` 是 `UnknownError` 而不是 `NotTrusted` —— 这就是那个坑。
     */
    private val untrustedReport = """
        {"probed":true,"status":"UnknownError","statusMessage":"已处理证书链，但是在不受信任提供程序信任的根证书中终止。","subject":"CN=PawLocker Development, O=PawLocker","thumbprint":"A60EC44BFCE32BE65AAD4191B943EEA1D2B8D819","notAfter":"2029-10-04","trusted":false,"error":null}
    """.trimIndent()

    private val trustedReport = """
        {"probed":true,"status":"Valid","statusMessage":"","subject":"CN=PawLocker Development, O=PawLocker","thumbprint":"A60EC44BFCE32BE65AAD4191B943EEA1D2B8D819","notAfter":"2029-10-04","trusted":true,"error":null}
    """.trimIndent()

    private val unsignedReport = """
        {"probed":true,"status":"NotSigned","statusMessage":"","subject":null,"thumbprint":null,"notAfter":null,"trusted":false,"error":null}
    """.trimIndent()

    // ——————————————————————————————————————————————————————————————
    // 解读规则
    // ——————————————————————————————————————————————————————————————

    @Test
    fun `证书不受信任时归为 Untrusted 而不是 Broken`() {
        val signature = SignerTrust.interpret(untrustedReport)

        assertEquals(DllSignatureStatus.Untrusted, signature.status)
        assertTrue(signature.probed, "探测本身是成功的")
        assertFalse(signature.isReady, "没被信任就不算就绪")
        assertTrue(signature.isSigned, "它确实签过名 —— 这是引导用户去信任、而不是去重签的前提")
    }

    @Test
    fun `签名有效且证书受信任时归为 Trusted`() {
        val signature = SignerTrust.interpret(trustedReport)

        assertEquals(DllSignatureStatus.Trusted, signature.status)
        assertTrue(signature.isReady)
        assertTrue(signature.isSigned)
    }

    @Test
    fun `没有签名时归为 NotSigned`() {
        val signature = SignerTrust.interpret(unsignedReport)

        assertEquals(DllSignatureStatus.NotSigned, signature.status)
        assertFalse(signature.isSigned)
        assertFalse(signature.isReady)
    }

    @Test
    fun `证书已在信任存储里但签名依然无效时归为 Broken`() {
        // 这一档的含义：证书是受信任的，所以问题不在信任上，
        // 而在签名本身（文件签名后被改过、或证书过期）。
        // 此时引导用户去「信任证书」是无效动作 —— 必须区分出来。
        val report = """
            {"probed":true,"status":"HashMismatch","statusMessage":"","subject":"CN=x","thumbprint":"AA","notAfter":"2030-01-01","trusted":true,"error":null}
        """.trimIndent()

        assertEquals(DllSignatureStatus.Broken, SignerTrust.interpret(report).status)
    }

    @Test
    fun `探测失败时不会伪装成没签名`() {
        // 「没看出来」和「看出来没签名」必须分开。混为一谈会让界面
        // 催用户去重签一个可能已经签好的 DLL。
        val report = """
            {"probed":false,"status":"ProbeFailed","statusMessage":null,"subject":null,"thumbprint":null,"notAfter":null,"trusted":false,"error":"Cannot find path"}
        """.trimIndent()

        val signature = SignerTrust.interpret(report)
        assertEquals(DllSignatureStatus.ProbeFailed, signature.status)
        assertFalse(signature.probed)
        assertEquals("Cannot find path", signature.probeError)
    }

    // ——————————————————————————————————————————————————————————————
    // 报文解析的健壮性
    // ——————————————————————————————————————————————————————————————

    @Test
    fun `带 BOM 与前后空白的输出能解析`() {
        // PowerShell 的重定向输出可能带 BOM，脚本本身也可能在 JSON 之前
        // 打印了别的东西。这两种情况都不该让探测结果变成「无法解析」。
        val noisy = "\uFEFF\r\nPS> 正在探测\r\n$trustedReport\r\n"

        assertEquals(DllSignatureStatus.Trusted, SignerTrust.interpret(noisy).status)
    }

    @Test
    fun `非 JSON 输出归为探测失败并保留原文`() {
        val signature = SignerTrust.interpret("powershell.exe 不是内部或外部命令")

        assertEquals(DllSignatureStatus.ProbeFailed, signature.status)
        assertTrue(
            signature.probeError?.contains("powershell.exe") == true,
            "失败原因要保留原文，否则排障时完全不知道发生了什么：${signature.probeError}",
        )
    }

    @Test
    fun `中文的 StatusMessage 能原样读出来`() {
        // 系统的说明文本是本地化的。Kotlin 侧按 UTF-8 解码，
        // 脚本侧也必须把输出编码设成 UTF-8，两边对不上就是一堆问号。
        val signature = SignerTrust.interpret(untrustedReport)

        assertTrue(
            signature.statusMessage?.contains("不受信任") == true,
            "中文说明应在解码后保持可读，实际：${signature.statusMessage}",
        )
    }

    @Test
    fun `多出来的字段不会让解析失败`() {
        // 脚本将来加了字段、而应用还是旧版本，不该整块挂掉
        val report = """
            {"probed":true,"status":"Valid","trusted":true,"thumbprint":"AA","someFutureField":{"nested":1},"anotherFuture":42}
        """.trimIndent()

        assertEquals(DllSignatureStatus.Trusted, SignerTrust.interpret(report).status)
    }

    @Test
    fun `字段缺失时使用默认值而不是抛异常`() {
        // 异常路径下脚本只填一部分字段
        val signature = SignerTrust.interpret("""{"probed":true,"status":"NotSigned"}""")

        assertEquals(DllSignatureStatus.NotSigned, signature.status)
        assertNull(signature.signerThumbprint)
        assertFalse(signature.signerTrustedOnMachine)
    }

    // ——————————————————————————————————————————————————————————————
    // 脚本本身
    // ——————————————————————————————————————————————————————————————

    @Test
    fun `生成的脚本都是合法的 PowerShell`() {
        // 提权那条路径在开发机上没法真跑（要弹 UAC），所以至少把语法挡住。
        // 一个语法错误会让用户在点完按钮、过了 UAC 之后才看到失败 ——
        // 那是最糟糕的失败时机。这里做的是**纯解析**，不执行任何东西。
        val awkwardPath = """C:\Program Files\PawLocker\it's.dll"""

        val samples = mapOf(
            "probe" to SignerTrust.probeScript(awkwardPath),
            "trust" to SignerTrust.trustScript(awkwardPath, "A60EC44BFCE32BE65AAD4191B943EEA1D2B8D819"),
            "revoke" to SignerTrust.revokeScript("A60EC44BFCE32BE65AAD4191B943EEA1D2B8D819"),
        )

        samples.forEach { (name, script) ->
            val errors = parseErrors(script)
            assertTrue(
                errors.isEmpty(),
                "$name 脚本有语法错误：\n${errors.joinToString("\n")}\n--- 脚本原文 ---\n$script",
            )
        }
    }

    @Test
    fun `路径里的单引号被转义成两个`() {
        // 路径被拼进 PowerShell 单引号字符串。不转义的话，
        // 一个带撇号的目录名（`C:\Users\O'Brien\`）就能把脚本从中间截断，
        // 后半段变成可执行的 PowerShell —— 这是拼接脚本最典型的一类漏洞。
        val script = SignerTrust.probeScript("""C:\Users\O'Brien\it's.dll""")

        assertTrue(
            script.contains("""'C:\Users\O''Brien\it''s.dll'"""),
            "单引号应当翻倍后嵌入，实际脚本里找不到转义后的路径",
        )
    }

    /**
     * 只解析、不执行，返回语法错误列表。
     *
     * 脚本正文走 stdin 传进去，而不是拼进 `-Command`：
     * 待校验的脚本里本来就有大量引号和 `$`，再嵌一层引号只会验证「转义写对了没」，
     * 而不是「被测脚本对不对」。
     */
    private fun parseErrors(script: String): List<String> {
        val validator = """
            ${'$'}text   = [Console]::In.ReadToEnd()
            ${'$'}tokens = ${'$'}null
            ${'$'}errors = ${'$'}null
            ${'$'}null = [System.Management.Automation.Language.Parser]::ParseInput(${'$'}text, [ref]${'$'}tokens, [ref]${'$'}errors)
            if (${'$'}errors.Count -gt 0) {
                foreach (${'$'}e in ${'$'}errors) { Write-Output ${'$'}e.Message }
                exit 1
            }
            exit 0
        """.trimIndent()

        val process = ProcessBuilder(
            "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", validator,
        ).redirectErrorStream(true).start()

        // 被测脚本先整段写进 stdin 再读输出：解析器要读完整段才会产出错误列表。
        // 脚本只有几 KB，不会撑满管道缓冲区，不存在读写互相等待的死锁。
        process.outputStream.bufferedWriter(Charsets.UTF_8).use { it.write(script) }
        val output = process.inputStream.readBytes().toString(Charsets.UTF_8)
        val exitCode = process.waitFor()

        return if (exitCode == 0) emptyList() else output.lines().filter { it.isNotBlank() }
    }

    // ——————————————————————————————————————————————————————————————
    // 真机探测（本机存在已构建 DLL 时才真正验证）
    // ——————————————————————————————————————————————————————————————

    /**
     * 走一遍真实链路：写脚本 → 起 PowerShell → 读 stdout → 解 JSON → 判定。
     *
     * 这一条守的是「能不能真的跑起来」，上面那些都只测了最后一步的解读。
     * 其中最容易出问题的是**把多行脚本经 `-Command` 传进 PowerShell** ——
     * 参数里的换行符、引号、`$` 号任何一处没处理对，都会表现为
     * 「探测失败」，而单看代码完全看不出问题。
     *
     * 本机没有构建产物时直接返回：这条测试的价值在开发机上，
     * 不该让一个干净的 clone 因为缺少构建产物而变红。
     */
    @Test
    fun `真实探测已签名的 DLL`() {
        val dll = locateBuiltDll()
        if (dll == null) {
            println("[SignerTrustTest] 未找到 credential-provider/build/PawLockerProvider.dll，跳过真机探测")
            return
        }

        val signature = SignerTrust.probe(dll.absolutePath)

        // 打印出来，好让编码问题（中文变问号）在跑测试时就能被肉眼看到
        println("[SignerTrustTest] 探测 $dll")
        println("[SignerTrustTest]   probed=${signature.probed} status=${signature.status} raw=${signature.rawStatus}")
        println("[SignerTrustTest]   subject=${signature.signerSubject}")
        println("[SignerTrustTest]   thumbprint=${signature.signerThumbprint}")
        println("[SignerTrustTest]   trusted=${signature.signerTrustedOnMachine}")
        println("[SignerTrustTest]   message=${signature.statusMessage}")
        println("[SignerTrustTest]   error=${signature.probeError}")

        assertTrue(
            signature.probed,
            "探测没能跑通，说明脚本或进程调用有问题：${signature.probeError}",
        )
        assertTrue(
            signature.isSigned,
            "这个 DLL 应当已签名（raw=${signature.rawStatus}），否则先跑一次 sign.bat",
        )
        assertEquals(
            40,
            signature.signerThumbprint?.length,
            "指纹应是 40 位十六进制，实际：${signature.signerThumbprint}",
        )
        assertTrue(
            signature.signerTrustedOnMachine == signature.isReady,
            "isReady 与信任状态必须一致：trusted=${signature.signerTrustedOnMachine} status=${signature.status}",
        )
    }

    private fun locateBuiltDll(): File? = listOf(
        // Gradle 跑 desktopTest 时的工作目录是模块目录（core/）
        "../credential-provider/build/PawLockerProvider.dll",
        "credential-provider/build/PawLockerProvider.dll",
    ).map(::File).firstOrNull { it.isFile }
}
