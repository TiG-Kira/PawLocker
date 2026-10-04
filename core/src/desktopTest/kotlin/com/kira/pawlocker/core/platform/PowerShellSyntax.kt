package com.kira.pawlocker.core.platform

import java.io.File

/**
 * 用 PowerShell 自己的解析器做**纯语法校验** —— 只解析，不执行，不弹 UAC。
 *
 * 它的价值在于挡住「用户点完按钮、过了 UAC 才发现脚本有语法错」这种
 * 最糟的失败时机：提权路径本身没法在开发机或 CI 上自动跑一遍
 * （每次都要真人点 UAC），但语法错可以在这里低成本地全量拦下。
 *
 * ## 为什么脚本走临时文件，而不是写进子进程的 stdin
 *
 * 最初的做法是把脚本写进 stdin，由 PowerShell 侧
 * `[Console]::In.ReadToEnd()` 读回来。这在纯 ASCII 脚本上没问题，
 * 但只要脚本里有**中文注释**就会炸 —— 而且报出来的是
 * 「Try 语句缺少其 Catch 或 Finally 块」「表达式或语句中包含意外的标记 }」
 * 这类**跟编码八竿子打不着**的语法错误，排查方向会被完全带偏。
 *
 * 原因：`[Console]::In` 用控制台的 **OEM 码页**（中文机器上是 936/GBK）
 * 去解码，而脚本是 **UTF-8** 的。一个三字节汉字会被错拼成别的字符，
 * 其中不少字节正好落在 `}`、`\`、`"` 这些**能直接改变语法结构**的
 * ASCII 码位上 —— 解析器于是看到一堆凭空多出来的右花括号。
 *
 * 改成「按 UTF-8 写临时文件 → 按 UTF-8 读回来」之后，编码这一环就彻底消失了。
 */
internal fun powershellParseErrors(script: String): List<String> {
    val scriptFile = File.createTempFile("pawlocker-syntax-", ".ps1")
    return try {
        scriptFile.writeText(script, Charsets.UTF_8)
        val path = scriptFile.absolutePath.replace("'", "''")

        val validator = """
            [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding ${'$'}false
            ${'$'}text   = [System.IO.File]::ReadAllText('$path', [System.Text.Encoding]::UTF8)
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

        val output = process.inputStream.readBytes().toString(Charsets.UTF_8)
        val exitCode = process.waitFor()

        if (exitCode == 0) emptyList() else output.lines().filter { it.isNotBlank() }
    } finally {
        scriptFile.delete()
    }
}
