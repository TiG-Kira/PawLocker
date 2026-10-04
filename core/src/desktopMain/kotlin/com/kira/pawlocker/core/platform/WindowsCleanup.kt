package com.kira.pawlocker.core.platform

/**
 * 「卸载前把系统痕迹清干净」的实现。
 *
 * ## 要清哪些、为什么是这五处
 *
 * 全部是**用户在应用里点了按钮之后**才写进系统的，MSI 眼里不存在，
 * 所以「控制面板 → 卸载」不会动它们：
 *
 * | # | 位置 | 清不掉的后果 |
 * |---|---|---|
 * | 1 | `HKLM\...\Credential Providers\{GUID}` | 锁屏上留着一个点开就报错的 PawLocker 磁贴 |
 * | 2 | `HKLM\SOFTWARE\Classes\CLSID\{GUID}` | LogonUI 会去加载一个已经不存在的 DLL |
 * | 3 | `LocalMachine\Root` + `TrustedPublisher` 里的自签证书 | 一条撤不掉的自签根信任 |
 * | 4 | `netsh` 入站防火墙规则 | 一条指向已删除程序路径的入站放行 |
 * | 5 | `HKCU\...\Run` 启动项 | 每次登录都试图启动一个已被卸载的程序 |
 *
 * 第 1 条最难受：用户看到锁屏上那个磁贴就会认为软件还在，于是反复重装，
 * 而重装不会消掉它 —— 因为它压根不是 MSI 装的。
 *
 * ## 顺序不是随意的
 *
 * 证书清理（3）必须在读 DLL 之后做：指纹是从**已注册的 DLL 路径**读出来的，
 * 而那个路径存在注册表的 `CLSID\...\InprocServer32`（第 2 项）里。
 * 先删注册表就再也读不到指纹，只能让用户自己去 `certmgr.msc` 里手删。
 * 所以顺序是：先取指纹 → 再删注册表 → 最后删证书。
 *
 * ## 为什么走「一个提权进程做完所有事」
 *
 * 分成五次 [WindowsCleanup] 里的独立提权会弹五次 UAC，用户会以为程序出问题了。
 * 这里把所有需要管理员权限的动作塞进**同一个 PowerShell 脚本**，
 * 一次 UAC 全部完成，逐项结果以 JSON 回传。
 *
 * 唯一不进脚本的是第 5 项（`HKCU`），它属于当前用户、不需要提权 ——
 * 而在提权进程里写 `HKCU` 会写到**管理员账户**的注册表去，
 * 那清理的是一个根本没启动过 PawLocker 的用户。
 */
internal object WindowsCleanup {

    /**
     * 提权脚本。
     *
     * 逐项捕获异常而不是让脚本整体崩：一项失败不该让后面的项没机会执行。
     * 输出用 JSON 数组，`$results` 里每项都带 `ok`，便于 Kotlin 侧区分
     * 「清掉了」「本来就没有」「失败了」。
     *
     * 编码先于 `$ErrorActionPreference` 设置，与 `FirewallProbe` 同一个理由：
     * 规则显示名里有中文，不显式设 UTF-8 会按 OEM 码页输出。
     */
    internal fun script(
        providerKey: String,
        clsidKey: String,
        thumbprint: String?,
        port: Int,
        ownRuleName: String,
        exePath: String?,
        deleteByProgram: Boolean,
    ): String {
        val thumb = thumbprint?.filter { !it.isWhitespace() }?.uppercase().orEmpty()
        return """
            [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding ${'$'}false
            ${'$'}ErrorActionPreference = 'Continue'

            ${'$'}results = New-Object System.Collections.ArrayList

            function Add-Result([string]${'$'}key, [bool]${'$'}ok, [string]${'$'}present, [string]${'$'}message) {
                ${'$'}results.Add([ordered]@{
                    key     = ${'$'}key
                    ok      = ${'$'}ok
                    present = ${'$'}present
                    message = ${'$'}message
                })
            }

            function Remove-Tree([string]${'$'}path) {
                # Test-Path 与 Remove-Item 之间没有原子性，但注册表删除在这中间
                # 被并发改动的概率可以忽略；真出异常会被下面的 catch 记成失败。
                if (-not (Test-Path ${'$'}path)) { return 'absent' }
                Remove-Item -Path ${'$'}path -Recurse -Force
                if (Test-Path ${'$'}path) { return 'stuck' } else { return 'removed' }
            }

            # ———— 1 & 2：凭据提供程序注册 ————
            ${'$'}providerPath = ${psQuote("HKLM:\\$providerKey")}
            try {
                ${'$'}r = Remove-Tree ${'$'}providerPath
                if (${'$'}r -eq 'removed') {
                    Add-Result 'credential_provider' ${'$'}true 'before' ${'$'}providerPath
                } elseif (${'$'}r -eq 'absent') {
                    Add-Result 'credential_provider' ${'$'}true 'absent' ${'$'}providerPath
                } else {
                    Add-Result 'credential_provider' ${'$'}false 'before' "删除后注册表项仍然存在：${'$'}providerPath"
                }
            } catch {
                Add-Result 'credential_provider' ${'$'}false 'before' ${'$'}_.Exception.Message
            }

            ${'$'}clsidPath = ${psQuote("HKLM:\\$clsidKey")}
            try {
                ${'$'}r = Remove-Tree ${'$'}clsidPath
                if (${'$'}r -eq 'removed') {
                    Add-Result 'credential_provider_clsid' ${'$'}true 'before' ${'$'}clsidPath
                } elseif (${'$'}r -eq 'absent') {
                    Add-Result 'credential_provider_clsid' ${'$'}true 'absent' ${'$'}clsidPath
                } else {
                    Add-Result 'credential_provider_clsid' ${'$'}false 'before' "删除后注册表项仍然存在：${'$'}clsidPath"
                }
            } catch {
                Add-Result 'credential_provider_clsid' ${'$'}false 'before' ${'$'}_.Exception.Message
            }

            # ———— 4：防火墙入站规则 ————
            # 两条都要删：本程序自己按名字建的，以及 Windows 首次监听时
            # 按程序路径自动建的那条（显示名取自 MSI 产品描述，名字完全不同）。
            #
            # 顺序有讲究：先按名字删 —— 如果它本来就不存在，
            # 接下来按程序路径删仍然成立，两次查询各自独立判断。
            #
            # ⚠️ $deleteByProgram 必须是 false 才走按程序路径那条。
            # 开发期跑在 java.exe 上，而本机有一堆 Java 应用的防火墙规则；
            # 拿 host 进程路径去批量删，会把与 PawLocker 毫无关系的规则一起清掉。
            # 这种误删用户往往事后才发现，而且很难联想到是这里干的。
            try {
                ${'$'}removedNames = @()
                foreach (${'$'}candidate in @(${psQuote(ownRuleName)})) {
                    if (${'$'}candidate -eq '') { continue }
                    ${'$'}hit = @(Get-NetFirewallRule -DisplayName ${'$'}candidate -ErrorAction SilentlyContinue)
                    if (${'$'}hit.Count -eq 0) { continue }
                    ${'$'}hit | Remove-NetFirewallRule -ErrorAction SilentlyContinue
                    ${'$'}left = @(Get-NetFirewallRule -DisplayName ${'$'}candidate -ErrorAction SilentlyContinue)
                    if (${'$'}left.Count -eq 0) {
                        ${'$'}removedNames += ${'$'}candidate
                    }
                }

                ${'$'}exe = ${psQuote(exePath.orEmpty())}
                ${'$'}byProgram = $deleteByProgram
                if (${'$'}byProgram -and ${'$'}exe -ne '') {
                    foreach (${'$'}app in @(Get-NetFirewallApplicationFilter -Program ${'$'}exe -ErrorAction SilentlyContinue)) {
                        ${'$'}rule = ${'$'}app | Get-NetFirewallRule -ErrorAction SilentlyContinue
                        if (${'$'}null -eq ${'$'}rule) { continue }
                        if ([string]${'$'}rule.Direction -ne 'Inbound') { continue }
                        # 只删放行，不动用户自己建的「拒绝」规则 ——
                        # 那条是用户的意图，不是本程序留下的痕迹
                        if ([string]${'$'}rule.Action -ne 'Allow') { continue }
                        ${'$'}name = [string]${'$'}rule.DisplayName
                        ${'$'}rule | Remove-NetFirewallRule -ErrorAction SilentlyContinue
                        if (-not @(Get-NetFirewallRule -DisplayName ${'$'}name -ErrorAction SilentlyContinue).Count) {
                            if (${'$'}removedNames -notcontains ${'$'}name) { ${'$'}removedNames += ${'$'}name }
                        }
                    }
                }

                if (${'$'}removedNames.Count -gt 0) {
                    Add-Result 'firewall' ${'$'}true 'before' (${'$'}removedNames -join '；')
                } else {
                    Add-Result 'firewall' ${'$'}true 'absent' "端口 ${'$'}port 的入站放行规则不存在"
                }
            } catch {
                Add-Result 'firewall' ${'$'}false 'before' ${'$'}_.Exception.Message
            }

            # ———— 3：自签证书信任 ————
            # 指纹为空只可能是「DLL 都不在位了，读不到签名」。
            # 这时不能报失败：那本来就是「没东西要清」，由 Kotlin 侧补成 skipped。
            if (${psQuote(thumb)} -eq '') {
                Add-Result 'certificate' ${'$'}true 'absent' '没有可清理的证书（未读到签名指纹）'
            } else {
                try {
                    ${'$'}removedStores = @()
                    ${'$'}failedStores = @()
                    foreach (${'$'}storeName in @('Root', 'TrustedPublisher')) {
                        ${'$'}store = New-Object System.Security.Cryptography.X509Certificates.X509Store(${'$'}storeName, 'LocalMachine')
                        try {
                            ${'$'}store.Open('ReadWrite')
                            ${'$'}stale = @()
                            foreach (${'$'}cert in ${'$'}store.Certificates) {
                                if ([string]${'$'}cert.Thumbprint -eq ${psQuote(thumb)}) { ${'$'}stale += ${'$'}cert }
                            }
                            foreach (${'$'}cert in ${'$'}stale) { ${'$'}store.Remove(${'$'}cert) }
                            if (${'$'}stale.Count -gt 0) { ${'$'}removedStores += ${'$'}storeName }
                        } catch {
                            ${'$'}failedStores += (${'$'}storeName + ': ' + ${'$'}_.Exception.Message)
                        } finally {
                            ${'$'}store.Close()
                        }
                    }

                    # 删完复查一遍：组策略接管的存储会把证书加回来，
                    # 那种情况下必须报失败而不是「以为成功了」
                    ${'$'}still = @()
                    foreach (${'$'}storeName in @('Root', 'TrustedPublisher')) {
                        ${'$'}store = New-Object System.Security.Cryptography.X509Certificates.X509Store(${'$'}storeName, 'LocalMachine')
                        try {
                            ${'$'}store.Open('ReadOnly')
                            foreach (${'$'}cert in ${'$'}store.Certificates) {
                                if ([string]${'$'}cert.Thumbprint -eq ${psQuote(thumb)}) { ${'$'}still += ${'$'}storeName }
                            }
                        } catch {
                        } finally {
                            ${'$'}store.Close()
                        }
                    }

                    if (${'$'}still.Count -eq 0) {
                        if (${'$'}removedStores.Count -gt 0) {
                            Add-Result 'certificate' ${'$'}true 'before' (${'$'}removedStores -join '、')
                        } else {
                            Add-Result 'certificate' ${'$'}true 'absent' '证书本来就不在受信任存储里'
                        }
                    } else {
                        Add-Result 'certificate' ${'$'}false 'before' (
                            '证书仍在本机受信任存储里' +
                            $(if (${'$'}failedStores.Count) { '（' + (${'$'}failedStores -join '；') + '）' } else { '，可能是组策略接管' })
                        )
                    }
                } catch {
                    Add-Result 'certificate' ${'$'}false 'before' ${'$'}_.Exception.Message
                }
            }

            ${'$'}results | ConvertTo-Json -Compress -Depth 4
        """.trimIndent()
    }

    /**
     * 提权进程的标准输出 → 逐项结果。
     *
     * 空输出（脚本在解析前就崩了）不返回空报告：那样界面会显示「全部已清」，
     * 而实际上一项都没动 —— 比报错坏得多。
     */
    fun run(
        script: String,
        onCancelled: () -> List<CleanupItem>,
    ): List<CleanupItem> {
        val process = try {
            ProcessBuilder(
                "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script,
            ).redirectErrorStream(true).start()
        } catch (error: Throwable) {
            return listOf(
                CleanupItem(
                    label = "提权进程",
                    detail = "powershell.exe",
                    status = CleanupStatus.Failed,
                    note = error.message ?: "无法启动提权进程",
                ),
            )
        }

        val output = process.inputStream.bufferedReader().readText().trim()
        val exitCode = process.waitFor()

        if (output.contains("canceled", ignoreCase = true) ||
            output.contains("cancelled", ignoreCase = true) ||
            output.contains("取消", ignoreCase = true)
        ) {
            return onCancelled()
        }

        return parse(output, exitCode)
    }

    /** 解析脚本输出。包一层 JSON 的情况（单个元素）也要能吃下。 */
    internal fun parse(output: String, exitCode: Int): List<CleanupItem> {
        // ⚠️ 不能逐行找 JSON：脚本输出可能被换行折断（管道缓冲、
        // 控制台宽度、重定向都会导致这件事），逐行找会把一个完整数组
        // 拆成许多行，然后只认到恰好以 `[` 开头 `]` 结尾的那一行 ——
        // 结果是「4 项只解析出 1 项」，而且因为剩下 3 项根本不在返回里，
        // 界面上会显示「已清理 1 项」，用户以为其余的都不用管。
        //
        // 所以改成：先剥掉 BOM，把**整段输出**当一个整体找最外层的括号。
        val text = output.removePrefix("\uFEFF").trim()
        val start = text.indexOf('[')
        val end = text.lastIndexOf(']')

        val raw = when {
            start >= 0 && end > start -> text.substring(start, end + 1)
            else -> {
                // 单元素时 ConvertTo-Json 输出的是对象而不是单元素数组
                val objStart = text.indexOf('{')
                val objEnd = text.lastIndexOf('}')
                if (objStart >= 0 && objEnd > objStart) {
                    "[" + text.substring(objStart, objEnd + 1) + "]"
                } else {
                    null
                }
            }
        }

        if (raw == null) {
            return listOf(
                CleanupItem(
                    label = "提权进程",
                    detail = "退出码 $exitCode",
                    status = CleanupStatus.Failed,
                    note = "清理脚本没有返回可解析的结果：${output.take(300)}",
                ),
            )
        }

        return try {
            json.decodeFromString<List<CleanupRawResult>>(raw).map { it.toItem() }
        } catch (error: Throwable) {
            listOf(
                CleanupItem(
                    label = "提权进程",
                    detail = "退出码 $exitCode",
                    status = CleanupStatus.Failed,
                    note = "无法解析清理结果：${error.message}",
                ),
            )
        }
    }

    /** 脚本输出里的一项的原始形态。 */
    @kotlinx.serialization.Serializable
    internal data class CleanupRawResult(
        val key: String = "",
        val ok: Boolean = false,
        /** `before` = 原本就在；`absent` = 本来就没有。 */
        val present: String = "",
        val message: String = "",
    ) {
        fun toItem(): CleanupItem = CleanupItem(
            label = LABELS[key] ?: key,
            detail = message,
            status = when {
                !ok -> CleanupStatus.Failed
                present == "absent" -> CleanupStatus.Skipped
                else -> CleanupStatus.Done
            },
        )
    }

    private val json = kotlinx.serialization.json.Json { ignoreUnknownKeys = true }

    /** 脚本里的 key 到界面文案的映射。加新项时这里必须同步。 */
    private val LABELS = mapOf(
        "credential_provider" to "锁屏凭据提供程序注册",
        "credential_provider_clsid" to "DLL 类注册（CLSID）",
        "firewall" to "入站防火墙规则",
        "certificate" to "DLL 签名证书信任",
    )

    /** PowerShell 单引号字符串；内部的 `'` 按 PowerShell 规则翻倍。 */
    private fun psQuote(value: String): String = "'" + value.replace("'", "''") + "'"
}
