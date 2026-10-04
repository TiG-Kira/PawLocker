package com.kira.pawlocker.core.platform

import com.sun.jna.platform.win32.Advapi32Util
import com.sun.jna.platform.win32.WinReg
import java.io.File

/**
 * Windows 侧的注册实现。
 *
 * ## 为什么首次启动必须做这一步
 *
 * 「手机解锁电脑」不是一个纯应用内的功能，它需要在系统层面挂上钩子：
 *
 * | 解锁策略 | 需要在 Windows 上注册什么 |
 * |---|---|
 * | 凭据提供程序 | 把 `PawLockerProvider.dll` 注册进 `Credential Providers`，锁屏界面才会出现 PawLocker 磁贴 |
 * | 仅唤醒屏幕 | 无需注册（但建议放行防火墙，否则手机连不进来） |
 * | 自定义命令 | 无需注册 |
 * | 仅记录日志 | 无需注册 |
 * | 任意策略 + 想自动服务 | 写开机启动项 |
 *
 * 这些动作**全部需要用户显式点击**才会发生，不静默执行：
 * 往系统里写凭据提供程序和防火墙规则是有安全含义的操作，
 * 偷偷做完会让用户在完全不知情的情况下改变自己机器的安全边界。
 *
 * ## 提权方式
 *
 * 注册表 HKLM 写入与防火墙规则需要管理员权限，这里统一走
 * `powershell Start-Process -Verb RunAs -Wait` —— 由系统弹 UAC，
 * 而不是要求用户「右键以管理员身份运行整个应用」。
 * 好处是**只有该操作提权**，主程序依然以普通用户权限运行，
 * 这是最小权限原则的直接体现。
 */
class DesktopWindowsRegistrar : WindowsRegistrar {

    override val isSupported: Boolean = true

    // ——————————————————————————————————————————————————————————
    // 体检
    // ——————————————————————————————————————————————————————————

    override fun inspect(port: Int): RegistrationState {
        val exe = executablePath()

        val cpRegistered = registryKeyExistsSafely(CP_PROVIDER_KEY)
        val dllPath = if (cpRegistered) {
            readDefaultRegistryValue(CP_CLSID_KEY + "\\InprocServer32")
        } else {
            null
        }
        val dllPresent = dllPath?.let { File(it).isFile } == true

        // 签名探测要起一次 PowerShell（实测约 1 秒），所以只在「注册了、DLL 也在」
        // 这个唯一有意义的前提下才跑。其余情况下这个问题根本不存在，
        // 白等一秒会让每次体检都像卡了一下 —— 而体检在启动、每次注册操作后都会跑。
        val signature = if (dllPresent) {
            SignerTrust.probe(dllPath)
        } else {
            DllSignature.Unprobed
        }

        val autoStartRegistered = runCatching {
            Advapi32Util.registryValueExists(WinReg.HKEY_CURRENT_USER, RUN_KEY, RUN_VALUE_NAME) &&
                Advapi32Util.registryGetStringValue(WinReg.HKEY_CURRENT_USER, RUN_KEY, RUN_VALUE_NAME)
                    .contains(exe.orEmpty(), ignoreCase = true) &&
                exe != null
        }.getOrDefault(false)

        // 防火墙探测按程序路径查，实测 53–70 ms；只有拿不到 exe 路径时
        // 才会退化成 1 秒级的关键字通配。
        val firewall = FirewallProbe.probe(port, exe)

        return RegistrationState(
            executablePath = exe,
            credentialProviderRegistered = cpRegistered,
            credentialProviderDllPath = dllPath,
            credentialProviderDllPresent = dllPresent,
            credentialProviderSignature = signature,
            autoStartRegistered = autoStartRegistered,
            firewallRulePresent = firewall.allowed,
            firewallRuleOwned = firewall.allowed && firewall.ruleName == firewallRuleName(port),
            firewallRuleName = firewall.ruleName,
            firewallRuleProfiles = firewall.profiles,
            firewallRuleLocalPorts = firewall.localPorts,
            firewallProbed = firewall.probed,
            firewallProbeError = firewall.probeError,
            port = port,
            elevationHint = "注册凭据提供程序、信任签名证书与放行防火墙时都会弹出 UAC，需要你点「是」",
        )
    }

    // ——————————————————————————————————————————————————————————
    // 凭据提供程序
    // ——————————————————————————————————————————————————————————

    override fun registerCredentialProvider(dllPath: String): RegistrationResult {
        val dll = File(dllPath)
        if (!dll.exists()) {
            return RegistrationResult.Failed("找不到 DLL：${dll.absolutePath}。请先编译 PawLockerProvider.dll 或修正路径")
        }

        // 不搬运 DLL：往系统目录写文件是用户的决定，不是安装程序该偷偷做的事
        val regFile = writeRegistryScript(
            """
            [HKEY_LOCAL_MACHINE\$CP_PROVIDER_SUBKEY$GUID]
            @="PawLocker"

            [HKEY_LOCAL_MACHINE\$CP_CLSID_SUBKEY$GUID]
            @="PawLocker 凭据提供程序"

            [HKEY_LOCAL_MACHINE\$CP_CLSID_SUBKEY$GUID\InprocServer32]
            @="${dll.absolutePath.toRegEscaped()}"
            "ThreadingModel"="Apartment"
            """.trimIndent(),
        )

        return try {
            runElevated("reg.exe", listOf("import", regFile.absolutePath))
        } finally {
            regFile.delete()
        }
    }

    override fun unregisterCredentialProvider(): RegistrationResult {
        val provider = runElevated(
            "reg.exe",
            listOf("delete", "HKLM\\$CP_PROVIDER_SUBKEY$GUID", "/f"),
        )
        val clsid = runElevated(
            "reg.exe",
            listOf("delete", "HKLM\\$CP_CLSID_SUBKEY$GUID", "/f"),
        )

        // 两条都「本来就不存在」也算成功：卸载的目标是「现在没有」，而不是「删除动作成功」
        return when {
            provider.isSuccess || clsid.isSuccess -> RegistrationResult.Success
            provider is RegistrationResult.Cancelled || clsid is RegistrationResult.Cancelled ->
                RegistrationResult.Cancelled

            provider is RegistrationResult.Failed && !isNotFound(provider.message) &&
                clsid is RegistrationResult.Failed && !isNotFound(clsid.message) -> provider

            else -> RegistrationResult.Success
        }
    }

    // ——————————————————————————————————————————————————————————
    // 防火墙
    // ——————————————————————————————————————————————————————————

    override fun ensureFirewallRule(port: Int): RegistrationResult = runElevated(
        "netsh.exe",
        listOf(
            "advfirewall", "firewall", "add", "rule",
            "name=${firewallRuleName(port)}",
            "dir=in",
            "action=allow",
            "protocol=TCP",
            "localport=$port",
            "profile=any",
        ),
    )

    override fun removeFirewallRule(port: Int): RegistrationResult {
        val result = runElevated(
            "netsh.exe",
            listOf("advfirewall", "firewall", "delete", "rule", "name=${firewallRuleName(port)}"),
        )
        // 规则不存在时 netsh 会报「找不到」，对卸载而言这已经达到目的
        return if (result is RegistrationResult.Failed && isNotFound(result.message)) {
            RegistrationResult.Success
        } else {
            result
        }
    }

    // ——————————————————————————————————————————————————————————
    // 开机启动
    // ——————————————————————————————————————————————————————————

    override fun setAutoStart(enabled: Boolean): RegistrationResult {
        val exe = executablePath()
            ?: return RegistrationResult.Failed("无法确定本程序路径，无法写开机启动项")

        return runCatching {
            if (enabled) {
                Advapi32Util.registrySetStringValue(
                    WinReg.HKEY_CURRENT_USER,
                    RUN_KEY,
                    RUN_VALUE_NAME,
                    "\"$exe\"",
                )
                PlatformEnv.log(TAG, "已注册开机启动：$exe")
            } else {
                if (Advapi32Util.registryValueExists(WinReg.HKEY_CURRENT_USER, RUN_KEY, RUN_VALUE_NAME)) {
                    Advapi32Util.registryDeleteValue(WinReg.HKEY_CURRENT_USER, RUN_KEY, RUN_VALUE_NAME)
                }
                PlatformEnv.log(TAG, "已取消开机启动")
            }
            RegistrationResult.Success
        }.getOrElse { error ->
            RegistrationResult.Failed("写入启动项失败：${error.message}")
        }
    }

    /**
     * 建议的 DLL 位置。
     *
     * ## 为什么是「读出来的」而不是硬编码
     *
     * 打包时 DLL 由 Compose 的 `appResourcesRootDir` 机制带进安装目录，落在
     * **`<安装目录>\app\resources\`**（不是安装根目录）—— 这是 jpackage 的固定布局：
     * 它会把资源目录设成一个系统属性
     *
     *     -Dcompose.application.resources.dir=$APPDIR\resources
     *
     * 写进生成的 `PawLocker.cfg`。所以运行时直接读这个属性就知道 DLL 在哪，
     * 不用去猜安装路径、也不怕用户装到非默认目录。
     *
     * 退回的顺序是有讲究的：
     *  1. 系统属性 —— 打包安装的正式路径，最准；
     *  2. 开发期（`gradle run`）没有那个属性，用仓库里的构建产物；
     *  3. 都没有时给 Program Files 下的常规位置，纯粹是为了界面上有个像样的初始值，
     *     用户能自己改。
     */
    override fun suggestedCredentialProviderPath(): String {
        packagedCredentialProviderDll()?.let { return it }

        // 开发期：从工作目录往上找仓库根，再拼构建产物路径
        generateSequence(File(System.getProperty("user.dir") ?: ".").absoluteFile) { it.parentFile }
            .take(6)
            .firstOrNull { File(it, "credential-provider/build/PawLockerProvider.dll").isFile }
            ?.let { return File(it, "credential-provider/build/PawLockerProvider.dll").absolutePath }

        return "C:\\Program Files\\PawLocker\\PawLockerProvider.dll"
    }

    /**
     * 随安装包分发的 DLL 路径，取不到时为 null。
     *
     * `compose.application.resources.dir` 指向 `<安装目录>\app\resources`，
     * 那里是本程序额外资源的落点（jpackage 只把 jar 和启动器放在 `app\` 直属下）。
     */
    internal fun packagedCredentialProviderDll(): String? {
        val resourceDir = System.getProperty(RESOURCES_DIR_PROPERTY)
            ?.takeIf { it.isNotBlank() }
            ?: return null

        val dll = File(resourceDir, CREDENTIAL_PROVIDER_DLL_NAME)
        return dll.absolutePath.takeIf { dll.isFile }
    }

    // ——————————————————————————————————————————————————————————
    // 代码签名证书信任
    // ——————————————————————————————————————————————————————————

    /**
     * 把 DLL 的签名证书装进本机受信任存储。
     *
     * 「怎么从 DLL 里取出证书、往哪个存储写、怎么读回来验证」都在 [SignerTrust]，
     * 这里只负责回答一个问题：当前注册的 DLL 是哪一个。
     */
    override fun trustDllSignerCertificate(thumbprint: String): RegistrationResult {
        val dll = registeredDllPath()
            ?: return RegistrationResult.Failed(
                "还没注册凭据提供程序，无法确定要信任哪张证书。请先完成上一项。",
            )
        return SignerTrust.trust(dll, thumbprint)
    }

    override fun revokeDllSignerCertificate(thumbprint: String): RegistrationResult =
        SignerTrust.revoke(registeredDllPath(), thumbprint)

    // ——————————————————————————————————————————————————————————
    // 内部
    // ——————————————————————————————————————————————————————————

    /**
     * 本程序的真实可执行文件路径。
     *
     * `jpackage.app-path` 是 jpackage 打包后的启动器路径，最准；
     * 开发期（`gradle run`）没有这个属性，退回进程自身的命令行首项。
     */
    private fun executablePath(): String? =
        System.getProperty("jpackage.app-path")
            ?: ProcessHandle.current().info().command().orElse(null)

    /**
     * 本程序**创建**规则时用的名字。
     *
     * 只用于 [ensureFirewallRule] / [removeFirewallRule]，**不再用于检测** ——
     * 检测改由 [FirewallProbe] 按程序路径做，因为 Windows 自己
     * 在应用首次监听时生成的那条规则用的是另一个名字（取自安装包的产品描述），
     * 拿这个名字去找它永远找不到。
     */
    private fun firewallRuleName(port: Int) = "PawLocker (TCP $port)"

    private fun registryKeyExistsSafely(path: String): Boolean =
        runCatching { Advapi32Util.registryKeyExists(WinReg.HKEY_LOCAL_MACHINE, path) }
            .getOrDefault(false)

    private fun readDefaultRegistryValue(path: String): String? =
        runCatching { Advapi32Util.registryGetStringValue(WinReg.HKEY_LOCAL_MACHINE, path, "") }
            .getOrNull()

    /**
     * 已注册的凭据提供程序 DLL 路径。
     *
     * 从 CLSID 的 `InprocServer32` 默认值读 —— 也就是 Windows 实际会去加载的那个路径。
     * 不用配置里记的路径：两者可能不一致（用户改过配置，或手动改了注册表），
     * 而要做签名校验和信任的对象必须**跟 Windows 实际加载的一致**，
     * 否则我们会给一个根本没被加载的 DLL 做信任，真正被加载的那个仍然被拒。
     */
    private fun registeredDllPath(): String? =
        readDefaultRegistryValue(CP_CLSID_KEY + "\\InprocServer32")?.takeIf { it.isNotBlank() }

    /** 写一份 UTF-16LE + BOM 的 `.reg` 脚本，交给 `reg import` 执行。 */
    private fun writeRegistryScript(body: String): File {
        val header = "Windows Registry Editor Version 5.00\r\n\r\n"
        val text = header + body.replace("\n", "\r\n") + "\r\n"
        val bom = byteArrayOf(0xFF.toByte(), 0xFE.toByte())
        return File(PlatformEnv.dataDir, "pawlocker-register.reg").apply {
            parentFile?.mkdirs()
            writeBytes(bom + text.toByteArray(Charsets.UTF_16LE))
        }
    }

    private fun String.toRegEscaped(): String = replace("\\", "\\\\")

    private fun isNotFound(message: String): Boolean =
        message.contains("找不到", ignoreCase = true) ||
            message.contains("not found", ignoreCase = true) ||
            message.contains("找不到指定的注册表项", ignoreCase = true) ||
            message.contains("unable to find", ignoreCase = true)

    /**
     * 以管理员身份运行一条命令。
     *
     * 用 PowerShell 的 `Start-Process -Verb RunAs` 而不是 JNA 的 `ShellExecuteEx`：
     * 前者由系统负责 UAC 交互与等待，我们只需要读退出码；
     * 后者要自己处理 `SHELLEXECUTEINFO` 结构体与消息循环，出错面大得多。
     */
    private fun runElevated(exe: String, args: List<String>): RegistrationResult {
        val argumentList = args.joinToString(",") { "'" + it.replace("'", "''") + "'" }
        val script = buildString {
            append("try { ")
            append("\$p = Start-Process -FilePath '").append(exe.replace("'", "''"))
            append("' -ArgumentList @(").append(argumentList)
            append(") -Verb RunAs -Wait -PassThru; ")
            append("exit \$p.ExitCode ")
            append("} catch { Write-Output \$_.Exception.Message; exit 1 }")
        }

        return try {
            val process = ProcessBuilder(
                "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script,
            ).redirectErrorStream(true).start()

            val output = process.inputStream.bufferedReader().readText().trim()
            val exitCode = process.waitFor()

            when {
                exitCode == 0 -> RegistrationResult.Success
                isCancelledByUser(output) -> RegistrationResult.Cancelled
                else -> RegistrationResult.Failed(
                    output.ifBlank { "命令执行失败，退出码 $exitCode（可能需要管理员权限）" },
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

    internal companion object {
        const val TAG = "WindowsRegistrar"

        /**
         * PawLocker 凭据提供程序的 CLSID。
         *
         * 这个 GUID 一旦发布就不能改 —— 已注册的机器升级后会找不到自己的项。
         * 用固定常量而不是随机生成，正是为了让「升级覆盖安装」能正常工作。
         */
        const val GUID = "{6F3A1C48-9D2B-4E77-A5C1-8B0E4D7F2315}"

        const val CP_PROVIDER_SUBKEY =
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\"
        const val CP_CLSID_SUBKEY = "SOFTWARE\\Classes\\CLSID\\"

        val CP_PROVIDER_KEY = CP_PROVIDER_SUBKEY + GUID
        val CP_CLSID_KEY = CP_CLSID_SUBKEY + GUID

        const val RUN_KEY = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        const val RUN_VALUE_NAME = "PawLocker"

        /** 凭据提供程序 DLL 的文件名。与 `windowsApp/resources/windows/` 里那个一致。 */
        const val CREDENTIAL_PROVIDER_DLL_NAME = "PawLockerProvider.dll"

        /**
         * jpackage 写进 `PawLocker.cfg` 的资源目录属性。
         *
         * 值形如 `<安装根>\app\resources`。改这个名字之前，
         * 先去 MSI 解包里核对 `app/PawLocker.cfg` 的 `[JavaOptions]` 段 ——
         * 两边必须逐字一致，否则打包安装后会定位不到 DLL，
         * 而开发期（不设这个属性、走仓库分支）完全看不出问题。
         */
        const val RESOURCES_DIR_PROPERTY = "compose.application.resources.dir"
    }
}

actual fun createWindowsRegistrar(): WindowsRegistrar = DesktopWindowsRegistrar()
