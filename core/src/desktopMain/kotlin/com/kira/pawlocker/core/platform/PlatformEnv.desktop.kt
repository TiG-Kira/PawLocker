package com.kira.pawlocker.core.platform

import com.sun.jna.platform.win32.Crypt32Util
import java.io.File
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermission

/**
 * Windows DPAPI（`CryptProtectData` / `CryptUnprotectData`）。
 *
 * 用当前用户作用域加密，含义是：**同一台机器上的其他用户、以及把文件拷走的攻击者
 * 都无法解密**，只有当前登录用户的 DPAPI 主密钥可以。
 *
 * 这也是为什么 PawLocker 的信任列表与身份私钥可以直接放在 `%APPDATA%` 下 ——
 * 明文只有进程内存里存在，落盘的永远是密文。
 */
internal object Dpapi {

    val available: Boolean = runCatching {
        System.getProperty("os.name").orEmpty().startsWith("Windows")
    }.getOrDefault(false)

    fun protect(plaintext: ByteArray): ByteArray = if (available) {
        Crypt32Util.cryptProtectData(plaintext)
    } else {
        // 非 Windows（开发机上的 Linux/macOS 跑 desktop target）退化为明文，
        // 生产环境只会是 Windows，所以这里只保证不崩
        plaintext
    }

    fun unprotect(ciphertext: ByteArray): ByteArray = if (available) {
        Crypt32Util.cryptUnprotectData(ciphertext)
    } else {
        ciphertext
    }
}

/**
 * Windows 平台环境。
 *
 * 数据目录：`%APPDATA%\PawLocker`
 *  - `secure\` —— DPAPI 保护的内容（信任列表、身份私钥）
 *  - `logs\`   —— 运行日志
 *  - `frpc.toml` —— 自动生成的内网穿透客户端配置
 */
actual object PlatformEnv {

    private var overrideRoot: String? = null

    actual val platformName: String = "Windows"

    actual fun init(handle: Any?) {
        // 单测可以传入临时目录
        if (handle is String && handle.isNotBlank()) overrideRoot = handle
    }

    actual val dataDir: String
        get() {
            overrideRoot?.let { return File(it).apply { mkdirs() }.absolutePath }
            val appData = System.getenv("APPDATA")
                ?: System.getProperty("user.home")
            return File(appData, "PawLocker").apply { mkdirs() }.absolutePath
        }

    /** Windows 没有 AndroidKeyStore，但 DPAPI 由操作系统密钥材料保护。 */
    actual val hasHardwareKeyStore: Boolean = Dpapi.available

    actual fun currentTimeMillis(): Long = System.currentTimeMillis()

    /**
     * 枚举本机 IPv4 地址，用作「局域网直连」候选下发给手机。
     *
     * 过滤规则全部集中在 [LanAddressPolicy.isAdvertisable] 里 ——
     * 这段逻辑出错的代价是「手机连到一个永远连不通的地址，卡到超时才换下一个」，
     * 用户看到的现象就是「扫码之后没反应」，而且两端都没有任何错误提示，
     * 属于必须能在单测里复现的那类问题。
     */
    actual fun localIpv4Addresses(): List<String> = try {
        java.net.NetworkInterface.getNetworkInterfaces().toList()
            .filter { it.isUp && !it.isLoopback }
            .flatMap { nic -> nic.inetAddresses.toList().map { nic to it } }
            .filter { (nic, address) ->
                address is java.net.Inet4Address &&
                    !address.isLoopbackAddress &&
                    !address.isLinkLocalAddress &&
                    LanAddressPolicy.isAdvertisable(
                        networkInterfaceName = nic.name,
                        displayName = nic.displayName,
                        isVirtual = nic.isVirtual,
                        hostAddress = address.hostAddress.orEmpty(),
                    )
            }
            .map { (_, address) -> address.hostAddress.orEmpty().substringBefore('%') }
            .filter { it.isNotBlank() }
            .distinctBy { it }
            // 优先级高的排前面，手机就按这个顺序试
            .sortedWith(compareBy { LanAddressPolicy.advertisabilityRank(it) })
    } catch (error: Throwable) {
        log("PlatformEnv", "枚举本机地址失败: ${error.message}")
        emptyList()
    }

    actual fun log(tag: String, message: String) {
        val line = "[${java.time.LocalDateTime.now()}] [$tag] $message"
        println(line)
        runCatching {
            val logFile = File(File(dataDir, "logs").apply { mkdirs() }, "pawlocker.log")
            if (logFile.length() > 5L * 1024 * 1024) logFile.writeText("")
            logFile.appendText(line + System.lineSeparator())
        }
    }

    actual fun writeSecure(name: String, data: ByteArray) {
        val file = fileFor(name)
        val sealed = Dpapi.protect(data)
        file.writeBytes(sealed)
        restrictToCurrentUser(file)
    }

    actual fun readSecure(name: String): ByteArray? {
        val file = fileFor(name)
        if (!file.exists()) return null
        return runCatching { Dpapi.unprotect(file.readBytes()) }.getOrElse { error ->
            log("PlatformEnv", "解密 $name 失败：${error.message}")
            null
        }
    }

    actual fun deleteSecure(name: String) {
        fileFor(name).delete()
    }

    private const val SECURE_DIR = "secure"

    private fun fileFor(name: String): File =
        File(File(dataDir, SECURE_DIR).apply { mkdirs() }, name)

    /**
     * 把文件 ACL 收紧到「仅当前用户 + SYSTEM」。
     * DPAPI 已经保证了机密性，这一步是额外的纵深防御 ——
     * 防止同机其他管理员进程随意读取（虽然它们拿不到当前用户的 DPAPI 主密钥）。
     */
    private fun restrictToCurrentUser(file: File) {
        runCatching {
            val path = file.toPath()
            val supported = path.fileSystem.supportedFileAttributeViews().contains("posix")
            if (supported) {
                Files.setPosixFilePermissions(
                    path,
                    setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE),
                )
            } else {
                // Windows：清空继承并只授予当前用户
                val user = System.getProperty("user.name") ?: return@runCatching
                ProcessBuilder(
                    "icacls", file.absolutePath,
                    "/inheritance:r",
                    "/grant:r", "$user:(R,W)",
                ).redirectErrorStream(true).start().waitFor()
            }
        }
    }
}

/**
 * 本机当前 Windows 账户身份 —— 三元绑定链的中间一环。
 *
 * 结果缓存：解析 SID 要拉一个 `whoami` 进程，而账户在进程生命周期内不会变。
 *
 * 用 `whoami.exe` 而不是 JNA 的令牌 API：`whoami` 在所有受支持的 Windows 上都在，
 * 输出里的 SID 文本与系统语言无关；令牌 API 则要自己处理 `TOKEN_USER`
 * 结构体布局与 PSID 释放，出错面更大 —— 而这里并不需要那种精度。
 */
private val cachedUserIdentity: UserIdentity by lazy {
    val accountName = System.getProperty("user.name").orEmpty()
    val sid = if (accountName.isBlank()) "" else runCatching {
        val process = ProcessBuilder("whoami", "/user", "/fo", "csv", "/nh")
            .redirectErrorStream(true)
            .start()
        val finished = process.waitFor(5, java.util.concurrent.TimeUnit.SECONDS)
        if (!finished) {
            process.destroyForcibly()
            ""
        } else {
            extractSidFrom(process.inputStream.bufferedReader().readText())
        }
    }.getOrDefault("")

    if (sid.isBlank()) {
        // 注意：这段代码在 `PlatformEnv` 对象之外，`log` 必须带接收者显式调用
        PlatformEnv.log("PlatformEnv", "未能解析当前账户 SID，绑定链将退化为按账户名匹配")
    }
    UserIdentity(sid = sid, accountName = accountName, displayName = accountName)
}

actual fun currentUserIdentity(): UserIdentity = cachedUserIdentity
