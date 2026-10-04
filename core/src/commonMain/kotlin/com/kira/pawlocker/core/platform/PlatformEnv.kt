package com.kira.pawlocker.core.platform

/**
 * 平台环境适配层。
 *
 * Android 侧需要在进程启动早期调用 [init] 传入 `Context`，
 * Windows 侧 [init] 可以忽略入参（数据目录直接取自 `%APPDATA%`）。
 */
expect object PlatformEnv {

    val platformName: String

    fun init(handle: Any?)

    /** 应用数据目录，绝对路径。 */
    val dataDir: String

    /** 该平台是否具备「私钥不可导出」的硬件密钥后端。 */
    val hasHardwareKeyStore: Boolean

    fun currentTimeMillis(): Long

    /**
     * 本机当前可用的 IPv4 地址（已过滤回环与虚拟网卡）。
     * 配对时这些地址会作为「局域网直连」候选下发给手机。
     */
    fun localIpv4Addresses(): List<String>

    /**
     * 写入「静态加密」文件。
     *  - Windows：内容先经 DPAPI（当前用户）封装再落盘
     *  - Android：写入应用私有目录（受系统沙箱 + 全盘加密保护）
     */
    fun writeSecure(name: String, data: ByteArray)

    fun readSecure(name: String): ByteArray?

    fun deleteSecure(name: String)

    /** 应用日志输出，Windows 侧同时写文件，Android 侧走 logcat。 */
    fun log(tag: String, message: String)
}
