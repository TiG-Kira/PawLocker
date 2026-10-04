package com.kira.pawlocker.core.config

/**
 * 内网穿透客户端进程的启动/停止。
 *
 * 设计取向：**只做「写配置 + 拉起进程」，不内置 frpc 二进制**。
 * 理由：内置二进制意味着要跟着 frp 的发布节奏更新、要处理各平台的架构差异、
 * 还要承担一个「打包了第三方可执行文件」带来的安全审查成本。
 * 让用户自己下载 frpc、把路径填进设置页，是把复杂度留给最合适的位置。
 */
interface TunnelLauncher {

    /** 该平台是否支持托管穿透进程。 */
    val isSupported: Boolean

    /** 是否正在运行。 */
    fun isRunning(): Boolean

    /**
     * 生成配置并启动隧道进程。
     * @return null 表示成功，否则返回人类可读的失败原因
     */
    fun start(config: AppConfig): String?

    fun stop()

    /** 隧道配置文件的绝对路径，供设置页展示「配置写在哪」。 */
    fun configFilePath(): String
}

/**
 * 拿一个当前平台的实现。
 *
 * Android 端拿到的是 [UnsupportedTunnelLauncher] ——
 * 手机是**连接方**，不承担被穿透的服务端角色。
 */
expect fun createTunnelLauncher(): TunnelLauncher

/**
 * 不做任何事的实现。
 *
 * 放在 `commonMain` 而不是各平台的 `actual` 里：它没有任何平台依赖，
 * 两个平台共享同一份代码，避免出现「Android 的禁用实现和桌面的禁用实现
 * 行为不一致」这种毫无意义的差异。
 */
class UnsupportedTunnelLauncher : TunnelLauncher {

    override val isSupported: Boolean = false

    override fun isRunning(): Boolean = false

    override fun start(config: AppConfig): String? = "当前平台不支持托管穿透进程"

    override fun stop() = Unit

    override fun configFilePath(): String = ""
}
