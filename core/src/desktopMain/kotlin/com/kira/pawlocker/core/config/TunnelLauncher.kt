package com.kira.pawlocker.core.config

import com.kira.pawlocker.core.platform.PlatformEnv
import java.io.File

/**
 * Windows 端的内网穿透托管实现。
 *
 * 把 `frpc.toml` 写到 `%APPDATA%\PawLocker\`，再用用户指定的 `frpc.exe`
 * 拉起子进程。子进程 stdout/stderr 重定向进应用日志，
 * 这样 frp 的连接失败原因能直接在「日志」页看到，不用去翻别的窗口。
 */
class DesktopTunnelLauncher : TunnelLauncher {

    private var process: Process? = null

    override val isSupported: Boolean = true

    override fun isRunning(): Boolean = process?.isAlive == true

    override fun configFilePath(): String = configFile().absolutePath

    override fun start(config: AppConfig): String? {
        stop()

        val tunnel = config.tunnel
        if (!tunnel.enabled) return null
        if (tunnel.serverAddr.isBlank()) return "未填写 frp 服务端地址"
        if (tunnel.frpcPath.isBlank()) {
            return "未指定 frpc 可执行文件路径。请下载 frp 客户端后，在设置页填入 frpc.exe 的完整路径"
        }

        val executable = File(tunnel.frpcPath)
        if (!executable.exists()) return "找不到 frpc：${executable.absolutePath}"

        // 配置文件固定落在数据目录，避免路径里出现中文或空格导致 frpc 解析异常
        val configFile = configFile()
        configFile.writeText(FrpcConfigWriter.toToml(config))

        return runCatching {
            val builder = ProcessBuilder(executable.absolutePath, "-c", configFile.absolutePath)
            builder.redirectErrorStream(true)
            val started = builder.start()
            process = started

            // 后台泵出日志，前缀 [frpc] 便于在日志页过滤
            Thread({
                runCatching {
                    started.inputStream.bufferedReader().forEachLine { line ->
                        PlatformEnv.log("frpc", line)
                    }
                }
            }, "pawlocker-frpc-log").apply { isDaemon = true }.start()

            PlatformEnv.log(TAG, "frpc 已启动：${executable.absolutePath}")
            null
        }.getOrElse { error ->
            "启动 frpc 失败：${error.message}"
        }
    }

    override fun stop() {
        val current = process ?: return
        process = null
        runCatching {
            current.destroy()
            if (!current.waitFor(3, java.util.concurrent.TimeUnit.SECONDS)) {
                current.destroyForcibly()
            }
            PlatformEnv.log(TAG, "frpc 已停止")
        }
    }

    private fun configFile(): File =
        File(PlatformEnv.dataDir, "frpc.toml").apply {
            parentFile?.mkdirs()
        }

    private companion object {
        const val TAG = "TunnelLauncher"
    }
}

actual fun createTunnelLauncher(): TunnelLauncher = DesktopTunnelLauncher()
