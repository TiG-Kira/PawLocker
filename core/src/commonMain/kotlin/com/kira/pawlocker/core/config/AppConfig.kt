package com.kira.pawlocker.core.config

import com.kira.pawlocker.core.platform.PlatformEnv
import com.kira.pawlocker.core.protocol.Endpoint
import com.kira.pawlocker.core.protocol.Protocol
import com.kira.pawlocker.core.protocol.TransportKind
import kotlinx.serialization.Serializable

/**
 * Windows 端配置。
 *
 * 落盘位置：`%APPDATA%\PawLocker\secure\config.json`（经 DPAPI 加密），
 * 因为里面含 frp 的 `auth.token`。
 */
@Serializable
data class AppConfig(

    // ———— 监听 ————
    val listenPort: Int = Protocol.DEFAULT_PORT,
    val bindAddress: String = "0.0.0.0",

    // ———— 局域网 ————
    /** 配对时是否把本机内网 IP 一并发给手机。 */
    val advertiseLanAddresses: Boolean = true,
    /** 多网卡机器上手工指定要用哪个地址；留空表示自动枚举全部。 */
    val preferredLanHost: String = "",

    // ———— 内网穿透 ————
    val tunnel: TunnelConfig = TunnelConfig(),

    // ———— 虚拟组网 ————
    val overlay: OverlayConfig = OverlayConfig(),

    // ———— 解锁方式 ————
    val unlockStrategy: WindowsUnlockStrategy = WindowsUnlockStrategy.DRY_RUN,
    /** [WindowsUnlockStrategy.CUSTOM_COMMAND] 下要执行的命令，支持 `{action}` 占位。 */
    val customUnlockCommand: String = "",

    // ———— 首次启动 ————
    /**
     * 首次启动注册向导是否已完成。
     *
     * 只在用户**主动**点过向导里的按钮后才置位 —— 这不是「注册状态」的镜像，
     * 而是「用户已经知情并做过决定」的记录。注册状态随时可能因为系统重装、
     * 手动删注册表而失效，那种情况由体检结果驱动重新提示，与本字段无关。
     */
    val setupCompleted: Boolean = false,
    /**
     * 用户填写的凭据提供程序 DLL 路径。
     * 记下来是为了让「重新注册」不用每次重填，而不是用来判断文件是否存在。
     */
    val credentialProviderDllPath: String = "",

    // ———— 行为 ————
    /** 开机自动启动监听服务。 */
    val autoStartService: Boolean = true,
    /** 是否允许在 Windows 锁屏界面唤起 PawLocker 登录窗口。 */
    val enableLockScreenTile: Boolean = true,
    /** 收到解锁指令后是否还要在本机再确认一次（默认关闭，否则失去「远程解锁」的意义）。 */
    val requireLocalConfirmation: Boolean = false,
    /** 是否记录解锁历史。 */
    val keepActivityLog: Boolean = true,
) {

    fun normalized(): AppConfig = copy(
        listenPort = migrateListenPort(listenPort),
        tunnel = tunnel.normalized(),
    )

    /**
     * 把仍然停在旧默认值的监听端口升到当前默认值。
     *
     * 只在值**恰好等于** [Protocol.LEGACY_DEFAULT_PORT] 时才动 ——
     * 用户手动指定的其他端口一律原样保留。
     *
     * 已知取舍：老配置里没有「这个值是不是默认值」的记录，所以区分不了
     * 「用户从没改过」和「用户主动选了 9898」。后者会被一并升走。
     * 但两个方向的误伤并不对称：把 9898 升走，正好是这次改端口想要的结果；
     * 而把用户自选的某个端口改掉，则会悄无声息地让他的手机再也连不上。
     * 所以迁移范围严格限制在旧默认值这一个点上，不做任何「笼统的旧值修正」。
     */
    private fun migrateListenPort(current: Int): Int = when {
        current == Protocol.LEGACY_DEFAULT_PORT -> Protocol.DEFAULT_PORT
        current in 1..65535 -> current
        else -> Protocol.DEFAULT_PORT
    }
}

@Serializable
data class TunnelConfig(
    val enabled: Boolean = false,
    /** 目前只内置 frp；字段保留为字符串，方便后续接入其他方案而不破坏配置文件兼容性。 */
    val provider: String = PROVIDER_FRP,

    /** frps 服务端地址，例如 `frp.example.com`。 */
    val serverAddr: String = "",
    /** frps 控制端口，frp 默认 7000。 */
    val serverPort: Int = 7000,
    /** 与服务端 `auth.token` 对应的共享密钥。 */
    val authToken: String = "",

    /**
     * 公网映射方式二选一：
     *  - [remotePort]：占用服务端一个固定端口（TCP 端口映射）
     *  - [subdomain]：走服务端配置好的子域（需要 frps 配 `subDomainHost`）
     */
    val remotePort: Int = 0,
    val subdomain: String = "",

    /** 是否启用 frp 自身的 TLS（`transport.tls.enable`）。 */
    val tls: Boolean = true,

    /** 本机 frpc 可执行文件路径；留空则只生成配置文件，由用户自行启动。 */
    val frpcPath: String = "",
    /** 启动应用时自动拉起 frpc 子进程。 */
    val autoStart: Boolean = true,

    // ———— 以下由程序推导，用户手填可覆盖 ————
    /** 手机实际连接的域名/IP，留空则用 [serverAddr]。 */
    val publicHost: String = "",
    /** 手机实际连接的端口，留空则由 [remotePort] 或 [serverPort] 推导。 */
    val publicPort: Int = 0,
) {

    val effectivePublicHost: String get() = publicHost.ifBlank { serverAddr }
    val effectivePublicPort: Int
        get() = when {
            publicPort > 0 -> publicPort
            remotePort > 0 -> remotePort
            else -> serverPort
        }

    fun normalized(): TunnelConfig = copy(
        serverPort = serverPort.takeIf { it in 1..65535 } ?: 7000,
        remotePort = if (remotePort in 1..65535) remotePort else 0,
    )

    companion object {
        const val PROVIDER_FRP = "frp"
    }
}

@Serializable
data class OverlayConfig(
    val enabled: Boolean = false,
    val provider: OverlayProvider = OverlayProvider.Tailscale,
    /**
     * 虚拟网卡上的地址或机器名，例如 Tailscale 的 `100.64.12.34`
     * 或 MagicDNS 名 `desktop-kira.tailnet-xxxx.ts.net`。
     */
    val virtualHost: String = "",
)

@Serializable
enum class OverlayProvider(val displayName: String, val hint: String) {
    Tailscale("Tailscale", "填 Tailscale 分配的 100.x.y.z 地址或 MagicDNS 名称"),
    ZeroTier("ZeroTier", "填 ZeroTier 网络的 10.x / 172.x 地址"),
    WireGuard("WireGuard", "填 WireGuard 接口地址"),
    Other("其他", "填虚拟网卡上的可达地址"),
}

/**
 * 把配置翻译成「手机该连哪一个地址」的候选列表。
 *
 * 顺序即优先级：局域网最快 → 虚拟组网次之 → 公网隧道兜底。
 * 手机端拿到列表后会按这个顺序串行尝试，连上第一个可用的就停。
 */
object EndpointResolver {

    fun resolve(config: AppConfig, boundPort: Int): List<Endpoint> = buildList {
        val port = boundPort.takeIf { it > 0 } ?: config.listenPort

        // ① 局域网直连
        if (config.advertiseLanAddresses) {
            val hosts = if (config.preferredLanHost.isNotBlank()) {
                listOf(config.preferredLanHost.trim())
            } else {
                PlatformEnv.localIpv4Addresses()
            }
            hosts.forEach { host ->
                add(Endpoint(TransportKind.LAN, host, port, "局域网"))
            }
        }

        // ② 虚拟组网
        if (config.overlay.enabled && config.overlay.virtualHost.isNotBlank()) {
            add(
                Endpoint(
                    kind = TransportKind.OVERLAY,
                    host = config.overlay.virtualHost.trim(),
                    port = port,
                    label = config.overlay.provider.displayName,
                ),
            )
        }

        // ③ 内网穿透
        if (config.tunnel.enabled && config.tunnel.effectivePublicHost.isNotBlank()) {
            add(
                Endpoint(
                    kind = TransportKind.TUNNEL,
                    host = config.tunnel.effectivePublicHost.trim(),
                    port = config.tunnel.effectivePublicPort,
                    label = "内网穿透（${config.tunnel.provider}）",
                ),
            )
        }
    }.distinctBy { it.kind to it.display }
        .sortedWith(Endpoint.preferredOrder)
}

/**
 * frpc 配置生成器。
 *
 * 不把 frp 的配置格式硬编码进协议层，而是生成一份标准 TOML 交给 frpc 自己解析 ——
 * 这样 frp 升级新增字段时，本应用不需要跟着改。
 */
object FrpcConfigWriter {

    fun toToml(config: AppConfig): String {
        val tunnel = config.tunnel
        val localPort = config.listenPort
        val proxyName = "pawlocker-${config.listenPort}"

        return buildString {
            appendLine("# 由 PawLocker 自动生成，请勿手工编辑 —— 修改会在下次启动时被覆盖")
            appendLine("# 如需自定义，请复制成独立文件并改用 `frpc -c your.toml` 启动")
            appendLine()
            appendLine("serverAddr = \"${tunnel.serverAddr}\"")
            appendLine("serverPort = ${tunnel.serverPort}")
            appendLine("loginFailExit = false")
            if (tunnel.authToken.isNotBlank()) {
                appendLine()
                appendLine("[auth]")
                appendLine("method = \"token\"")
                appendLine("token = \"${tunnel.authToken}\"")
            }
            if (tunnel.tls) {
                appendLine()
                appendLine("[transport.tls]")
                appendLine("enable = true")
            }
            appendLine()
            appendLine("[[proxies]]")
            appendLine("name = \"$proxyName\"")
            appendLine("type = \"tcp\"")
            appendLine("localIP = \"127.0.0.1\"")
            appendLine("localPort = $localPort")
            if (tunnel.subdomain.isNotBlank()) {
                appendLine("subdomain = \"${tunnel.subdomain}\"")
            } else {
                appendLine("remotePort = ${if (tunnel.remotePort > 0) tunnel.remotePort else localPort}")
            }
            appendLine("transport.useEncryption = true")
            appendLine("transport.useCompression = false")
        }
    }
}

/**
 * 配置文件读写。用 [PlatformEnv] 的静态加密通道，
 * 因为 frp token 属于凭据，不该明文躺在磁盘上。
 */
class ConfigStore(private val fileName: String = "config.json") {

    private val json = kotlinx.serialization.json.Json {
        prettyPrint = true
        encodeDefaults = true
        ignoreUnknownKeys = true
    }

    fun load(): AppConfig {
        val raw = PlatformEnv.readSecure(fileName) ?: return AppConfig()
        return runCatching { json.decodeFromString(AppConfig.serializer(), raw.decodeToString()) }
            .getOrElse { error ->
                PlatformEnv.log("ConfigStore", "配置损坏，回退到默认值：${error.message}")
                AppConfig()
            }
            .normalized()
    }

    fun save(config: AppConfig) {
        val text = json.encodeToString(AppConfig.serializer(), config.normalized())
        PlatformEnv.writeSecure(fileName, text.encodeToByteArray())
    }
}
