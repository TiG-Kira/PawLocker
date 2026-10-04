package com.kira.pawlocker.core.net

import com.kira.pawlocker.core.protocol.Endpoint
import com.kira.pawlocker.core.protocol.WireMessage

/**
 * 一条已建立的双向连接。
 *
 * 生命周期由调用方负责，[close] 必须幂等。
 * [receive] 返回 null 表示对端正常关闭；异常表示连接损坏。
 */
interface Connection {

    val remoteDescription: String

    suspend fun send(message: WireMessage)

    suspend fun receive(): WireMessage?

    fun close()
}

interface ServerHandle {
    val boundPort: Int
    fun close()
}

/**
 * 传输层抽象。
 *
 * 这里**不做 TLS**，理由是经过权衡的：
 *  1. 业务载荷已经被 E2E 的 AES-256-GCM 保护，密钥来自 ECDH，不依赖传输层
 *  2. 主机地址是动态的（内网 IP / frp 域名 / 虚拟组网 IP），自签证书的轮换与固定非常难做
 *  3. 引入 TLS 会让「证书不匹配」变成最常见的用户报错，收益却接近于零
 *
 * 如果部署环境有合规要求，可以在 frp 那一跳单独加 TLS（frpc 支持 `transport.tls`），
 * 与协议本身不冲突。
 */
expect object Transport {

    suspend fun connect(
        endpoint: Endpoint,
        connectTimeoutMillis: Int = 8_000,
        readTimeoutMillis: Int = 30_000,
    ): Connection

    /**
     * 监听端口。每个进来的连接都会新起一个协程调用 [onClient]，
     * [onClient] 抛异常只会终止该连接，不影响监听本身。
     */
    suspend fun listen(
        port: Int,
        bindAddress: String = "0.0.0.0",
        onClient: suspend (Connection) -> Unit,
    ): ServerHandle
}

/** 连接层失败（TCP 层的问题，不是协议层）。 */
class TransportException(message: String, cause: Throwable? = null) : Exception(message, cause)
