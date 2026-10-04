package com.kira.pawlocker.core.net

import com.kira.pawlocker.core.platform.PlatformEnv
import com.kira.pawlocker.core.protocol.Endpoint
import com.kira.pawlocker.core.protocol.WireCodec
import com.kira.pawlocker.core.protocol.WireMessage
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Windows 侧 TCP 传输。与 Android 侧实现同构 ——
 * 唯一差别是 Windows 同时承担服务端的角色。
 */
actual object Transport {

    private const val SERVER_IDLE_TIMEOUT_MILLIS = 300_000

    actual suspend fun connect(
        endpoint: Endpoint,
        connectTimeoutMillis: Int,
        readTimeoutMillis: Int,
    ): Connection = withContext(Dispatchers.IO) {
        val socket = Socket()
        try {
            socket.tcpNoDelay = true
            socket.connect(InetSocketAddress(endpoint.host, endpoint.port), connectTimeoutMillis)
            socket.soTimeout = readTimeoutMillis
            SocketConnection(socket)
        } catch (error: Throwable) {
            runCatching { socket.close() }
            throw TransportException(
                "无法连接 ${endpoint.display}：${error.message ?: error::class.simpleName}",
                error,
            )
        }
    }

    actual suspend fun listen(
        port: Int,
        bindAddress: String,
        onClient: suspend (Connection) -> Unit,
    ): ServerHandle {
        require(port in 1..65535) { "端口越界: $port" }

        val serverSocket = ServerSocket()
        try {
            serverSocket.reuseAddress = true
            // 只绑 0.0.0.0 会让同网段任何人都能连；
            // 是否需要限制来源由 Windows 防火墙负责（见 docs/03-nat-traversal.md）
            serverSocket.bind(InetSocketAddress(bindAddress, port), 50)
        } catch (error: Throwable) {
            runCatching { serverSocket.close() }
            throw TransportException(
                "无法监听 $bindAddress:$port：${error.message}（端口被占用或权限不足）",
                error,
            )
        }

        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        scope.launch {
            while (isActive) {
                val socket = try {
                    serverSocket.accept()
                } catch (error: Throwable) {
                    break
                }

                launch {
                    try {
                        socket.tcpNoDelay = true
                        socket.soTimeout = SERVER_IDLE_TIMEOUT_MILLIS
                        onClient(SocketConnection(socket))
                    } catch (error: Throwable) {
                        PlatformEnv.log("Transport", "连接处理失败: ${error.message}")
                    } finally {
                        runCatching { socket.close() }
                    }
                }
            }
        }

        return object : ServerHandle {
            override val boundPort: Int = serverSocket.localPort
            override fun close() {
                runCatching { serverSocket.close() }
                scope.cancel()
            }
        }
    }
}

private class SocketConnection(private val socket: Socket) : Connection {

    private val input = DataInputStream(socket.getInputStream().buffered())
    private val output = DataOutputStream(socket.getOutputStream().buffered())
    private val closed = AtomicBoolean(false)
    private val writeLock = Any()

    override val remoteDescription: String =
        socket.inetAddress?.hostAddress ?: socket.remoteSocketAddress?.toString() ?: "unknown"

    override suspend fun send(message: WireMessage) = withContext(Dispatchers.IO) {
        check(!closed.get()) { "连接已关闭" }
        val frame = WireCodec.frame(WireCodec.encode(message))
        synchronized(writeLock) {
            output.write(frame)
            output.flush()
        }
    }

    override suspend fun receive(): WireMessage? = withContext(Dispatchers.IO) {
        if (closed.get()) return@withContext null

        val header = ByteArray(HEADER_SIZE)
        val first = input.read(header)
        if (first < 0) return@withContext null
        if (first < HEADER_SIZE) input.readFully(header, first, HEADER_SIZE - first)

        val length = WireCodec.readLengthHeader(header)
        val payload = ByteArray(length)
        input.readFully(payload)
        WireCodec.decode(payload)
    }

    override fun close() {
        if (closed.compareAndSet(false, true)) {
            runCatching { socket.close() }
        }
    }

    private companion object {
        const val HEADER_SIZE = 4
    }
}
