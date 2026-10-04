package com.kira.pawlocker.core.net

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
 * Android 侧 TCP 传输。
 *
 * 用阻塞式 `java.net.Socket` + `Dispatchers.IO`，而不是 NIO。
 * 理由很实际：解锁操作的并发量是「0 到 1」，NIO 带来的复杂度（Selector 状态机、
 * 半包处理、Buffer 管理）换不来任何收益，而阻塞 IO 的代码路径短到可以一眼看完。
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
            serverSocket.bind(InetSocketAddress(bindAddress, port), 50)
        } catch (error: Throwable) {
            runCatching { serverSocket.close() }
            throw TransportException("无法监听 $bindAddress:$port：${error.message}", error)
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
                        com.kira.pawlocker.core.platform.PlatformEnv.log(
                            "Transport",
                            "连接处理失败: ${error.message}",
                        )
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

/** 长度前缀分帧的阻塞实现。[send] 内部加锁，允许多个协程并发投递。 */
internal class SocketConnection(private val socket: Socket) : Connection {

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
