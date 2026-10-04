package com.kira.pawlocker.core.platform

import com.kira.pawlocker.core.crypto.PlatformCrypto
import com.sun.jna.Pointer
import com.sun.jna.platform.win32.Kernel32
import com.sun.jna.platform.win32.WinNT
import com.sun.jna.ptr.IntByReference
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * 凭据投递：把登录凭据**一次性**交给运行在 LogonUI 里的凭据提供程序。
 *
 * ## 为什么不把凭据落盘给 DLL 读
 *
 * 那份 DPAPI 文件是**用户作用域**加密的，只有当前用户的 DPAPI 主密钥能解；
 * 而 DLL 跑在 LogonUI 进程（SYSTEM 上下文）里，解不开。
 *
 * 换成机器作用域倒是能让 DLL 解开，代价是**同机任何进程都能解开** ——
 * 对「远程解锁」这种场景，磁盘上常驻一份机器可解的密码副本是不能接受的。
 *
 * 所以走现投：主程序此刻一定在运行（解锁指令就是它收的），
 * 由它在内存里解密凭据、经命名管道交给 DLL。**磁盘上永远不存在机器可解的副本。**
 *
 * ## 时序（顺序不能换）
 *
 * ```
 *   1. listen()        —— 先把管道挂起来（此时还没有客户端）
 *   2. SetEvent(...)   —— 再通知 CP「可以来取了」
 *   3. deliver(blob)   —— CP 连上后把凭据写过去
 * ```
 *
 * 先建管道再置事件是必须的：反过来会出现「CP 被叫醒了，但管道还不存在」
 * 的竞态，而那个窗口在慢机器上很容易复现。
 *
 * ## 权限
 *
 * 不需要自己设 SDDL。命名管道由当前用户进程创建时，其默认 DACL 已经包含
 * SYSTEM 与当前用户 —— LogonUI（SYSTEM）天然连得上，少一处可能配错的地方。
 */
class CredentialHandoff(
    private val accountName: String,
    private val timeoutMillis: Long = 5_000,
) {

    fun pipeName(): String =
        PIPE_PREFIX + accountName.ifBlank { FALLBACK_ACCOUNT }

    /**
     * 建立起监听。必须在置位解锁事件**之前**调用。
     *
     * @return null 表示管道没建起来（端口被占用、句柄耗尽等），调用方应当放弃本次投递
     */
    fun listen(): Session? {
        val handle = Kernel32.INSTANCE.CreateNamedPipe(
            pipeName(),
            // 只写：我们只负责送，读的一律是对方
            PIPE_ACCESS_OUTBOUND,
            // 字节流 + 阻塞模式。消息模式在这里没有好处，反而会多一层分帧语义要对齐
            PIPE_TYPE_BYTE or PIPE_READMODE_BYTE or PIPE_WAIT,
            1,
            0,
            MAX_PAYLOAD_BYTES,
            0,
            null,
        )

        // JNA 的 HANDLE 是 PointerType 而不是 Pointer，要取底层指针再判 INVALID_HANDLE_VALUE(-1)
        val raw = handle?.pointer
        if (raw == null || Pointer.nativeValue(raw) == -1L) {
            PlatformEnv.log(TAG, "创建命名管道失败：${pipeName()}")
            return null
        }

        return Session(handle)
    }

    /**
     * 一次投递会话。
     *
     * 内部起一条守护线程：它先阻塞等 CP 连上，再阻塞等 [deliver] 把数据交过来，
     * 写完就关管道。之所以要线程，是因为 `ConnectNamedPipe` 是阻塞调用，
     * 而调用方需要在「已开始监听」和「真正写入」之间插入 `SetEvent`。
     */
    inner class Session internal constructor(private val handle: WinNT.HANDLE) {

        private val connected = CountDownLatch(1)
        private val outbound = ArrayBlockingQueue<ByteArray>(1)
        private val delivered = AtomicBoolean(false)
        private val finished = CountDownLatch(1)

        private val worker = Thread({ run() }, "pawlocker-credential-handoff").apply {
            isDaemon = true
            start()
        }

        /** 等 CP 连上。返回 false 表示超时 —— 说明锁屏上没有 PawLocker 磁贴。 */
        fun awaitClient(): Boolean {
            val ok = connected.await(timeoutMillis, TimeUnit.MILLISECONDS)
            if (!ok) {
                PlatformEnv.log(TAG, "等待凭据提供程序连接超时（${timeoutMillis}ms）")
            }
            return ok && clientConnected
        }

        /**
         * 把凭据交出去。无论成败，调用方都应立刻清零自己的明文副本。
         * @return 是否完整写出
         */
        fun deliver(payload: ByteArray): Boolean {
            if (!clientConnected) return false
            outbound.offer(payload)
            finished.await(timeoutMillis, TimeUnit.MILLISECONDS)
            return delivered.get()
        }

        @Volatile
        private var clientConnected = false

        private fun run() {
            try {
                val ok = Kernel32.INSTANCE.ConnectNamedPipe(handle, null)
                val error = if (ok) 0 else Kernel32.INSTANCE.GetLastError()
                // ERROR_PIPE_CONNECTED 表示「在我调用之前客户端就已经连上了」——
                // 这是成功情形，不是失败
                clientConnected = ok || error == ERROR_PIPE_CONNECTED
                if (!clientConnected) {
                    PlatformEnv.log(TAG, "连接命名管道失败，Win32 错误码 $error")
                }
            } finally {
                connected.countDown()
            }

            if (!clientConnected) {
                closeQuietly()
                finished.countDown()
                return
            }

            try {
                val payload = outbound.poll(timeoutMillis, TimeUnit.MILLISECONDS)
                if (payload == null) {
                    PlatformEnv.log(TAG, "凭据投递超时：没有拿到待发送的数据")
                    return
                }
                val written = IntByReference(0)
                val ok = Kernel32.INSTANCE.WriteFile(handle, payload, payload.size, written, null)
                if (ok && written.value == payload.size) {
                    Kernel32.INSTANCE.FlushFileBuffers(handle)
                    delivered.set(true)
                    PlatformEnv.log(TAG, "已投递凭据（${payload.size} 字节）")
                } else {
                    PlatformEnv.log(
                        TAG,
                        "写入凭据失败：写入 ${written.value}/${payload.size} 字节，Win32 ${Kernel32.INSTANCE.GetLastError()}",
                    )
                }
            } catch (error: InterruptedException) {
                Thread.currentThread().interrupt()
            } finally {
                closeQuietly()
                finished.countDown()
            }
        }

        private fun closeQuietly() {
            runCatching { Kernel32.INSTANCE.DisconnectNamedPipe(handle) }
            runCatching { Kernel32.INSTANCE.CloseHandle(handle) }
        }

        /** 供测试与日志用。 */
        fun isDelivered(): Boolean = delivered.get()
    }

    private companion object {
        const val TAG = "CredentialHandoff"

        /**
         * 管道名前缀。必须与 DLL 侧 `PawLockerContract.h` 的 `kPipePrefix` 一字不差。
         * Kotlin 字符串里反斜杠要转义，`\\\\.\\pipe\\` 实际是 `\\.\pipe\`。
         */
        const val PIPE_PREFIX = "\\\\.\\pipe\\PawLocker.Cred."

        /** 账户名取不到时的兜底，与 DLL 侧 `kFallbackUserName` 一致。 */
        const val FALLBACK_ACCOUNT = "PawLocker"

        const val MAX_PAYLOAD_BYTES = 64 * 1024

        // Win32 常量。JNA 里这些名字分散在 Kernel32 / WinBase 上，
        // 版本之间有出入，按文档值写死反而更稳。
        const val PIPE_ACCESS_OUTBOUND = 0x00000002
        const val PIPE_TYPE_BYTE = 0x00000000
        const val PIPE_READMODE_BYTE = 0x00000000
        const val PIPE_WAIT = 0x00000000
        const val ERROR_PIPE_CONNECTED = 535
    }
}

/**
 * 凭据二进制块的编码。
 *
 * **格式必须与 DLL 侧 `PAWLOCKER_CREDENTIAL_BLOB_HEADER` 完全一致**（小端）：
 *
 * ```
 *   偏移 0   DWORD  magic            'PWLC' = 0x434C5750
 *   偏移 4   WORD   version          1
 *   偏移 6   WORD   flags            bit0 = 有密码
 *   偏移 8   DWORD  userNameBytes
 *   偏移 12  DWORD  domainBytes
 *   偏移 16  DWORD  passwordBytes
 *   偏移 20  DWORD  sidBytes
 *   偏移 24  ...    四个 UTF-8 字段依次排列
 * ```
 *
 * 为什么用定长头而不是 JSON：C 侧解析只需要走一趟、没有边界歧义，
 * 也不用为一个字符串字段在原生侧实现一个 JSON 解析器（那是 bug 温床）。
 */
object CredentialBlobCodec {

    const val MAGIC = 0x434C5750  // 'PWLC'
    const val VERSION = 1
    const val FLAG_HAS_PASSWORD = 0x0001
    const val HEADER_BYTES = 24
    const val MAX_FIELD_BYTES = 4096

    /** 帧格式：`[4 字节小端总长][载荷]`。 */
    fun encode(
        userName: String,
        domain: String,
        password: String,
        sid: String,
    ): ByteArray {
        val userBytes = userName.encodeToByteArray()
        val domainBytes = domain.encodeToByteArray()
        val passwordBytes = password.encodeToByteArray()
        val sidBytes = sid.encodeToByteArray()

        for ((label, size) in listOf(
            "userName" to userBytes.size,
            "domain" to domainBytes.size,
            "password" to passwordBytes.size,
            "sid" to sidBytes.size,
        )) {
            require(size <= MAX_FIELD_BYTES) { "$label 字段过长：$size 字节" }
        }

        val payload = ByteArray(HEADER_BYTES + userBytes.size + domainBytes.size + passwordBytes.size + sidBytes.size)
        var cursor = 0
        fun putInt(value: Int) {
            payload[cursor++] = (value and 0xFF).toByte()
            payload[cursor++] = ((value ushr 8) and 0xFF).toByte()
            payload[cursor++] = ((value ushr 16) and 0xFF).toByte()
            payload[cursor++] = ((value ushr 24) and 0xFF).toByte()
        }
        fun putShort(value: Int) {
            payload[cursor++] = (value and 0xFF).toByte()
            payload[cursor++] = ((value ushr 8) and 0xFF).toByte()
        }

        putInt(MAGIC)
        putShort(VERSION)
        putShort(if (password.isNotEmpty()) FLAG_HAS_PASSWORD else 0)
        putInt(userBytes.size)
        putInt(domainBytes.size)
        putInt(passwordBytes.size)
        putInt(sidBytes.size)

        for (chunk in listOf(userBytes, domainBytes, passwordBytes, sidBytes)) {
            chunk.copyInto(payload, cursor)
            cursor += chunk.size
        }

        // 外层帧：先写总长，再写载荷。
        // 除了载荷之外还多 4 字节的长度头 —— DLL 侧先读它再读载荷。
        val framed = ByteArray(4 + payload.size)
        framed[0] = (payload.size and 0xFF).toByte()
        framed[1] = ((payload.size ushr 8) and 0xFF).toByte()
        framed[2] = ((payload.size ushr 16) and 0xFF).toByte()
        framed[3] = ((payload.size ushr 24) and 0xFF).toByte()
        payload.copyInto(framed, 4)
        return framed
    }

    /** 尽力擦除明文凭据。 */
    fun wipe(bytes: ByteArray) {
        PlatformCrypto.wipe(bytes)
    }
}
