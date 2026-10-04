package com.kira.pawlocker.core.protocol

import com.kira.pawlocker.core.hexToBytes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * 线路编码与分帧。
 *
 * 分帧是「对端可以随便发任何字节」的入口，长度头是唯一的内存保护，
 * 必须能挡住超大长度、零长度与截断输入。
 */
class WireCodecTest {

    // 端口故意用一个跟默认值无关的数：这份 fixture 测的是「显示串怎么拼」，
    // 绑上 Protocol.DEFAULT_PORT 只会让以后改默认端口时误伤到这里。
    private val endpoint = Endpoint(TransportKind.LAN, "192.168.1.10", 12345, "家里 Wi-Fi")

    private val samples: List<WireMessage> = listOf(
        ClientHello(
            deviceId = "phone-id",
            displayName = "Kira 的手机",
            model = "Pixel 9",
            publicKey = "pk",
            nonce = "n1",
        ),
        ServerHello(
            deviceId = "pc-id",
            displayName = "书房主机",
            model = "Desktop",
            publicKey = "pk2",
            nonce = "n2",
            pairingOpen = true,
            activePairingId = "pairing-1",
            serverTime = 1_700_000_000_000L,
            trustedDeviceCount = 2,
        ),
        ServerHello(
            deviceId = "pc-id",
            displayName = "书房主机",
            model = "Desktop",
            publicKey = "pk2",
            nonce = "n2",
            pairingOpen = false,
            activePairingId = null,
            serverTime = 1L,
        ),
        PairRequest(pairingId = "p", nonce = "n", ciphertext = "ct"),
        PairPending(pairingId = "p", serverTime = 5L),
        PairResponse(pairingId = "p", nonce = "n", ciphertext = "ct"),
        UnlockRequest(
            deviceId = "phone-id",
            targetUserSid = "S-1-5-21-1-2-3-1001",
            counter = 7,
            requestedAt = 1_700_000_000_000L,
            nonce = "n",
            ciphertext = "ct",
            signature = "sig",
        ),
        UnlockAck(ok = true, code = null, message = null, serverTime = 1L, counter = 7, mac = "mac"),
        Ping(at = 1L),
        Pong(at = 1L, serverTime = 2L),
        ErrorMessage(code = ErrorCodes.BAD_SIGNATURE, message = "签名不对"),
    )

    @Test
    fun `所有报文类型都能往返`() {
        for (message in samples) {
            val decoded = WireCodec.decode(WireCodec.encode(message))
            assertEquals(message, decoded, "报文类型 ${message::class.simpleName} 往返失败")
        }
    }

    @Test
    fun `判别字段固定为 t`() {
        val json = WireCodec.encode(
            UnlockRequest("d", "S-1-5-21-1-2-3-1001", 1, 2, "n", "ct", "sig"),
        ).decodeToString()

        assertTrue(json.contains("\"t\":\"unlock\""), "实际报文: $json")
        assertTrue(json.contains("\"deviceId\":\"d\""))
    }

    @Test
    fun `判别值来自 MessageTypes 常量`() {
        // 这些字符串是两端 ABI 的一部分，改动会直接造成协议不兼容
        assertEquals("hello", MessageTypes.CLIENT_HELLO)
        assertEquals("hello.ack", MessageTypes.SERVER_HELLO)
        assertEquals("pair.request", MessageTypes.PAIR_REQUEST)
        assertEquals("pair.pending", MessageTypes.PAIR_PENDING)
        assertEquals("pair.response", MessageTypes.PAIR_RESPONSE)
        assertEquals("unlock", MessageTypes.UNLOCK)
        assertEquals("unlock.ack", MessageTypes.UNLOCK_ACK)
        assertEquals("ping", MessageTypes.PING)
        assertEquals("pong", MessageTypes.PONG)
        assertEquals("error", MessageTypes.ERROR)
    }

    @Test
    fun `默认值被显式编码`() {
        // encodeDefaults = true：协议字段必须出现在报文里，
        // 否则未来给字段换默认值时，新旧版本会静默地理解成不同含义
        val json = WireCodec.encode(
            ClientHello(
                deviceId = "d",
                displayName = "n",
                model = "m",
                publicKey = "pk",
                nonce = "n",
            ),
        ).decodeToString()
        assertTrue(json.contains("\"v\":${Protocol.VERSION}"), "实际报文: $json")
    }

    @Test
    fun `可空字段被显式写成 null`() {
        val json = WireCodec.encode(
            ServerHello(
                deviceId = "d",
                displayName = "n",
                model = "m",
                publicKey = "pk",
                nonce = "n",
                pairingOpen = false,
                activePairingId = null,
                serverTime = 1L,
            ),
        ).decodeToString()
        assertTrue(json.contains("\"activePairingId\":null"), "实际报文: $json")
    }

    @Test
    fun `未知字段直接报错而不是被忽略`() {
        val valid = WireCodec.encode(Ping(at = 1L)).decodeToString()
        val injected = valid.dropLast(1) + ",\"backdoor\":\"yes\"}"

        assertFailsWith<IllegalArgumentException> {
            WireCodec.decode(injected.encodeToByteArray())
        }
    }

    @Test
    fun `缺少必填字段直接报错`() {
        assertFailsWith<IllegalArgumentException> {
            WireCodec.decode("{\"t\":\"unlock\"}".encodeToByteArray())
        }
    }

    @Test
    fun `未知判别值直接报错`() {
        assertFailsWith<IllegalArgumentException> {
            WireCodec.decode("{\"t\":\"do-something-else\"}".encodeToByteArray())
        }
    }

    @Test
    fun `非 JSON 输入直接报错`() {
        assertFailsWith<IllegalArgumentException> {
            WireCodec.decode(byteArrayOf(0x00, 0x01, 0x02))
        }
    }

    @Test
    fun `分帧加入 4 字节大端长度头`() {
        val payload = WireCodec.encode(Ping(at = 1L))
        val framed = WireCodec.frame(payload)

        assertEquals(payload.size + 4, framed.size)
        assertEquals(
            payload.size,
            WireCodec.readLengthHeader(framed.copyOfRange(0, 4)),
            "长度头必须等于载荷长度",
        )
        assertTrue(framed.copyOfRange(4, framed.size).contentEquals(payload))
    }

    @Test
    fun `长度头是网络字节序`() {
        // 手动构造 0x00000100 = 256，确认不是小端
        val header = byteArrayOf(0x00, 0x00, 0x01, 0x00)
        assertEquals(256, WireCodec.readLengthHeader(header))
    }

    @Test
    fun `长度头大小端不会因平台而异`() {
        for (size in intArrayOf(1, 2, 255, 256, 65535, 65536, Protocol.MAX_FRAME_SIZE)) {
            val framed = WireCodec.frame(ByteArray(size))
            assertEquals(size, WireCodec.readLengthHeader(framed.copyOfRange(0, 4)))
        }
    }

    @Test
    fun `零长度与超大帧被拒绝`() {
        assertFailsWith<IllegalArgumentException> { WireCodec.frame(ByteArray(0)) }
        assertFailsWith<IllegalArgumentException> { WireCodec.frame(ByteArray(Protocol.MAX_FRAME_SIZE + 1)) }

        // 上界本身必须被接受
        assertEquals(Protocol.MAX_FRAME_SIZE, WireCodec.frame(ByteArray(Protocol.MAX_FRAME_SIZE)).size - 4)
    }

    @Test
    fun `长度头校验挡住恶意长度`() {
        assertFailsWith<IllegalArgumentException> {
            WireCodec.readLengthHeader(byteArrayOf(0, 0, 0, 0))
        }
        assertFailsWith<IllegalArgumentException> {
            // 0x7FFFFFFF，典型的「分配一个巨大缓冲区」攻击
            WireCodec.readLengthHeader("7fffffff".hexToBytes())
        }
        assertFailsWith<IllegalArgumentException> {
            WireCodec.readLengthHeader(byteArrayOf(1, 2, 3))
        }
    }

    @Test
    fun `长度头边界值`() {
        assertEquals(1, WireCodec.readLengthHeader(byteArrayOf(0, 0, 0, 1)))
        assertEquals(
            Protocol.MAX_FRAME_SIZE,
            WireCodec.readLengthHeader("00010000".hexToBytes()),
        )
    }

    @Test
    fun `端点排序把局域网排在隧道前面`() {
        val sorted = listOf(
            Endpoint(TransportKind.TUNNEL, "tunnel.example.com"),
            Endpoint(TransportKind.MANUAL, "10.0.0.9"),
            Endpoint(TransportKind.LAN, "192.168.1.10"),
            Endpoint(TransportKind.OVERLAY, "100.64.0.1"),
        ).sortedWith(Endpoint.preferredOrder)

        assertEquals(
            listOf(TransportKind.LAN, TransportKind.OVERLAY, TransportKind.TUNNEL, TransportKind.MANUAL),
            sorted.map { it.kind },
        )
    }

    @Test
    fun `端点显示串包含端口`() {
        assertEquals("192.168.1.10:12345", endpoint.display)
        assertEquals(Protocol.DEFAULT_PORT, Endpoint(TransportKind.LAN, "h").port)
        assertEquals(
            "h:${Protocol.DEFAULT_PORT}",
            Endpoint(TransportKind.LAN, "h").display,
            "省略端口时应回落到默认端口，显示串要跟着它走而不是写死",
        )
    }

    @Test
    fun `解锁报文的 AAD 覆盖全部头部字段`() {
        val base = UnlockRequest("d", "S-1-5-21-1-2-3-1001", 1, 2, "n", "ct", "sig")

        val aad = base.aad().decodeToString()
        // 绑定链的中间一环（目标 Windows 账户）必须在 AAD 里
        assertEquals("${Protocol.VERSION}|d|S-1-5-21-1-2-3-1001|1|2|n", aad)

        // 任一字段变化都必须改变 AAD，否则该字段就不受 GCM 保护
        assertTrue(base.copy(deviceId = "x").aad().decodeToString() != aad)
        assertTrue(base.copy(targetUserSid = "S-1-5-21-9-9-9-1002").aad().decodeToString() != aad)
        assertTrue(base.copy(counter = 9).aad().decodeToString() != aad)
        assertTrue(base.copy(requestedAt = 9).aad().decodeToString() != aad)
        assertTrue(base.copy(nonce = "z").aad().decodeToString() != aad)
        assertEquals(aad, base.copy(signature = "other").aad().decodeToString(), "签名不参与 AAD")
    }

    @Test
    fun `签名覆盖 AAD 与密文`() {
        val request = UnlockRequest("d", "S-1-5-21-1-2-3-1001", 1, 2, "n", "ct", "sig")
        val signed = request.signedBytes().decodeToString()
        assertEquals("${request.aad().decodeToString()}ct", signed)

        assertTrue(!request.copy(ciphertext = "ct2").signedBytes().contentEquals(request.signedBytes()))
        assertTrue(!request.copy(counter = 5).signedBytes().contentEquals(request.signedBytes()))
    }

    @Test
    fun `枚举常量保持稳定`() {
        assertEquals(4, TransportKind.entries.size)
        assertEquals(0, TransportKind.LAN.rank)
        assertEquals(3, TransportKind.MANUAL.rank)
        assertTrue(TransportKind.entries.none { it.displayName.isBlank() })
        // rank 必须严格递增，否则 preferredOrder 的排序语义会退化
        assertEquals(listOf(0, 1, 2, 3), TransportKind.entries.map { it.rank })
    }
}
