package com.kira.pawlocker.core.crypto

import com.kira.pawlocker.core.hexToBytes
import com.kira.pawlocker.core.repeatByte
import com.kira.pawlocker.core.toHex
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * RFC 4648 §10 的官方测试向量。
 *
 * 协议里所有二进制字段（公钥、nonce、密文、签名）都靠这套编解码承载，
 * 它一旦出错，两端会在「看起来一切正常」的情况下互相解不开 —— 所以必须钉死。
 */
class Base64UrlTest {

    private val vectors = listOf(
        "" to "",
        "f" to "Zg",
        "fo" to "Zm8",
        "foo" to "Zm9v",
        "foob" to "Zm9vYg",
        "fooba" to "Zm9vYmE",
        "foobar" to "Zm9vYmFy",
    )

    @Test
    fun `RFC 4648 测试向量 —— 无填充编码`() {
        for ((plain, encoded) in vectors) {
            assertEquals(encoded, Base64Url.encode(plain.encodeToByteArray()), "编码 $plain")
            assertEquals(plain, Base64Url.decode(encoded).decodeToString(), "解码 $encoded")
        }
    }

    @Test
    fun `RFC 4648 测试向量 —— 带填充编码`() {
        assertEquals("Zg==", Base64Url.encode("f".encodeToByteArray(), padding = true))
        assertEquals("Zm8=", Base64Url.encode("fo".encodeToByteArray(), padding = true))
        assertEquals("Zm9v", Base64Url.encode("foo".encodeToByteArray(), padding = true))
        assertEquals("Zm9vYg==", Base64Url.encode("foob".encodeToByteArray(), padding = true))
        assertEquals("Zm9vYmE=", Base64Url.encode("fooba".encodeToByteArray(), padding = true))
    }

    @Test
    fun `填充与换行在解码时被忽略`() {
        // 深链可能经过邮件客户端 / 剪贴板，被插入换行是常态
        assertContentEquals("f".encodeToByteArray(), Base64Url.decode("Zg=="))
        assertContentEquals("foob".encodeToByteArray(), Base64Url.decode("Zm9v\r\nYg=="))
    }

    @Test
    fun `任意字节序列往返一致`() {
        val random = Random(20261004)
        for (size in 0..80) {
            val bytes = ByteArray(size) { random.nextInt(256).toByte() }
            assertContentEquals(bytes, Base64Url.decode(Base64Url.encode(bytes)), "长度 $size")
        }
    }

    @Test
    fun `使用 URL 安全字母表而不是标准字母表`() {
        // 0xFF 0xFF 0xFF 编码后是 "____"，标准 Base64 会是 "////"
        val encoded = Base64Url.encode(repeatByte(0xFF, 3))
        assertEquals("____", encoded)
        assertFalse(encoded.contains('/'), "URL 安全字母表不应出现 /")
        assertFalse(encoded.contains('+'), "URL 安全字母表不应出现 +")
    }

    @Test
    fun `非法字符直接报错而不是静默忽略`() {
        // 静默忽略会让「截断的密文」被解成另一段密文，进而变成难以定位的认证失败
        assertFailsWith<IllegalArgumentException> { Base64Url.decode("Zm9v!!!") }
        assertFailsWith<IllegalArgumentException> { Base64Url.decode("Zm9v/") }
        assertFailsWith<IllegalArgumentException> { Base64Url.decode("Zm9v+") }
    }

    @Test
    fun `toHexShort 只取前若干字节`() {
        // 13 字节：3 个已知值 + 10 个 0xFF
        val bytes = byteArrayOf(0x00, 0x0A, 0x7F) + repeatByte(0xFF, 10)

        // 默认上限 8 字节 → 16 个十六进制字符
        assertEquals("000a7fffffffffff", bytes.toHexShort())
        assertEquals("000a7f", bytes.toHexShort(3))
        assertEquals(16, bytes.toHexShort().length)
        assertEquals(26, bytes.toHexShort(limit = 13).length)
    }

    @Test
    fun `定长比较对内容与长度都敏感`() {
        val base = "pawlocker".encodeToByteArray()

        assertTrue(constantTimeEquals(base, "pawlocker".encodeToByteArray()))
        assertFalse(constantTimeEquals(base, "pawlockeR".encodeToByteArray()))
        // 长度不同必须直接 false：否则比较循环会按较短者结束，留下前缀匹配漏洞
        assertFalse(constantTimeEquals(base, "pawlocker!".encodeToByteArray()))
        assertFalse(constantTimeEquals(base, ByteArray(0)))
        assertTrue(constantTimeEquals(ByteArray(0), ByteArray(0)))
    }

    @Test
    fun `单字节差异的十六进制对照可用于回归比对`() {
        // 这条只是把 hexToBytes 自身也纳入校验，避免测试工具本身有 bug
        assertEquals("0b0b0b", repeatByte(0x0B, 3).toHex())
        assertEquals("00ff10", "00FF10".hexToBytes().toHex())
    }
}
