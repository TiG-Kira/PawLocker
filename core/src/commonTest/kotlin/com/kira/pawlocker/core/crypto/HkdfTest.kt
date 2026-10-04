package com.kira.pawlocker.core.crypto

import com.kira.pawlocker.core.hexToBytes
import com.kira.pawlocker.core.repeatByte
import com.kira.pawlocker.core.sequentialBytes
import com.kira.pawlocker.core.toHex
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse

/**
 * RFC 5869 Appendix A 的三组官方测试向量。
 *
 * HKDF 是整个密钥体系的根：配对密钥、加密密钥、MAC 密钥、SAS 全部由它派生。
 * 它算错一个比特，两端就会派生出不同的密钥 —— 而且症状是「配对莫名其妙失败」，
 * 极难排查。所以这里必须用官方向量而不是自造往返测试。
 */
class HkdfTest {

    @Test
    fun `RFC 5869 测试用例 1 —— 基础场景`() {
        val ikm = repeatByte(0x0B, 22)
        val salt = "000102030405060708090a0b0c".hexToBytes()
        val info = "f0f1f2f3f4f5f6f7f8f9".hexToBytes()

        val prk = Hkdf.extract(salt, ikm)
        assertEquals(
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
            prk.toHex(),
        )

        val okm = Hkdf.expand(prk, info, 42)
        assertEquals(
            "3cb25f25faacd57a90434f64d0362f2a" +
                "2d2d0a90cf1a5a4c5db02d56ecc4c5bf" +
                "34007208d5b887185865",
            okm.toHex(),
        )
        assertEquals(42, okm.size)
    }

    @Test
    fun `RFC 5869 测试用例 2 —— 长输入跨多个 HMAC 块`() {
        val ikm = sequentialBytes(80)
        val salt = sequentialBytes(80, start = 0x60)
        val info = sequentialBytes(80, start = 0xB0)

        val prk = Hkdf.extract(salt, ikm)
        assertEquals(
            "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
            prk.toHex(),
        )

        // 82 字节 = 3 个数据块，正好覆盖 expand 里的「多块串联」分支
        val okm = Hkdf.expand(prk, info, 82)
        assertEquals(82, okm.size)
        assertEquals(
            "b11e398dc80327a1c8e7f78c596a4934" +
                "4f012eda2d4efad8a050cc4c19afa97c" +
                "59045a99cac7827271cb41c65e590e09" +
                "da3275600c2f09b8367793a9aca3db71" +
                "cc30c58179ec3e87c14c01d5c1f3434f" +
                "1d87",
            okm.toHex(),
        )
    }

    @Test
    fun `RFC 5869 测试用例 3 —— 空 salt 与空 info`() {
        val ikm = repeatByte(0x0B, 22)

        val prk = Hkdf.extract(ByteArray(0), ikm)
        // salt 为空时按 RFC 退化为 32 字节全零盐
        assertEquals(
            "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
            prk.toHex(),
        )

        val okm = Hkdf.expand(prk, ByteArray(0), 42)
        assertEquals(
            "8da4e775a563c18f715f802a063c5a31" +
                "b8a11f5c5ee1879ec3454e5f3c738d2d" +
                "9d201395faa4b61a96c8",
            okm.toHex(),
        )
    }

    @Test
    fun `derive 与手工 extract 加 expand 等价`() {
        val ikm = "shared-secret-material".encodeToByteArray()
        val salt = "salt-value".encodeToByteArray()

        assertContentEquals(
            Hkdf.expand(Hkdf.extract(salt, ikm), "PawLocker/test".encodeToByteArray(), 48),
            Hkdf.derive(ikm, salt, "PawLocker/test", 48),
        )
    }

    @Test
    fun `不同 info 标签派生出互不相同的密钥`() {
        val prk = Hkdf.extract(ByteArray(0), repeatByte(0x42, 32))

        val enc = Hkdf.expand(prk, ProtocolLabels.ENC_KEY.encodeToByteArray(), 32)
        val mac = Hkdf.expand(prk, ProtocolLabels.MAC_KEY.encodeToByteArray(), 32)
        val pairing = Hkdf.expand(prk, ProtocolLabels.PAIRING_KEY.encodeToByteArray(), 32)

        assertFalse(enc.contentEquals(mac), "enc 与 mac 派生结果必须不同")
        assertFalse(enc.contentEquals(pairing), "enc 与 pairing 派生结果必须不同")
        assertFalse(mac.contentEquals(pairing), "mac 与 pairing 派生结果必须不同")
    }

    @Test
    fun `输出长度边界被校验`() {
        val prk = repeatByte(0x11, 32)

        assertFailsWith<IllegalArgumentException> { Hkdf.expand(prk, ByteArray(0), 0) }
        assertFailsWith<IllegalArgumentException> { Hkdf.expand(prk, ByteArray(0), -1) }
        // RFC 5869 §2.3 规定上限为 255 * HashLen
        assertFailsWith<IllegalArgumentException> { Hkdf.expand(prk, ByteArray(0), 255 * 32 + 1) }

        assertEquals(255 * 32, Hkdf.expand(prk, ByteArray(0), 255 * 32).size)
    }

    @Test
    fun `输出是确定性且前缀稳定的`() {
        val ikm = repeatByte(0x5A, 32)
        val salt = repeatByte(0x01, 8)

        val short = Hkdf.derive(ikm, salt, "label", 32)
        val long = Hkdf.derive(ikm, salt, "label", 64)

        // 短输出必须是长输出的前缀，否则「延长长度」这类协议演进会破坏兼容性
        assertContentEquals(short, long.copyOfRange(0, 32))
        assertContentEquals(short, Hkdf.derive(ikm, salt, "label", 32))
    }
}
