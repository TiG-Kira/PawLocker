package com.kira.pawlocker.core.crypto

import com.kira.pawlocker.core.hexToBytes
import com.kira.pawlocker.core.repeatByte
import com.kira.pawlocker.core.toHex
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * 平台密码学原语的向量测试。
 *
 * 这些向量都用**独立实现**交叉验证过（Python `hashlib`/`hmac`、Node 的 OpenSSL），
 * 不是从被测算实现里"回抄"出来的 —— 否则测试只能证明代码没变，不能证明代码对。
 */
class PlatformCryptoTest {

    @Test
    fun `SHA-256 已知向量`() {
        assertEquals(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            PlatformCrypto.sha256("abc".encodeToByteArray()).toHex(),
        )
        assertEquals(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            PlatformCrypto.sha256(ByteArray(0)).toHex(),
            "空输入的哈希值是 SHA-256 的经典边界用例",
        )
        assertEquals(32, PlatformCrypto.sha256(repeatByte(0x00, 1000)).size)
    }

    @Test
    fun `HMAC-SHA256 RFC 4231 测试用例 1 —— 密钥短于块长`() {
        assertEquals(
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            PlatformCrypto.hmacSha256(repeatByte(0x0B, 20), "Hi There".encodeToByteArray()).toHex(),
        )
    }

    @Test
    fun `HMAC-SHA256 RFC 4231 测试用例 2 —— 文本密钥`() {
        assertEquals(
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            PlatformCrypto.hmacSha256(
                "Jefe".encodeToByteArray(),
                "what do ya want for nothing?".encodeToByteArray(),
            ).toHex(),
        )
    }

    @Test
    fun `HMAC-SHA256 RFC 4231 测试用例 3 —— 长密钥与长消息`() {
        assertEquals(
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
            PlatformCrypto.hmacSha256(repeatByte(0xAA, 20), repeatByte(0xDD, 50)).toHex(),
        )
    }

    @Test
    fun `HMAC-SHA256 RFC 4231 测试用例 4 —— 25 字节密钥`() {
        assertEquals(
            "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
            PlatformCrypto.hmacSha256(
                "0102030405060708090a0b0c0d0e0f10111213141516171819".hexToBytes(),
                repeatByte(0xCD, 50),
            ).toHex(),
        )
    }

    /**
     * NIST GCM 规范 Test Case 16 / 17（AES-256，无 AAD / 有 AAD）。
     * 期望值由 Node 的 OpenSSL 实现交叉验证。
     * `aesGcmSeal` 返回 `密文 || 16 字节标签`，所以期望串就是两者拼接。
     */
    private val gcmKey =
        "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308".hexToBytes()
    private val gcmNonce = "cafebabefacedbaddecaf888".hexToBytes()
    private val gcmPlaintext = (
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72" +
            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
        ).hexToBytes()
    private val gcmExpectedNoAad = (
        "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa" +
            "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662" +
            "eb9f796c8d356fc31a8433884b696f4f"
        ).hexToBytes()

    @Test
    fun `AES-256-GCM NIST 测试用例 16 —— 无附加数据`() {
        val sealed = PlatformCrypto.aesGcmSeal(gcmKey, gcmNonce, gcmPlaintext, ByteArray(0))
        assertEquals(gcmExpectedNoAad.toHex(), sealed.toHex())
        assertEquals(gcmPlaintext.size + Aead.TAG_SIZE, sealed.size, "密文长度 + 标签长度")
    }

    @Test
    fun `AES-256-GCM NIST 测试用例 17 —— 带附加数据`() {
        val aad = "feedfacedeadbeeffeedfacedeadbeefabaddad2".hexToBytes()
        val expected = (
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa" +
                "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662" +
                "76fc6ece0f4e1768cddf8853bb2d551b"
            ).hexToBytes()

        val sealed = PlatformCrypto.aesGcmSeal(gcmKey, gcmNonce, gcmPlaintext, aad)
        assertEquals(expected.toHex(), sealed.toHex(), "附加数据必须真正参与认证")
    }

    @Test
    fun `AES-256-GCM 空明文只产出标签`() {
        val aad = "feedfacedeadbeeffeedfacedeadbeefabaddad2".hexToBytes()
        val sealed = PlatformCrypto.aesGcmSeal(gcmKey, gcmNonce, ByteArray(0), aad)

        assertEquals(Aead.TAG_SIZE, sealed.size)
        assertEquals("9f6be07603c0b0bd1272854063e9c9ba", sealed.toHex())
        assertContentEquals(ByteArray(0), PlatformCrypto.aesGcmOpen(gcmKey, gcmNonce, sealed, aad))
    }

    @Test
    fun `AES-256-GCM 加解密往返`() {
        val key = PlatformCrypto.randomBytes(32)
        val nonce = PlatformCrypto.randomBytes(Aead.NONCE_SIZE)
        val aad = "unlock|1|device|42".encodeToByteArray()
        val plaintext = "{\"action\":\"unlock\"}".encodeToByteArray()

        val sealed = PlatformCrypto.aesGcmSeal(key, nonce, plaintext, aad)
        assertContentEquals(plaintext, PlatformCrypto.aesGcmOpen(key, nonce, sealed, aad))
    }

    @Test
    fun `修改密文任意一位都会导致认证失败`() {
        val key = PlatformCrypto.randomBytes(32)
        val nonce = PlatformCrypto.randomBytes(Aead.NONCE_SIZE)
        val sealed = PlatformCrypto.aesGcmSeal(key, nonce, "sensitive".encodeToByteArray(), ByteArray(0))

        // 逐字节翻转，确保整个密文与标签都在认证范围之内
        for (index in sealed.indices) {
            val tampered = sealed.copyOf().also { it[index] = (it[index].toInt() xor 0x01).toByte() }
            assertFailsWith<AeadFailure>("第 $index 字节被改动却没被发现") {
                PlatformCrypto.aesGcmOpen(key, nonce, tampered, ByteArray(0))
            }
        }
    }

    @Test
    fun `错误的附加数据或密钥无法解密`() {
        val key = PlatformCrypto.randomBytes(32)
        val nonce = PlatformCrypto.randomBytes(Aead.NONCE_SIZE)
        val sealed = PlatformCrypto.aesGcmSeal(key, nonce, "payload".encodeToByteArray(), "aad-1".encodeToByteArray())

        assertFailsWith<AeadFailure> {
            PlatformCrypto.aesGcmOpen(key, nonce, sealed, "aad-2".encodeToByteArray())
        }
        assertFailsWith<AeadFailure> {
            PlatformCrypto.aesGcmOpen(key, nonce, sealed, ByteArray(0))
        }
        assertFailsWith<AeadFailure> {
            PlatformCrypto.aesGcmOpen(PlatformCrypto.randomBytes(32), nonce, sealed, "aad-1".encodeToByteArray())
        }
    }

    @Test
    fun `错误的 nonce 无法解密`() {
        val key = PlatformCrypto.randomBytes(32)
        val sealed = PlatformCrypto.aesGcmSeal(
            key,
            PlatformCrypto.randomBytes(Aead.NONCE_SIZE),
            "payload".encodeToByteArray(),
            ByteArray(0),
        )

        assertFailsWith<AeadFailure> {
            PlatformCrypto.aesGcmOpen(key, PlatformCrypto.randomBytes(Aead.NONCE_SIZE), sealed, ByteArray(0))
        }
    }

    @Test
    fun `截断的密文无法解密`() {
        val key = PlatformCrypto.randomBytes(32)
        val nonce = PlatformCrypto.randomBytes(Aead.NONCE_SIZE)
        val sealed = PlatformCrypto.aesGcmSeal(key, nonce, "0123456789".encodeToByteArray(), ByteArray(0))

        assertFailsWith<AeadFailure> {
            PlatformCrypto.aesGcmOpen(key, nonce, sealed.copyOfRange(0, sealed.size - 1), ByteArray(0))
        }
    }

    @Test
    fun `相同密钥与 nonce 产出确定性密文`() {
        // GCM 不是随机化加密：nonce 由调用方保证唯一。这条确认实现没有偷偷加随机量，
        // 否则协议里的「nonce 即 AAD 的一部分」这一假设会失效。
        val key = repeatByte(0x11, 32)
        val nonce = repeatByte(0x22, Aead.NONCE_SIZE)
        val first = PlatformCrypto.aesGcmSeal(key, nonce, "same".encodeToByteArray(), "ctx".encodeToByteArray())
        val second = PlatformCrypto.aesGcmSeal(key, nonce, "same".encodeToByteArray(), "ctx".encodeToByteArray())

        assertEquals(first.toHex(), second.toHex())
    }

    @Test
    fun `randomBytes 长度与随机性`() {
        assertEquals(0, PlatformCrypto.randomBytes(0).size)
        assertEquals(32, PlatformCrypto.randomBytes(32).size)

        val a = PlatformCrypto.randomBytes(32)
        val b = PlatformCrypto.randomBytes(32)
        assertFalse(a.contentEquals(b), "两次随机输出不应相同")
        assertFalse(a.contentEquals(ByteArray(32)), "随机输出不应是全零")
    }

    @Test
    fun `wipe 会把缓冲区清零`() {
        val bytes = "top-secret-key-material".encodeToByteArray()
        PlatformCrypto.wipe(bytes)
        assertContentEquals(ByteArray(bytes.size), bytes)
    }

    @Test
    fun `后端标识非空可用于排障展示`() {
        assertTrue(PlatformCrypto.backendName.isNotBlank())
    }
}
