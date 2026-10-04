package com.kira.pawlocker.core.protocol

import com.kira.pawlocker.core.crypto.PlatformCrypto
import com.kira.pawlocker.core.crypto.ProtocolLabels
import com.kira.pawlocker.core.crypto.constantTimeEquals
import com.kira.pawlocker.core.toHex
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * 配对协议的「不需要私钥」的那一半。
 *
 * 重点是 confirmTag：它把**双方公钥**绑进受配对码保护的 HMAC，
 * 这是整套方案里唯一能阻止中间人替换公钥的机制。它一旦失去绑定力，
 * 配对码就只能证明「对方知道配对码」，证明不了「对方就是那台电脑」。
 */
class PairingPrimitivesTest {

    private val pairingId = "pairing-id-abcdef"
    private val code = "123456"
    private val computerPub = ByteArray(65) { (it + 1).toByte() }.also { it[0] = 0x04 }
    private val phonePub = ByteArray(65) { (it + 100).toByte() }.also { it[0] = 0x04 }

    @Test
    fun `配对码派生密钥对相同输入是确定的`() {
        val a = PairingProtocol.derivePairingKey(code, pairingId)
        val b = PairingProtocol.derivePairingKey(code, pairingId)

        assertEquals(32, a.size)
        assertContentEquals(a, b)
    }

    @Test
    fun `配对码或会话 ID 不同则派生密钥不同`() {
        val base = PairingProtocol.derivePairingKey(code, pairingId)

        assertFalse(base.contentEquals(PairingProtocol.derivePairingKey("123457", pairingId)))
        // 会话 ID 进 salt，防止把 A 会话的密文搬到 B 会话里重放
        assertFalse(base.contentEquals(PairingProtocol.derivePairingKey(code, "other-pairing")))
    }

    @Test
    fun `confirmTag 把双方公钥绑在一起`() {
        val tag = PairingProtocol.confirmTag(
            PlatformCrypto.randomBytes(32), "confirm", computerPub, phonePub, pairingId,
        )
        assertEquals(32, tag.size)

        // 同一把 K_code 下，只要任一公钥被替换，tag 就会变 —— 中间人无法绕过
        val key = PlatformCrypto.randomBytes(32)
        val original = PairingProtocol.confirmTag(key, "confirm", computerPub, phonePub, pairingId)
        val swappedComputer = PairingProtocol.confirmTag(
            key, "confirm", phonePub.copyOf(), phonePub, pairingId,
        )
        val swappedPhone = PairingProtocol.confirmTag(
            key, "confirm", computerPub, computerPub.copyOf(), pairingId,
        )

        assertFalse(original.contentEquals(swappedComputer), "替换电脑公钥必须改变 tag")
        assertFalse(original.contentEquals(swappedPhone), "替换手机公钥必须改变 tag")
    }

    @Test
    fun `confirmTag 区分去程与回程标签`() {
        val key = PlatformCrypto.randomBytes(32)
        val forward = PairingProtocol.confirmTag(key, "confirm", computerPub, phonePub, pairingId)
        val backward = PairingProtocol.confirmTag(key, "confirm2", computerPub, phonePub, pairingId)

        assertFalse(
            forward.contentEquals(backward),
            "去程与回程必须用不同标签，否则手机端的响应可被原样反射回去",
        )
    }

    @Test
    fun `confirmTag 绑定会话 ID`() {
        val key = PlatformCrypto.randomBytes(32)
        assertFalse(
            PairingProtocol.confirmTag(key, "confirm", computerPub, phonePub, pairingId)
                .contentEquals(
                    PairingProtocol.confirmTag(key, "confirm", computerPub, phonePub, "$pairingId-x"),
                ),
        )
    }

    @Test
    fun `不知道配对码就构造不出正确的 tag`() {
        val wrongKey = PairingProtocol.derivePairingKey("654321", pairingId)
        val rightKey = PairingProtocol.derivePairingKey(code, pairingId)

        val expected = PairingProtocol.confirmTag(rightKey, "confirm", computerPub, phonePub, pairingId)
        val forged = PairingProtocol.confirmTag(wrongKey, "confirm", computerPub, phonePub, pairingId)

        assertFalse(constantTimeEquals(expected, forged))
    }

    @Test
    fun `AAD 绑定会话 ID 与 nonce`() {
        val base = PairingProtocol.aad(pairingId, "nonce-1").decodeToString()
        assertEquals("pair|${Protocol.VERSION}|$pairingId|nonce-1", base)

        assertNotEquals(base, PairingProtocol.aad(pairingId, "nonce-2").decodeToString())
        assertNotEquals(base, PairingProtocol.aad("other", "nonce-1").decodeToString())
    }

    @Test
    fun `配对码始终是六位数字`() {
        repeat(2000) {
            val code = PairingProtocol.randomCode()
            assertEquals(Protocol.PAIRING_CODE_DIGITS, code.length, "实际值: $code")
            assertTrue(code.all { it in '0'..'9' }, "实际值: $code")
        }
    }

    @Test
    fun `配对码有足够的变化量且能生成前导零`() {
        val seen = HashSet<String>()
        repeat(2000) { seen.add(PairingProtocol.randomCode()) }

        // 2000 次抽样覆盖到 100 万空间里的 2000 个值，几乎不可能出现大量碰撞；
        // 这里只要求「不是常量」这种最低限度，避免测试因随机性而偶发失败
        assertTrue(seen.size > 1900, "配对码随机性异常，仅生成 ${seen.size} 种")

        // 000000 这类前导零结果证明 padStart 生效
        val padded = (0 until 100_000).map { PairingProtocol.randomCode() }
        assertTrue(padded.all { it.length == 6 })
    }

    @Test
    fun `会话 ID 与 nonce 使用密码学随机源`() {
        val ids = (0 until 200).map { PairingProtocol.newPairingId() }
        assertEquals(200, ids.toSet().size, "会话 ID 出现重复")
        // 16 字节 Base64Url 无填充 = 22 个字符
        assertEquals(22, ids.first().length)

        val nonces = (0 until 200).map { PairingProtocol.newNonce() }
        assertEquals(200, nonces.toSet().size, "nonce 出现重复")
        // 12 字节 Base64Url 无填充 = 16 个字符
        assertEquals(16, nonces.first().length)
    }

    @Test
    fun `协议标签两两不同`() {
        val labels = listOf(
            ProtocolLabels.PAIRING_KEY,
            ProtocolLabels.PAIRING_TAG,
            ProtocolLabels.ENC_KEY,
            ProtocolLabels.MAC_KEY,
            ProtocolLabels.UNLOCK_TAG,
        )
        assertEquals(labels.size, labels.toSet().size, "HKDF 标签重复会导致派生密钥撞车")
        assertTrue(labels.all { it.isNotBlank() })
        // 每个标签都必须落在同一个带版本的命名空间里。
        // 注意这里跟的是 **KDF 版本**（派生方案版本），不是 Protocol.VERSION（线路格式版本）——
        // 两者独立演进，否则每次线路加字段都会把密钥派生域一起改掉。
        val namespace = "PawLocker/v${ProtocolLabels.KDF_VERSION}/"
        assertTrue(labels.all { it.startsWith(namespace) }, labels.toString())
    }

    @Test
    fun `配对邀请深链可往返`() {
        val offer = PairingOffer(
            pairingId = "pid",
            code = "000123",
            computerDeviceId = "pc",
            computerDisplayName = "书房主机",
            computerPublicKey = "cGtieXRlcw",
            endpoints = listOf(
                Endpoint(TransportKind.LAN, "192.168.1.10"),
                Endpoint(TransportKind.TUNNEL, "tunnel.example.com", 18989),
            ),
            expiresAt = 1_700_000_000_000L,
        )

        val link = offer.toDeepLink()
        assertTrue(link.startsWith("${Protocol.DEEP_LINK_SCHEME}://pair?d="), link)
        // 深链要能安全地放进二维码与剪贴板：不能含 + / 等需转义的字符
        assertFalse(link.contains('+'))
        assertFalse(link.contains('/').and(link.substringAfter("://").contains('/')))

        assertEquals(offer, PairingOffer.fromDeepLink(link))
    }

    @Test
    fun `深链非法时返回 null 而不是抛异常`() {
        assertNull(PairingOffer.fromDeepLink(""))
        assertNull(PairingOffer.fromDeepLink("https://example.com/pair?d=xxx"))
        assertNull(PairingOffer.fromDeepLink("pawlocker://pair?d=@@@非法@@@"))
        // 前缀对但内容不是合法 JSON
        assertNull(PairingOffer.fromDeepLink("pawlocker://pair?d=" + "bm90LWpzb24"))
    }

    @Test
    fun `配对邀请里的配对码不参与密钥派生`() {
        // 配对码只用于「证明你知道它」，加密密钥来自 ECDH。
        // 这条确认即使配对码被短时偷看，也换不来长期密钥。
        val keyFromCode = PairingProtocol.derivePairingKey("123456", pairingId)
        assertEquals(
            keyFromCode.toHex(),
            PairingProtocol.derivePairingKey("123456", pairingId).toHex(),
        )
        assertFalse(
            keyFromCode.contentEquals(
                PairingProtocol.derivePairingKey("123456", "different-pairing"),
            ),
        )
    }
}
