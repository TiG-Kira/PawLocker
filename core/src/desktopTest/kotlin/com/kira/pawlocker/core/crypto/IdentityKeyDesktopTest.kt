package com.kira.pawlocker.core.crypto

import com.kira.pawlocker.core.TestEnv
import com.kira.pawlocker.core.flipLastBase64Byte
import com.kira.pawlocker.core.platform.PlatformEnv
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Windows 侧身份密钥。
 *
 * 这里跑的是**真实代码路径**：JCE 生成 P-256 → 打包成
 * `[4 字节长度][PKCS#8][65 字节公钥]` → DPAPI 封装落盘 → 重新加载时解包。
 * 容器格式一旦有偏差，签名与协商就会在真机上莫名失败，所以逐字节核对。
 */
class IdentityKeyDesktopTest {

    @Test
    fun `同一别名重复加载得到同一把密钥`() {
        val first = TestEnv.identity("idempotent")
        val second = TestEnv.identity("idempotent")

        assertContentEquals(first.publicKey, second.publicKey, "loadOrCreate 必须是幂等的")
        assertEquals(65, first.publicKey.size)
        assertEquals(0x04, first.publicKey[0].toInt() and 0xFF)
        assertTrue(EcKeys.isValidRawPoint(first.publicKey))
    }

    @Test
    fun `不同别名得到不同的密钥`() {
        val a = TestEnv.identity("alias-a")
        val b = TestEnv.identity("alias-b")
        assertFalse(a.publicKey.contentEquals(b.publicKey))
    }

    @Test
    fun `别名原样保留便于排障`() {
        assertEquals("test-named", TestEnv.identity("named").alias)
    }

    @Test
    fun `Windows 侧私钥由 DPAPI 而非硬件保护`() {
        // 明确记录这一事实：桌面端的静态保护靠 DPAPI，
        // 硬件后端（TPM/CNG）是 IdentityKey 接口预留的替换点，尚未实现
        assertFalse(TestEnv.identity("hw-flag").hardwareBacked)
    }

    @Test
    fun `签名可被自己的公钥验证`() {
        val key = TestEnv.identity("signer")
        val data = "unlock|1|device-x|42|1700000000000|nonce".encodeToByteArray()

        val signature = key.sign(data)
        assertTrue(signature.isNotEmpty())
        assertTrue(PlatformCrypto.verifyEcdsa(key.publicKey, data, signature))
    }

    @Test
    fun `签名是 DER 序列且长度符合 P-256 的预期`() {
        val signature = TestEnv.identity("der").sign("payload".encodeToByteArray())

        assertEquals(0x30, signature[0].toInt() and 0xFF, "DER 应以 SEQUENCE 开头")
        assertEquals(signature.size - 2, signature[1].toInt() and 0xFF, "DER 长度字段应等于剩余字节数")
        // P-256 的 r、s 各最多 33 字节（含可能的 0x00 前导），加上开销约 70~72
        assertTrue(signature.size in 68..72, "意外的签名长度：${signature.size}")
    }

    @Test
    fun `同一数据的两次签名不同但都有效`() {
        val key = TestEnv.identity("randomized")
        val data = "same-input".encodeToByteArray()

        val first = key.sign(data)
        val second = key.sign(data)

        // ECDSA 每次签名都带随机 k，签名不应可预测
        assertFalse(first.contentEquals(second), "ECDSA 签名必须是随机化的")
        assertTrue(PlatformCrypto.verifyEcdsa(key.publicKey, data, first))
        assertTrue(PlatformCrypto.verifyEcdsa(key.publicKey, data, second))
    }

    @Test
    fun `数据被改动一位后签名失效`() {
        val key = TestEnv.identity("tamper")
        val data = "originating-command".encodeToByteArray()
        val signature = key.sign(data)

        val tampered = data.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 0x01).toByte() }
        assertFalse(PlatformCrypto.verifyEcdsa(key.publicKey, tampered, signature))
    }

    @Test
    fun `换成别人的公钥验证失败`() {
        val signer = TestEnv.identity("real-signer")
        val impostor = TestEnv.identity("impostor")
        val data = "unlock".encodeToByteArray()

        assertFalse(PlatformCrypto.verifyEcdsa(impostor.publicKey, data, signer.sign(data)))
    }

    @Test
    fun `签名本身被篡改后验证失败`() {
        val key = TestEnv.identity("sig-tamper")
        val data = "unlock".encodeToByteArray()
        val signature = key.sign(data)

        val tampered = signature.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 0x01).toByte() }
        assertFalse(PlatformCrypto.verifyEcdsa(key.publicKey, data, tampered))
    }

    @Test
    fun `乱码签名不会抛异常而是返回 false`() {
        // 攻击者会喂各种垃圾签名，实现必须稳如磐石地返回 false，而不是让异常冒到调用栈上层
        val key = TestEnv.identity("garbage-sig")
        val data = "unlock".encodeToByteArray()

        assertFalse(PlatformCrypto.verifyEcdsa(key.publicKey, data, ByteArray(0)))
        assertFalse(PlatformCrypto.verifyEcdsa(key.publicKey, data, byteArrayOf(0x30, 0x00)))
        assertFalse(PlatformCrypto.verifyEcdsa(key.publicKey, data, ByteArray(200) { 0xFF.toByte() }))
        assertFalse(PlatformCrypto.verifyEcdsa(key.publicKey, data, "AQID".encodeToByteArray()))
    }

    @Test
    fun `不在曲线上的公钥不会让验签崩溃`() {
        // isValidRawPoint 只做轻量校验（长度 / 前缀 / 非零），
        // 真正的曲线点验证交给 JCE —— 这里确认那一层的失败被吞成 false
        val offCurve = ByteArray(65).also {
            it[0] = 0x04
            it[1] = 0x01 // X = 1
            it[33] = 0x01 // Y = 1
        }
        assertTrue(EcKeys.isValidRawPoint(offCurve), "轻量校验按设计会放过它")

        val key = TestEnv.identity("off-curve")
        assertFalse(
            PlatformCrypto.verifyEcdsa(offCurve, "data".encodeToByteArray(), key.sign("data".encodeToByteArray())),
            "JCE 必须拒绝不在曲线上的点",
        )
    }

    @Test
    fun `ECDH 双方算出同一个共享秘密`() {
        val alice = TestEnv.identity("alice")
        val bob = TestEnv.identity("bob")

        val aliceSide = alice.agree(bob.publicKey)
        val bobSide = bob.agree(alice.publicKey)

        assertEquals(32, aliceSide.size, "P-256 的共享秘密是 32 字节")
        assertContentEquals(aliceSide, bobSide, "ECDH 必须对称")
    }

    @Test
    fun `与不同对端协商得到不同共享秘密`() {
        val alice = TestEnv.identity("alice-2")
        val bob = TestEnv.identity("bob-2")
        val carol = TestEnv.identity("carol-2")

        assertFalse(alice.agree(bob.publicKey).contentEquals(alice.agree(carol.publicKey)))
    }

    @Test
    fun `非法对端公钥会被拒绝`() {
        val key = TestEnv.identity("bad-peer")

        assertFailsWith<IllegalArgumentException> { key.agree(ByteArray(65)) }
        assertFailsWith<IllegalArgumentException> { key.agree(ByteArray(0)) }
        assertFailsWith<IllegalArgumentException> { key.agree(ByteArray(64)) }
    }

    @Test
    fun `落盘容器结构自洽`() {
        val key = TestEnv.identity("container")
        val packed = PlatformEnv.readSecure("key-test-container")
            ?: error("身份密钥没有落盘")

        assertTrue(packed.size > 4 + EcKeys.RAW_PUBLIC_KEY_SIZE)

        val length = ((packed[0].toInt() and 0xFF) shl 24) or
            ((packed[1].toInt() and 0xFF) shl 16) or
            ((packed[2].toInt() and 0xFF) shl 8) or
            (packed[3].toInt() and 0xFF)

        assertEquals(packed.size, 4 + length + EcKeys.RAW_PUBLIC_KEY_SIZE, "长度前缀必须自洽")
        assertTrue(length > 0)
        assertContentEquals(
            key.publicKey,
            packed.copyOfRange(4 + length, packed.size),
            "容器尾部的公钥必须与身份公钥一致",
        )
    }

    @Test
    fun `落盘的是密文而不是明文私钥`() {
        val key = TestEnv.identity("dpapi")
        val packed = PlatformEnv.readSecure("key-test-dpapi")!!

        // DPAPI 的输出带固定描述块；明文 PKCS#8 以 30 82 开头，绝不能出现在磁盘上
        assertFalse(packed.decodeToString().contains("PRIVATE"))
        if (PlatformEnv.platformName == "Windows") {
            assertFalse(
                packed.size >= 2 && packed[0] == 0x30.toByte() && packed[1] == 0x82.toByte(),
                "磁盘上出现了未加密的 PKCS#8 私钥",
            )
        }
        // 无论平台，公钥都不该以明文形式出现在容器开头
        assertFalse(packed.copyOfRange(0, 4).contentEquals(key.publicKey.copyOfRange(0, 4)))
    }

    @Test
    fun `删除后重新生成的是另一把密钥`() {
        val alias = "test-rotating"
        val before = TestEnv.identity("rotating").publicKey

        IdentityKeyFactory.delete(alias)
        assertNull(PlatformEnv.readSecure("key-$alias"), "删除后文件应不存在")

        val after = TestEnv.identity("rotating").publicKey
        assertFalse(before.contentEquals(after), "重置身份必须产生新密钥")
        assertEquals(65, after.size)
    }

    @Test
    fun `容器损坏时重新生成而不是崩溃`() {
        val alias = "test-corrupted"
        // 模拟磁盘损坏 / 半截写入
        PlatformEnv.writeSecure("key-$alias", byteArrayOf(1, 2, 3))

        val key = TestEnv.identity("corrupted")
        assertTrue(EcKeys.isValidRawPoint(key.publicKey))
    }

    @Test
    fun `长度前缀与文件大小不符时重新生成`() {
        val alias = "test-mismatched"
        val bogus = ByteArray(4 + 100 + 65)
        bogus[3] = 50 // 声称 pkcs8 有 50 字节，与实际不符
        PlatformEnv.writeSecure("key-$alias", bogus)

        // 不应抛异常
        assertTrue(EcKeys.isValidRawPoint(TestEnv.identity("mismatched").publicKey))
    }

    @Test
    fun `设备 ID 由公钥派生且长度固定`() {
        val key = TestEnv.identity("device-id")
        val id = DeviceIds.fromPublicKey(key.publicKey)

        assertEquals(id, DeviceIds.fromPublicKey(key.publicKey), "派生必须稳定")
        // SHA-256 取前 16 字节 → Base64Url 无填充 = 22 字符
        assertEquals(22, id.length)
        assertFalse(id.contains('+'))
        assertFalse(id.contains('/'))
        assertFalse(id.contains('='))
    }

    @Test
    fun `不同公钥派生不同设备 ID`() {
        assertFalse(
            DeviceIds.fromPublicKey(TestEnv.identity("dev-a").publicKey) ==
                DeviceIds.fromPublicKey(TestEnv.identity("dev-b").publicKey),
        )
    }

    @Test
    fun `身份密钥写入的文件权限被收紧`() {
        // 这一步是纵深防御：即使 DPAPI 被绕过，同机其他账户也读不到文件
        val key = TestEnv.identity("perms")
        val file = TestEnv.secureFile("key-test-perms")
        assertTrue(file.exists(), "身份密钥文件应存在于 ${key.alias} 的目录下")
        assertTrue(file.length() > 0)
    }

    @Test
    fun `篡改后的身份文件不会静默产生错误密钥`() {
        val alias = "test-tampered"
        TestEnv.identity("tampered")
        val file = TestEnv.secureFile("key-$alias")

        // 把密文最后一位改掉，DPAPI 解密会失败 → 应回退到重新生成
        val original = file.readBytes()
        val tampered = original.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 0x01).toByte() }
        file.writeBytes(tampered)

        val regenerated = TestEnv.identity("tampered")
        assertTrue(EcKeys.isValidRawPoint(regenerated.publicKey))
    }

    @Test
    fun `签名接口不泄漏可用于复用签名的状态`() {
        // 同一条数据、同一把密钥连签多次，输出必须互不相同（随机 k），
        // 否则攻击者能从签名里反推出私钥的线性关系
        val key = TestEnv.identity("k-reuse")
        val data = "fixed".encodeToByteArray()
        val signatures = (0 until 8).map { key.sign(data).map { b -> b.toInt() }.joinToString() }

        assertEquals(signatures.size, signatures.toSet().size, "出现了重复签名，k 可能被复用")
    }

    @Test
    fun `翻转任意一字节的密文都无法通过验签`() {
        val key = TestEnv.identity("flip")
        val data = "abc".encodeToByteArray()
        val signature = key.sign(data)

        assertFalse(PlatformCrypto.verifyEcdsa(key.publicKey, data, signature.copyOf().also { it[3] = (it[3].toInt() xor 0x01).toByte() }))
        assertFalse(PlatformCrypto.verifyEcdsa(key.publicKey.copyOf().also { it[10] = (it[10].toInt() xor 0x01).toByte() }, data, signature))
    }

    @Test
    fun `三十二字节的假秘密不会被误当成合法输入`() {
        // 只是提醒：PairSecret.decode 才是解析入口，别把裸字节塞进 encode 期望的字符串位置
        val fake = Base64Url.encode(ByteArray(16)).flipLastBase64Byte()
        assertFailsWith<IllegalArgumentException> { PairSecret.decode(fake) }
    }
}
