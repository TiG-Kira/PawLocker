package com.kira.pawlocker.core.trust

import com.kira.pawlocker.core.TestEnv
import com.kira.pawlocker.core.sampleRecord
import com.kira.pawlocker.core.protocol.Endpoint
import com.kira.pawlocker.core.protocol.TransportKind
import com.kira.pawlocker.core.crypto.Base64Url
import com.kira.pawlocker.core.crypto.PairSecret
import com.kira.pawlocker.core.crypto.PlatformCrypto
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * 信任列表的落盘与恢复。
 *
 * 这个文件是「攻击面最大、容错要求最高」的一处 ——
 * 它既要是持久的（重启后防重放基线不能丢），又要能识别并拒绝被篡改的内容。
 * 设计上宁可**整份丢弃**也不做部分恢复：一份被改过的信任列表，
 * 保留「能解析的那些条目」等于让攻击者用一条合法记录掩护一条非法记录。
 */
class FileTrustStoreTest {

    private fun store(prefix: String = "trust") = FileTrustStore(TestEnv.uniqueName(prefix))

    @Test
    fun `初始状态为空`() {
        val store = store()
        assertTrue(store.all().isEmpty())
        assertNull(store.byId("nobody"))
    }

    @Test
    fun `写入后可按设备 ID 读回`() {
        val store = store()
        val record = sampleRecord("device-1")
        store.upsert(record)

        assertEquals(1, store.all().size)
        assertEquals(record, store.byId("device-1"))
    }

    @Test
    fun `新实例从磁盘恢复`() {
        val name = TestEnv.uniqueName("persist")
        FileTrustStore(name).upsert(sampleRecord("device-1"))

        // 换一个实例，强制走磁盘读取路径（原实例有内存缓存）
        val reloaded = FileTrustStore(name)
        assertEquals(1, reloaded.all().size)
        assertEquals("device-1", reloaded.all().first().deviceId)
    }

    @Test
    fun `同一设备重复 upsert 是更新而不是追加`() {
        val store = store()
        store.upsert(sampleRecord("device-1", displayName = "旧名字"))
        store.upsert(sampleRecord("device-1", displayName = "新名字"))

        assertEquals(1, store.all().size)
        assertEquals("新名字", store.byId("device-1")!!.displayName)
    }

    @Test
    fun `多条记录顺序稳定`() {
        val store = store()
        val ids = listOf("a", "b", "c")
        ids.forEach { store.upsert(sampleRecord(it)) }

        assertEquals(ids, store.all().map { it.deviceId })

        // 更新中间一条不应改变顺序
        store.upsert(sampleRecord("b", displayName = "改了"))
        assertEquals(ids, store.all().map { it.deviceId })
    }

    @Test
    fun `删除只影响目标设备`() {
        val store = store()
        store.upsert(sampleRecord("a"))
        store.upsert(sampleRecord("b"))

        store.remove("a")
        assertEquals(listOf("b"), store.all().map { it.deviceId })
        assertNull(store.byId("a"))
    }

    @Test
    fun `删除不存在的设备是安全的空操作`() {
        val store = store()
        store.upsert(sampleRecord("a"))
        store.remove("does-not-exist")
        assertEquals(1, store.all().size)
    }

    @Test
    fun `clear 清空内存与磁盘`() {
        val name = TestEnv.uniqueName("clear")
        val store = FileTrustStore(name)
        store.upsert(sampleRecord("a"))
        assertTrue(TestEnv.secureFile(name).exists())

        store.clear()

        assertTrue(store.all().isEmpty())
        assertFalse(TestEnv.secureFile(name).exists(), "clear 之后磁盘文件应被删除")
    }

    @Test
    fun `端点列表完整往返`() {
        val name = TestEnv.uniqueName("endpoints")
        val endpoints = listOf(
            Endpoint(TransportKind.LAN, "192.168.1.10"),
            Endpoint(TransportKind.OVERLAY, "100.64.0.1", 9898, "Tailscale"),
            Endpoint(TransportKind.TUNNEL, "tunnel.example.com", 18989, "frp"),
            Endpoint(TransportKind.MANUAL, "10.0.0.9", 12345),
        )

        FileTrustStore(name).upsert(sampleRecord("pc-1").copy(endpoints = endpoints))

        assertEquals(endpoints, FileTrustStore(name).byId("pc-1")!!.endpoints)
    }

    @Test
    fun `计数器与 SAS 标记被持久化`() {
        val name = TestEnv.uniqueName("counter")
        val record = sampleRecord("phone-1").copy(
            lastCounter = 4242,
            sasVerified = true,
            lastSeenAt = 1_700_000_123_456L,
        )

        FileTrustStore(name).upsert(record)
        val reloaded = FileTrustStore(name).byId("phone-1")!!

        assertEquals(4242, reloaded.lastCounter, "重启后防重放基线必须能恢复")
        assertTrue(reloaded.sasVerified)
        assertEquals(1_700_000_123_456L, reloaded.lastSeenAt)
    }

    @Test
    fun `配对密钥可完整还原`() {
        val name = TestEnv.uniqueName("secret")
        val record = sampleRecord("phone-1")
        FileTrustStore(name).upsert(record)

        val original = record.resolveSecret()
        val restored = FileTrustStore(name).byId("phone-1")!!.resolveSecret()

        assertTrue(original.encKey.contentEquals(restored.encKey))
        assertTrue(original.macKey.contentEquals(restored.macKey))
        assertEquals(original.sas, restored.sas)
    }

    @Test
    fun `公钥字节可完整还原`() {
        val name = TestEnv.uniqueName("pubkey")
        val record = sampleRecord("phone-1")
        FileTrustStore(name).upsert(record)

        val restored = FileTrustStore(name).byId("phone-1")!!
        assertEquals(65, restored.publicKeyBytes().size)
        assertTrue(restored.publicKeyBytes().contentEquals(record.publicKeyBytes()))
    }

    @Test
    fun `磁盘上是密文而不是可读的信任列表`() {
        val name = TestEnv.uniqueName("encrypted")
        val secret = PairSecret(PlatformCrypto.randomBytes(32), PlatformCrypto.randomBytes(32)).encode()
        FileTrustStore(name).upsert(sampleRecord("phone-1").copy(secret = secret))

        val raw = TestEnv.secureFile(name).readBytes()

        // DPAPI 已启用时，磁盘内容不该出现任何 JSON 结构或密钥字段名
        val asText = raw.decodeToString()
        assertFalse(asText.contains("deviceId"), "磁盘上出现了明文 JSON 字段名")
        assertFalse(asText.contains("secret"))
        assertFalse(asText.contains(secret), "配对密钥以明文出现在磁盘上")
        assertFalse(asText.contains("records"))
    }

    @Test
    fun `文件被篡改时整份丢弃而不是部分加载`() {
        val name = TestEnv.uniqueName("corrupt")
        FileTrustStore(name).upsert(sampleRecord("a"))
        FileTrustStore(name).upsert(sampleRecord("b"))

        // 直接破坏磁盘上的密文（模拟被改过 / 半截写入 / 换了 DPAPI 用户）
        TestEnv.secureFile(name).writeBytes(byteArrayOf(9, 9, 9, 9))

        // 关键：不是「抛出异常」，也不是「加载出 0 条但保留文件」，
        // 而是当作没有信任记录 —— 用户需要重新配对，攻击者拿不到任何东西
        assertTrue(FileTrustStore(name).all().isEmpty())
    }

    @Test
    fun `内容合法但结构错误时也会被丢弃`() {
        val name = TestEnv.uniqueName("badschema")
        // 直接写一段能通过 DPAPI、但不是合法信封的内容
        com.kira.pawlocker.core.platform.PlatformEnv.writeSecure(
            name,
            "{\"schema\":1,\"records\":\"这不是数组\"}".encodeToByteArray(),
        )

        assertTrue(FileTrustStore(name).all().isEmpty())
    }

    @Test
    fun `空文件不会导致崩溃`() {
        val name = TestEnv.uniqueName("empty")
        com.kira.pawlocker.core.platform.PlatformEnv.writeSecure(name, ByteArray(0))
        assertTrue(FileTrustStore(name).all().isEmpty())
    }

    @Test
    fun `并发 upsert 不会丢记录`() {
        val name = TestEnv.uniqueName("concurrent")
        val store = FileTrustStore(name)
        val threads = (0 until 8).map { index ->
            Thread { repeat(20) { store.upsert(sampleRecord("device-${index * 20 + it}")) } }
        }
        threads.forEach { it.start() }
        threads.forEach { it.join() }

        // 整读整写的实现必须在锁保护下不丢更新；换实例从磁盘复读一次确认也确实落盘了
        assertEquals(160, FileTrustStore(name).all().size)
    }

    @Test
    fun `内存实现的行为与文件实现一致`() {
        val memory = InMemoryTrustStore()
        assertTrue(memory.all().isEmpty())

        memory.upsert(sampleRecord("a"))
        memory.upsert(sampleRecord("b"))
        assertEquals(listOf("a", "b"), memory.all().map { it.deviceId })

        memory.upsert(sampleRecord("a", displayName = "改名"))
        assertEquals("改名", memory.byId("a")!!.displayName)
        assertEquals(2, memory.all().size)

        memory.remove("a")
        assertEquals(listOf("b"), memory.all().map { it.deviceId })

        memory.clear()
        assertTrue(memory.all().isEmpty())
    }

    @Test
    fun `内存实现可用初始数据构造`() {
        val store = InMemoryTrustStore(listOf(sampleRecord("given")))
        assertEquals(1, store.all().size)
        assertFalse(store.all().first().secret.isBlank())
        // 配对数密钥是 64 字节（encKey 32 + macKey 32）
        assertEquals(64, Base64Url.decode(store.all().first().secret).size)
    }
}
