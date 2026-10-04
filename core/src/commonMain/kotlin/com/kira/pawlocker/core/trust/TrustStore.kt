package com.kira.pawlocker.core.trust

import com.kira.pawlocker.core.crypto.PairSecret
import com.kira.pawlocker.core.platform.PlatformEnv
import com.kira.pawlocker.core.protocol.Endpoint
import kotlinx.serialization.Serializable

/** 记录里保存的是「对方」的角色。 */
@Serializable
enum class PeerRole {
    /** Windows 电脑（手机端保存这个） */
    COMPUTER,

    /** Android 手机（Windows 端保存这个） */
    PHONE,
}

/**
 * 一条信任关系。
 *
 * 注意 [secret] 落盘前会再经过平台静态加密：
 *  - Windows：整份信任列表文件由 DPAPI 封装
 *  - Android：文件位于应用私有目录，且身份私钥在 AndroidKeyStore 中不可导出
 *
 * 即使有人把文件拷走，没有当前用户的 DPAPI 主密钥也解不开。
 */
@Serializable
data class TrustRecord(
    val deviceId: String,
    val role: PeerRole,
    val displayName: String,
    val model: String,
    val platform: String,
    /** Base64Url(65 字节未压缩点) */
    val publicKey: String,
    /** Base64Url(encKey 32 + macKey 32) */
    val secret: String,
    /** 仅 COMPUTER 记录有意义：手机端连接时按序尝试 */
    val endpoints: List<Endpoint> = emptyList(),
    val pairedAt: Long,
    val lastSeenAt: Long = 0,
    /** Windows 侧使用：该手机最后一次成功使用的计数器，重启后据此恢复防重放基线 */
    val lastCounter: Long = 0,
    /** 用户是否已经人工比对过 SAS emoji */
    val sasVerified: Boolean = false,
) {

    fun resolveSecret(): PairSecret = PairSecret.decode(secret)

    fun publicKeyBytes(): ByteArray =
        com.kira.pawlocker.core.crypto.Base64Url.decode(publicKey)
}

/**
 * 信任列表存储。读写整份列表，不做增量 —— 条目数量级是「个位数手机」，
 * 整读整写反而更容易保证一致性，避免出现半截更新。
 */
interface TrustStore {

    fun all(): List<TrustRecord>

    fun byId(deviceId: String): TrustRecord?

    fun upsert(record: TrustRecord)

    fun remove(deviceId: String)

    fun clear()
}

/**
 * 基于平台静态加密文件的默认实现。
 * 文件名固定为 `trust-store.json`。
 */
class FileTrustStore(
    private val fileName: String = "trust-store.json",
) : TrustStore {

    @Serializable
    private data class Envelope(
        val schema: Int = SCHEMA,
        val records: List<TrustRecord> = emptyList(),
    )

    private val lock = Any()

    @Volatile
    private var cache: MutableList<TrustRecord>? = null

    override fun all(): List<TrustRecord> = synchronized(lock) { load().toList() }

    override fun byId(deviceId: String): TrustRecord? =
        synchronized(lock) { load().firstOrNull { it.deviceId == deviceId } }

    override fun upsert(record: TrustRecord) = synchronized(lock) {
        val list = load()
        val index = list.indexOfFirst { it.deviceId == record.deviceId }
        if (index >= 0) list[index] = record else list.add(record)
        persist(list)
    }

    override fun remove(deviceId: String) = synchronized(lock) {
        val list = load()
        if (list.removeAll { it.deviceId == deviceId }) persist(list)
    }

    override fun clear() = synchronized(lock) {
        cache = mutableListOf()
        PlatformEnv.deleteSecure(fileName)
    }

    private fun load(): MutableList<TrustRecord> {
        cache?.let { return it }
        val raw = PlatformEnv.readSecure(fileName)
        val records = if (raw == null) {
            mutableListOf()
        } else {
            runCatching {
                WireJson.decodeFromString(Envelope.serializer(), raw.decodeToString())
            }.getOrElse { error ->
                // 解密/解析失败一律当作「没有信任记录」处理：
                // 宁可让用户重新配对，也不能让一份损坏或被篡改的列表蒙混过关。
                PlatformEnv.log(TAG, "信任列表损坏，已丢弃: ${error.message}")
                Envelope()
            }.records.toMutableList()
        }
        cache = records
        return records
    }

    private fun persist(records: List<TrustRecord>) {
        val text = WireJson.encodeToString(Envelope.serializer(), Envelope(records = records))
        PlatformEnv.writeSecure(fileName, text.encodeToByteArray())
        cache = records.toMutableList()
    }

    private companion object {
        const val SCHEMA = 1
        const val TAG = "FileTrustStore"
    }
}

/** 进程内实现，用于单元测试与预览。 */
class InMemoryTrustStore(
    initial: List<TrustRecord> = emptyList(),
) : TrustStore {

    private val records = initial.toMutableList()

    override fun all(): List<TrustRecord> = records.toList()
    override fun byId(deviceId: String): TrustRecord? = records.firstOrNull { it.deviceId == deviceId }
    override fun upsert(record: TrustRecord) {
        records.removeAll { it.deviceId == record.deviceId }
        records.add(record)
    }

    override fun remove(deviceId: String) {
        records.removeAll { it.deviceId == deviceId }
    }

    override fun clear() = records.clear()
}

/** 信任列表专用的 JSON 配置：严格、自描述。 */
internal val WireJson = kotlinx.serialization.json.Json {
    encodeDefaults = true
    ignoreUnknownKeys = false
    prettyPrint = true
}
