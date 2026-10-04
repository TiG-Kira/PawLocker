package com.kira.pawlocker.core.crypto

/**
 * AES-256-GCM 信封封装。
 *
 * 协议里所有机密内容都是 `nonce(12) || ciphertext+tag` 的形式，
 * 但本项目把 nonce 单独放在报文的 `nonce` 字段里，密文放 `ct` 字段，
 * 这样 AAD 里可以带上 nonce 之外的上下文（协议版本、设备 ID、计数器、时间戳），
 * 任何一个字段被中间人改动都会导致认证失败。
 */
object Aead {

    const val NONCE_SIZE = 12
    const val TAG_SIZE = 16

    fun seal(
        key: ByteArray,
        plaintext: ByteArray,
        aad: ByteArray,
        nonce: ByteArray = PlatformCrypto.randomBytes(NONCE_SIZE),
    ): SealedBox {
        require(nonce.size == NONCE_SIZE) { "nonce 必须为 $NONCE_SIZE 字节" }
        val ct = PlatformCrypto.aesGcmSeal(key, nonce, plaintext, aad)
        return SealedBox(nonce, ct)
    }

    fun open(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray, aad: ByteArray): ByteArray =
        PlatformCrypto.aesGcmOpen(key, nonce, ciphertext, aad)
}

data class SealedBox(val nonce: ByteArray, val ciphertext: ByteArray)

/**
 * 一次配对产生的长期密钥material。
 * `encode()` 后的字符串就是落盘/传输的形式。
 */
class PairSecret(
    /** 数据加密密钥 KEK */
    val encKey: ByteArray,
    /** 指令完整性密钥 KAK */
    val macKey: ByteArray,
) {

    /** 64 字节：encKey(32) || macKey(32) */
    fun encode(): String = Base64Url.encode(encKey + macKey)

    /** 双方人工比对的 SAS 短校验串（4 组 emoji，由 encKey 确定性派生）。 */
    val sas: List<String> get() = Sas.fromKey(encKey)

    fun wipe() {
        PlatformCrypto.wipe(encKey)
        PlatformCrypto.wipe(macKey)
    }

    companion object {

        const val ENCODED_SIZE = 64

        fun decode(encoded: String): PairSecret {
            val raw = Base64Url.decode(encoded)
            require(raw.size == ENCODED_SIZE) { "配对数密钥长度异常: ${raw.size}" }
            return PairSecret(
                encKey = raw.copyOfRange(0, 32),
                macKey = raw.copyOfRange(32, 64),
            )
        }

        /**
         * 由 ECDH 共享秘密派生。
         *
         * 参与派生的四样东西都进 salt / info：
         *  - 双方公钥（把身份绑进密钥）
         *  - `pairingId`（把「这一次配对」绑进去）
         *  - `windowsUserSid`（**把 Windows 账户绑进去** —— 三元绑定链的中间一环）
         *
         * 最后一条是关键：即使同一对设备、同一台电脑为两个不同的 Windows 账户
         * 各配一次对，派生出来的密钥也完全不同。于是「为账户 A 配对的手机」
         * 在密码学上就解不开账户 B 的指令 —— 不依赖任何一方的自觉检查。
         *
         * 字段之间插入分隔字节，避免拼接歧义（否则 A|BC 与 AB|C 会撞车）。
         */
        fun derive(
            sharedSecret: ByteArray,
            pairingId: String,
            windowsPublicKey: ByteArray,
            phonePublicKey: ByteArray,
            windowsUserSid: String,
        ): PairSecret {
            val salt = PlatformCrypto.sha256(
                windowsPublicKey + SEPARATOR +
                    phonePublicKey + SEPARATOR +
                    pairingId.encodeToByteArray() + SEPARATOR +
                    windowsUserSid.encodeToByteArray(),
            )
            return PairSecret(
                encKey = Hkdf.derive(sharedSecret, salt, ProtocolLabels.ENC_KEY, 32),
                macKey = Hkdf.derive(sharedSecret, salt, ProtocolLabels.MAC_KEY, 32),
            )
        }

        private val SEPARATOR = byteArrayOf(0x00)
    }
}

/**
 * HKDF 的 info 标签，集中管理，防止两处代码写错字符串导致密钥不一致。
 *
 * ## [KDF_VERSION] 与 `Protocol.VERSION` 是两件事
 *
 * `Protocol.VERSION` 说的是**线路格式**（报文里有哪些字段、判别值叫什么）；
 * [KDF_VERSION] 说的是**密钥派生方案**（salt/info 怎么拼、掺进哪些东西）。
 * 二者独立演进：v2 只是给线路加了账户绑定字段，派生方案的**结构**没变，
 * 但参与派生的输入变了 —— 这时就该抬 [KDF_VERSION]，
 * 让新旧密钥在派生域上彻底隔离，而不是指望 salt 恰好不同。
 *
 * 放在这里而不是引用 `Protocol.VERSION`，是为了不让 `crypto` 反向依赖
 * `protocol`（后者已经大量依赖前者）。
 */
object ProtocolLabels {

    /** 密钥派生方案的版本。改动 salt / info 的构造方式时必须 +1。 */
    const val KDF_VERSION = 2

    private const val NS = "PawLocker/v$KDF_VERSION"

    const val PAIRING_KEY = "$NS/pairing-protection"
    const val PAIRING_TAG = "$NS/pairing-confirm"
    const val ENC_KEY = "$NS/enc"
    const val MAC_KEY = "$NS/mac"
    const val UNLOCK_TAG = "$NS/unlock-signature"
}

/**
 * SAS（Short Authentication String）—— 配对完成后两端各显示同一组 emoji，
 * 用户肉眼比对一次，就能排除「中间人同时和两端各自完成配对」的可能。
 */
object Sas {

    private val EMOJI = listOf(
        "🐶", "🐱", "🦊", "🐻", "🐼", "🐨", "🐯", "🦁",
        "🐮", "🐷", "🐸", "🐵", "🐔", "🐧", "🦉", "🦄",
        "🍎", "🍊", "🍋", "🍉", "🍇", "🍓", "🍒", "🍑",
        "⚽", "🏀", "🏈", "🎾", "🎱", "🎯", "🎲", "🎸",
    )

    /** 从任意密钥材料确定性生成 4 个 emoji。 */
    fun fromKey(key: ByteArray, count: Int = 4): List<String> {
        val digest = PlatformCrypto.sha256(key + "sas".encodeToByteArray())
        return (0 until count).map { i ->
            EMOJI[(digest[i].toInt() and 0xFF) % EMOJI.size]
        }
    }
}
