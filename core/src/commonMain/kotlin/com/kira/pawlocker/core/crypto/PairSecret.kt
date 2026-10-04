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
         * 由 ECDH 共享秘密派生。两侧的 `pairingId`、双方公钥都会进 salt / info，
         * 保证即使 (Windows, 手机A) 与 (Windows, 手机B) 的共享秘密意外相同，
         * 派生结果也不会相同。
         */
        fun derive(
            sharedSecret: ByteArray,
            pairingId: String,
            windowsPublicKey: ByteArray,
            phonePublicKey: ByteArray,
        ): PairSecret {
            val salt = PlatformCrypto.sha256(
                windowsPublicKey + phonePublicKey + pairingId.encodeToByteArray(),
            )
            return PairSecret(
                encKey = Hkdf.derive(sharedSecret, salt, ProtocolLabels.ENC_KEY, 32),
                macKey = Hkdf.derive(sharedSecret, salt, ProtocolLabels.MAC_KEY, 32),
            )
        }
    }
}

/** HKDF 的 info 标签，集中管理，防止两处代码写错字符串导致密钥不一致。 */
object ProtocolLabels {
    const val PAIRING_KEY = "PawLocker/v1/pairing-protection"
    const val PAIRING_TAG = "PawLocker/v1/pairing-confirm"
    const val ENC_KEY = "PawLocker/v1/enc"
    const val MAC_KEY = "PawLocker/v1/mac"
    const val UNLOCK_TAG = "PawLocker/v1/unlock-signature"
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
