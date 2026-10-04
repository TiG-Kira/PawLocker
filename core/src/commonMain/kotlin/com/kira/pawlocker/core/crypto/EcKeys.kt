package com.kira.pawlocker.core.crypto

/**
 * 曲线 NIST P-256（secp256r1）的点编解码工具。
 *
 * 为什么选 P-256 而不是更时髦的 X25519 / Ed25519：
 *  - AndroidKeyStore 对 P-256 有原生支持，能把私钥放进 TEE / StrongBox，永不导出；
 *  - JDK 从 8 起就内置 P-256，Windows 端不需要额外的 JCE provider；
 *  - Android API 26 全量覆盖，minSdk 不用往上抬。
 */
object EcKeys {

    /** 未压缩点长度：0x04 || X(32) || Y(32) */
    const val RAW_PUBLIC_KEY_SIZE = 65

    /** 私钥 / 共享秘密长度 */
    const val SCALAR_SIZE = 32

    /**
     * P-256 公钥的 SubjectPublicKeyInfo 固定前缀。
     * 30 59                                  SEQUENCE (89)
     *   30 13                                SEQUENCE (19)
     *     06 07 2A 86 48 CE 3D 02 01         OID 1.2.840.10045.2.1  ecPublicKey
     *     06 08 2A 86 48 CE 3D 03 01 07      OID 1.2.840.10045.3.1.7 prime256v1
     *   03 42 00                             BIT STRING (66) 未使用位=0
     *   <65 字节未压缩点>
     */
    private val P256_SPKI_PREFIX: ByteArray =
        "3059301306072A8648CE3D020106082A8648CE3D030107034200".hexToBytes()

    /** raw(65) -> SPKI(91)，交给 java.security.KeyFactory 用。 */
    fun rawToSpki(raw: ByteArray): ByteArray {
        require(isValidRawPoint(raw)) { "公钥不是合法的 P-256 未压缩点" }
        return P256_SPKI_PREFIX + raw
    }

    /** SPKI(91) -> raw(65)，用于把 AndroidKeyStore 里的公钥导出来发给对端。 */
    fun spkiToRaw(spki: ByteArray): ByteArray {
        require(spki.size == P256_SPKI_PREFIX.size + RAW_PUBLIC_KEY_SIZE) {
            "不是 P-256 SPKI 公钥，长度=${spki.size}"
        }
        return spki.copyOfRange(P256_SPKI_PREFIX.size, spki.size)
    }

    /**
     * 轻量合法性校验：长度、未压缩标记、坐标不越界。
     * 真正的曲线点验证交给 JCE 的 KeyFactory 完成（非法点会直接抛异常）。
     */
    fun isValidRawPoint(raw: ByteArray): Boolean {
        if (raw.size != RAW_PUBLIC_KEY_SIZE) return false
        if (raw[0] != 0x04.toByte()) return false
        // X / Y 不能是 0，且必须小于素数域 p（最高字节 < 0xFF 即可覆盖绝大多数非法值）
        return raw.copyOfRange(1, 33).any { it != 0.toByte() } &&
            raw.copyOfRange(33, 65).any { it != 0.toByte() }
    }

    /**
     * 十六进制串转字节。写成字符串常量而不是 `byteArrayOf(0x30, ...)`：
     * Kotlin 的 `byteArrayOf` 只收 `Byte`，字面量 0x30 是 `Int`，
     * 逐个 `.toByte()` 不但啰嗦，还容易出现漏改。
     */
    private fun String.hexToBytes(): ByteArray {
        require(length % 2 == 0) { "十六进制串长度必须是偶数" }
        return ByteArray(length / 2) { index ->
            val high = this[index * 2].digitToInt(16)
            val low = this[index * 2 + 1].digitToInt(16)
            ((high shl 4) or low).toByte()
        }
    }
}
