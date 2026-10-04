package com.kira.pawlocker.core.crypto

/**
 * HKDF-SHA256（RFC 5869）。
 *
 * 两端所有「从一个共享秘密派生出多条用途不同的密钥」的地方都走这里：
 * 加密密钥、MAC 密钥、配对码保护密钥、SAS 校验串，全部带独立的 info 标签，
 * 保证密钥之间互相不可推导。
 */
object Hkdf {

    private const val HASH_LEN = 32

    /** RFC 5869 §2.2 —— 提取阶段。salt 为空时退化为全零盐。 */
    fun extract(salt: ByteArray, ikm: ByteArray): ByteArray {
        val effectiveSalt = if (salt.isEmpty()) ByteArray(HASH_LEN) else salt
        return PlatformCrypto.hmacSha256(effectiveSalt, ikm)
    }

    /** RFC 5869 §2.3 —— 扩展阶段。 */
    fun expand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        require(length in 1..(255 * HASH_LEN)) { "HKDF 输出长度越界: $length" }
        val blocks = (length + HASH_LEN - 1) / HASH_LEN
        val okm = ByteArray(length)
        var previous = ByteArray(0)
        var offset = 0
        for (counter in 1..blocks) {
            val input = previous + info + byteArrayOf(counter.toByte())
            previous = PlatformCrypto.hmacSha256(prk, input)
            val take = minOf(HASH_LEN, length - offset)
            previous.copyInto(okm, offset, 0, take)
            offset += take
        }
        return okm
    }

    /** 一步式派生，日常调用用这个。 */
    fun derive(ikm: ByteArray, salt: ByteArray, info: String, length: Int = 32): ByteArray =
        expand(extract(salt, ikm), info.encodeToByteArray(), length)
}
