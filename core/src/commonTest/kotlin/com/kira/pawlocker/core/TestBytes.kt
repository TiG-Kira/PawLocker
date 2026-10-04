package com.kira.pawlocker.core

/**
 * 测试专用的十六进制工具。
 *
 * 官方测试向量（RFC 5869 / RFC 4231 / NIST）都以十六进制串给出，
 * 直接抄进测试比手工敲 `byteArrayOf(0x0b, 0x0b, ...)` 可靠得多 ——
 * 抄错一个字节会让「实现有 bug」和「向量抄错」变得无法区分。
 */
internal fun String.hexToBytes(): ByteArray {
    val clean = filterNot { it.isWhitespace() }
    require(clean.length % 2 == 0) { "十六进制串长度必须是偶数：$clean" }
    return ByteArray(clean.length / 2) { index ->
        val high = clean[index * 2].digitToInt(16)
        val low = clean[index * 2 + 1].digitToInt(16)
        ((high shl 4) or low).toByte()
    }
}

internal fun ByteArray.toHex(): String =
    joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }

/** 重复某个字节若干次，用于构造 RFC 里的 `0x0b` * 22 这类输入。 */
internal fun repeatByte(value: Int, count: Int): ByteArray =
    ByteArray(count) { value.toByte() }

/** 顺序递增的字节序列 `00 01 02 ...`，长度不足时按 256 取模回绕。 */
internal fun sequentialBytes(count: Int, start: Int = 0): ByteArray =
    ByteArray(count) { (start + it).toByte() }

/**
 * 把 Base64Url 串的最后一个字节翻转一位，用于「篡改密文」类负向测试。
 *
 * 刻意不用随机替换：翻转一位是攻击者最容易做到、也最难被随机性掩盖的篡改方式。
 */
internal fun String.flipLastBase64Byte(): String {
    val bytes = com.kira.pawlocker.core.crypto.Base64Url.decode(this)
    require(bytes.isNotEmpty()) { "无法篡改空串" }
    val tampered = bytes.copyOf()
    tampered[tampered.size - 1] = (tampered[tampered.size - 1].toInt() xor 0x01).toByte()
    return com.kira.pawlocker.core.crypto.Base64Url.encode(tampered)
}
