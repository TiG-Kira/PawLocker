package com.kira.pawlocker.core.crypto

private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

/**
 * URL 安全 Base64（RFC 4648 §5）。协议中所有二进制字段都以此编码成字符串，
 * 这样整条报文就是一个可读的 JSON，方便抓包排查，又不牺牲二进制安全性。
 */
object Base64Url {

    fun encode(bytes: ByteArray, padding: Boolean = false): String {
        val sb = StringBuilder((bytes.size + 2) / 3 * 4)
        var i = 0
        while (i < bytes.size) {
            val b0 = bytes[i].toInt() and 0xFF
            val b1 = if (i + 1 < bytes.size) bytes[i + 1].toInt() and 0xFF else -1
            val b2 = if (i + 2 < bytes.size) bytes[i + 2].toInt() and 0xFF else -1

            sb.append(ALPHABET[b0 shr 2])
            if (b1 < 0) {
                sb.append(ALPHABET[(b0 and 0x03) shl 4])
                if (padding) sb.append("==")
            } else {
                sb.append(ALPHABET[((b0 and 0x03) shl 4) or (b1 shr 4)])
                if (b2 < 0) {
                    sb.append(ALPHABET[(b1 and 0x0F) shl 2])
                    if (padding) sb.append('=')
                } else {
                    sb.append(ALPHABET[((b1 and 0x0F) shl 2) or (b2 shr 6)])
                    sb.append(ALPHABET[b2 and 0x3F])
                }
            }
            i += 3
        }
        return sb.toString()
    }

    fun decode(text: String): ByteArray {
        val clean = text.filter { it != '=' && it != '\n' && it != '\r' }
        val out = ByteArray(clean.length * 3 / 4)
        var buffer = 0
        var bits = 0
        var index = 0
        for (ch in clean) {
            val value = indexOf(ch)
            require(value >= 0) { "非法 Base64Url 字符: '$ch'" }
            buffer = (buffer shl 6) or value
            bits += 6
            if (bits >= 8) {
                bits -= 8
                out[index++] = ((buffer shr bits) and 0xFF).toByte()
            }
        }
        return if (index == out.size) out else out.copyOf(index)
    }

    private fun indexOf(ch: Char): Int = when (ch) {
        in 'A'..'Z' -> ch - 'A'
        in 'a'..'z' -> ch - 'a' + 26
        in '0'..'9' -> ch - '0' + 52
        '-' -> 62
        '_' -> 63
        else -> -1
    }
}

/** 把 ByteArray 转成便于日志展示的短十六进制串（只用于调试输出）。 */
fun ByteArray.toHexShort(limit: Int = 8): String =
    take(limit).joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }

/** 定长比较，避免计时侧信道。 */
fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
    if (a.size != b.size) return false
    var diff = 0
    for (i in a.indices) diff = diff or (a[i].toInt() xor b[i].toInt())
    return diff == 0
}
