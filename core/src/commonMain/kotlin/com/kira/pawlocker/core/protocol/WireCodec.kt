package com.kira.pawlocker.core.protocol

/**
 * 线路编码。
 *
 * 帧格式：`[4 字节大端长度][JSON 报文]`
 *
 * 所有二进制字段（公钥、nonce、密文、签名）都以 Base64Url 编码进 JSON，
 * 好处是抓包可读、跨语言实现友好；代价是约 33% 的带宽开销，
 * 对于「一条解锁指令」这种量级（几百字节）完全可以忽略。
 */
object WireCodec {

    val json = kotlinx.serialization.json.Json {
        /** 报文类型判别字段 */
        classDiscriminator = "t"
        /** 协议字段必须显式出现在报文中，缺字段直接报错，而不是静默套用默认值 */
        encodeDefaults = true
        /** 对方多发字段也视为协议错误，避免「未知字段被忽略」带来的绕过风险 */
        ignoreUnknownKeys = false
        isLenient = false
        explicitNulls = true
    }

    fun encode(message: WireMessage): ByteArray =
        json.encodeToString(WireMessage.serializer(), message).encodeToByteArray()

    fun decode(payload: ByteArray): WireMessage =
        json.decodeFromString(WireMessage.serializer(), payload.decodeToString())

    /** 加 4 字节大端长度头。 */
    fun frame(payload: ByteArray): ByteArray {
        require(payload.size in 1..Protocol.MAX_FRAME_SIZE) {
            "帧过大: ${payload.size} > ${Protocol.MAX_FRAME_SIZE}"
        }
        return byteArrayOf(
            (payload.size ushr 24).toByte(),
            (payload.size ushr 16).toByte(),
            (payload.size ushr 8).toByte(),
            payload.size.toByte(),
        ) + payload
    }

    fun readLengthHeader(header: ByteArray): Int {
        require(header.size == 4) { "长度头必须为 4 字节" }
        val length = ((header[0].toInt() and 0xFF) shl 24) or
            ((header[1].toInt() and 0xFF) shl 16) or
            ((header[2].toInt() and 0xFF) shl 8) or
            (header[3].toInt() and 0xFF)
        require(length in 1..Protocol.MAX_FRAME_SIZE) {
            "非法的帧长度: $length（协议不匹配或恶意流量）"
        }
        return length
    }
}
