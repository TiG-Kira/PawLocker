package com.kira.pawlocker.core.protocol

/**
 * 协议常量。
 *
 * 版本号写在每一条报文里。双方版本不一致时 Windows 端必须直接拒绝，
 * 而不是尝试兼容 —— 密码学协议最忌讳「带降级的兼容逻辑」，
 * 那基本等于给攻击者送一个 downgrade 通道。
 */
object Protocol {

    /** 当前协议版本。任何字段语义变更都要 +1。 */
    const val VERSION = 1

    /** Windows 端默认监听端口。 */
    const val DEFAULT_PORT = 9898

    /** 单帧最大长度，防止对端用超大 length 头打爆内存。 */
    const val MAX_FRAME_SIZE = 64 * 1024

    /** 单条报文最大长度。 */
    const val MAX_MESSAGE_SIZE = 32 * 1024

    /** 配对会话有效期。 */
    const val PAIRING_TTL_MILLIS = 120_000L

    /** 允许的客户端时钟偏移，超出即判定重放。 */
    const val CLOCK_SKEW_MILLIS = 60_000L

    /** 重放缓存保留窗口。 */
    const val REPLAY_WINDOW_MILLIS = 300_000L

    /** 未配对的客户端在 hello 之后必须在这个时间内完成配对或断线。 */
    const val UNPAIRED_IDLE_MILLIS = 15_000L

    /** 已配对的空闲连接保活间隔。 */
    const val KEEPALIVE_INTERVAL_MILLIS = 30_000L

    /** 配对码位数。 */
    const val PAIRING_CODE_DIGITS = 6

    /** QR / 深链 scheme。 */
    const val DEEP_LINK_SCHEME = "pawlocker"
}

/** 报文类型判别值，对应 kotlinx.serialization 的 `t` 字段。 */
object MessageTypes {
    const val CLIENT_HELLO = "hello"
    const val SERVER_HELLO = "hello.ack"
    const val PAIR_REQUEST = "pair.request"
    const val PAIR_RESPONSE = "pair.response"
    const val PAIR_PENDING = "pair.pending"
    const val UNLOCK = "unlock"
    const val UNLOCK_ACK = "unlock.ack"
    const val PING = "ping"
    const val PONG = "pong"
    const val ERROR = "error"
}

/** 错误码。Android 端据此外显提示，避免把技术细节直接甩给用户。 */
object ErrorCodes {
    const val VERSION_MISMATCH = "version_mismatch"
    const val PAIRING_CLOSED = "pairing_closed"
    const val PAIRING_EXPIRED = "pairing_expired"
    const val PAIRING_CODE_MISMATCH = "pairing_code_mismatch"
    const val DEVICE_NOT_TRUSTED = "device_not_trusted"
    const val DEVICE_REVOKED = "device_revoked"
    const val BAD_SIGNATURE = "bad_signature"
    const val DECRYPT_FAILED = "decrypt_failed"
    const val REPLAY_DETECTED = "replay_detected"
    const val CLOCK_SKEW = "clock_skew"
    const val RATE_LIMITED = "rate_limited"
    const val UNLOCK_REJECTED = "unlock_rejected"
    const val INTERNAL = "internal"
}
