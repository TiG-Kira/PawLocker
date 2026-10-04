package com.kira.pawlocker.core.protocol

/**
 * 协议常量。
 *
 * 版本号写在每一条报文里。双方版本不一致时 Windows 端必须直接拒绝，
 * 而不是尝试兼容 —— 密码学协议最忌讳「带降级的兼容逻辑」，
 * 那基本等于给攻击者送一个 downgrade 通道。
 */
object Protocol {

    /**
     * 当前协议版本。任何字段语义变更都要 +1。
     *
     * v2：引入「电脑设备 + Windows 账户 + 手机设备」三元绑定 ——
     * 账户身份进入 HKDF 的 salt，并且必须出现在解锁指令的 AAD 与签名里。
     * 这是不兼容变更（v1 的配对记录无法继续使用），因此版本号必须抬高，
     * 让旧客户端在握手阶段就被明确拒绝，而不是以为配对成功却发现解不开锁。
     */
    const val VERSION = 2

    /**
     * Windows 端默认监听端口。
     *
     * 2026-10 由 9898 改为 28900。换的起因是现场反馈 9898「从外面连不上」，
     * 而本机侧一切正常（服务在监听、防火墙已放行、局域网 IP 自连可通）——
     * 换到一段几乎没人用的空档，先把「端口本身是不是被环境盯上」这个变量排除掉。
     *
     * 28900 的选取依据（以下每条都是可验证的硬约束）：
     *  - 落在 1024–49151 的注册端口区间：普通用户即可 bind；同时**远离 Windows 的
     *    动态端口范围**（默认自 49152 起 16384 个）。这一点比看上去重要 ——
     *    Hyper-V / WSL / Docker 开启后会在动态范围内再划走大段保留区
     *    （`netsh int ipv4 show excludedportrange`），落进去的端口会 bind 失败
     *    并报 10048，而现象跟「被别的程序占用」一模一样，极难排查。
     *  - IANA 未分配，不与任何知名服务冲突，也没有出现在常见调试/远控端口的观察名单里。
     *  - 避开主流代理端口（7890/7891/7892/8080/8888）与 frp 默认端口（7000/7500）——
     *    这台开发机上 FlClash 正开着 TUN，代理端口段必须绕开。
     *
     * ⚠️ 端口会随配对流程下发给手机，并写进手机的设备记录。
     * 改这个常量 = **所有已配对的手机失效，只能重新配对**。
     */
    const val DEFAULT_PORT = 28900

    /**
     * 历史上的默认监听端口。
     *
     * 留着它只为一件事：让配置迁移能认出「用户从来没动过端口」的老配置。
     * 只有恰好等于这个值、且未被迁移过的配置才会被升到 [DEFAULT_PORT]；
     * 用户手动指定的其他任何端口都不在迁移范围内。
     */
    const val LEGACY_DEFAULT_PORT = 9898

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

    /**
     * 绑定链不匹配：设备对，但 Windows 账户对不上。
     *
     * 单独给一个错误码（而不是混进 `device_not_trusted`）是因为这两种情况
     * 对用户意味着完全不同的下一步动作：设备不对要去重新配对，
     * 账户不对说明「这台手机是配给另一个 Windows 账户的」，
     * 需要在目标账户下重新配对，或者换一台手机。
     */
    const val USER_MISMATCH = "user_mismatch"

    const val BAD_SIGNATURE = "bad_signature"
    const val DECRYPT_FAILED = "decrypt_failed"
    const val REPLAY_DETECTED = "replay_detected"
    const val CLOCK_SKEW = "clock_skew"
    const val RATE_LIMITED = "rate_limited"
    const val UNLOCK_REJECTED = "unlock_rejected"
    const val INTERNAL = "internal"
}
