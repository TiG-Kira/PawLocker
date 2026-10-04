package com.kira.pawlocker.core.protocol

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * 线路报文的根类型。
 *
 * 用 sealed + kotlinx.serialization 的多态机制生成 `t` 判别字段。
 * 判别值来自 [MessageTypes]，两端必须一字不差。
 */
@Serializable
sealed interface WireMessage

/**
 * 连接地址。一台 Windows 电脑可能有多个可达地址，
 * 手机端按 [priority] 从小到大依次尝试，任一成功即停止。
 */
@Serializable
data class Endpoint(    val kind: TransportKind,
    val host: String,
    val port: Int = Protocol.DEFAULT_PORT,
    val label: String = "",
) {
    val display: String get() = "$host:$port"

    companion object {
        /** 同一场景内地址去重后的排序键：局域网直连最快，隧道最慢。 */
        val preferredOrder: Comparator<Endpoint> = compareBy { it.kind.rank }
    }
}

@Serializable
enum class TransportKind(val rank: Int, val displayName: String) {
    /** 同一 Wi-Fi / 交换机下直连内网 IP */
    LAN(0, "局域网直连"),

    /** Tailscale / ZeroTier 等虚拟组网 */
    OVERLAY(1, "虚拟组网"),

    /** frp 等公网反向代理 */
    TUNNEL(2, "内网穿透"),

    /** 用户手工填写的地址 */
    MANUAL(3, "手动配置"),
}

// ——————————————————————————————————————————————————————————————
// 握手
// ——————————————————————————————————————————————————————————————

/**
 * 手机 → Windows 的第一条报文。此时连接尚未经过任何认证，
 * 所以这条报文的内容一律视为不可信输入。
 */
@Serializable
@SerialName(MessageTypes.CLIENT_HELLO)
data class ClientHello(
    val v: Int = Protocol.VERSION,
    val deviceId: String,
    val displayName: String,
    val model: String,
    val publicKey: String,
    val nonce: String,
) : WireMessage

@Serializable
@SerialName(MessageTypes.SERVER_HELLO)
data class ServerHello(
    val v: Int = Protocol.VERSION,
    val deviceId: String,
    val displayName: String,
    val model: String,
    val publicKey: String,
    val nonce: String,
    /** 是否已有已登录用户在管理页开启了「允许配对」。 */
    val pairingOpen: Boolean,
    /**
     * 当前配对会话的 ID。
     *
     * 有了它，「手动输入 host + port + 6 位配对码」这条路才走得通 ——
     * 手机连上后先从 ServerHello 拿到 pairingId 与电脑公钥，再走标准配对流程，
     * 不需要用户额外抄一串会话 ID。
     *
     * 泄露它没有风险：配对码才是唯一的信任锚，而配对码保护的
     * `confirmTag` 同时绑定了 pairingId 与双方公钥，被替换就必然校验失败。
     */
    val activePairingId: String? = null,
    /**
     * 本机当前登录的 Windows 账户。
     *
     * 「手动输入 host + port + 配对码」这条路径没有二维码可扫，
     * 手机只能从这里拿到绑定的账户 —— 否则它无法构造出符合绑定链的配对请求。
     */
    val windowsUserSid: String = "",
    val windowsUserName: String = "",
    /** 服务端时间，手机端据此校正本地时钟偏移。 */
    val serverTime: Long,
    /** 当前已信任手机数量，用于手机端展示。 */
    val trustedDeviceCount: Int = 0,
) : WireMessage

// ——————————————————————————————————————————————————————————————
// 配对
// ——————————————————————————————————————————————————————————————

/**
 * 配对请求。整个 [Payload] 用「配对码派生密钥 K_code」加密，
 * 因此**没有配对码的人连报文内容都构造不出来**。
 */
@Serializable
@SerialName(MessageTypes.PAIR_REQUEST)
data class PairRequest(
    val pairingId: String,
    val nonce: String,
    val ciphertext: String,
) : WireMessage {

    @Serializable
    data class Payload(
        val phoneDeviceId: String,
        val phoneDisplayName: String,
        val phoneModel: String,
        val phonePublicKey: String,
        /** HMAC(K_code, "confirm" | windowsPub | phonePub | pairingId) */
        val confirmTag: String,
        /**
         * 手机原样回传它从邀请里读到的 Windows 账户。
         * 电脑端必须比对 —— 不一致说明这条配对请求不是发给它的账户的。
         */
        val windowsUserSid: String = "",
        val requestedAt: Long,
    )
}

/** Windows 收到配对请求后先回一个「已收到，等用户点确认」。 */
@Serializable
@SerialName(MessageTypes.PAIR_PENDING)
data class PairPending(
    val pairingId: String,
    val serverTime: Long,
) : WireMessage

@Serializable
@SerialName(MessageTypes.PAIR_RESPONSE)
data class PairResponse(
    val pairingId: String,
    val nonce: String,
    val ciphertext: String,
) : WireMessage {

    @Serializable
    data class Payload(
        val accepted: Boolean,
        val code: String? = null,
        val message: String? = null,
        val windowsDeviceId: String,
        val windowsDisplayName: String,
        val windowsModel: String,
        val windowsPublicKey: String,
        /** HMAC(K_code, "confirm2" | windowsPub | phonePub | pairingId) */
        val serverConfirmTag: String,
        /** 该配对绑定的 Windows 账户，手机端保存后用于后续解锁指令。 */
        val windowsUserSid: String = "",
        val windowsUserName: String = "",
        /** 配对完立刻把可达地址下发，手机端无需再问。 */
        val endpoints: List<Endpoint>,
        val pairedAt: Long,
    )
}

// ——————————————————————————————————————————————————————————————
// 解锁
// ——————————————————————————————————————————————————————————————

/**
 * 解锁指令。三层保护叠在一起：
 *  1. [signature] —— 用**手机的长期身份私钥**对整段头部 + 密文签名，证明来源
 *  2. [ciphertext] —— AES-256-GCM 加密，密钥来自配对时协商的共享秘密
 *  3. [counter] / [requestedAt] / [nonce] —— 防重放三件套
 */
@Serializable
@SerialName(MessageTypes.UNLOCK)
data class UnlockRequest(
    val deviceId: String,
    /**
     * 这条指令要解锁的 **Windows 账户标识**（绑定链的中间一环）。
     *
     * 它同时进入 AAD 与签名：电脑端会拿本机真实账户去比对，
     * 对不上就整条拒绝。这样「为 A 账户配对的手机会去开 B 账户」这件事
     * 在指令层面就被阻断，而不是指望某处忘记检查时才不出事。
     */
    val targetUserSid: String,
    val counter: Long,
    val requestedAt: Long,
    val nonce: String,
    val ciphertext: String,
    val signature: String,
) : WireMessage {

    @Serializable
    data class Payload(
        val action: String = UnlockAction.UNLOCK,
        val issuedAt: Long,
        val clientDisplayName: String,
    )

    /**
     * AEAD 的附加认证数据：覆盖除密文自身以外的全部头部字段。
     * 中间人改任意一位都会让 GCM 解密失败。
     */
    fun aad(): ByteArray = buildString {
        append(Protocol.VERSION).append('|')
        append(deviceId).append('|')
        append(targetUserSid).append('|')
        append(counter).append('|')
        append(requestedAt).append('|')
        append(nonce)
    }.encodeToByteArray()

    /** 签名覆盖的字节序列 = AAD + 密文，两端必须逐字节一致。 */
    fun signedBytes(): ByteArray = aad() + ciphertext.encodeToByteArray()
}

object UnlockAction {
    const val UNLOCK = "unlock"
    /** 仅点亮屏幕 / 唤醒，不执行登录。 */
    const val WAKE = "wake"
    /** 锁屏（手机端主动上锁）。 */
    const val LOCK = "lock"
}

@Serializable
@SerialName(MessageTypes.UNLOCK_ACK)
data class UnlockAck(
    val ok: Boolean,
    val code: String? = null,
    val message: String? = null,
    val serverTime: Long,
    val counter: Long,
    /** HMAC(macKey, "$ok|$counter|$serverTime")，让手机端能确认回执确实来自可信电脑。 */
    val mac: String? = null,
) : WireMessage

// ——————————————————————————————————————————————————————————————
// 通用
// ——————————————————————————————————————————————————————————————

@Serializable
@SerialName(MessageTypes.PING)
data class Ping(val at: Long) : WireMessage

@Serializable
@SerialName(MessageTypes.PONG)
data class Pong(val at: Long, val serverTime: Long) : WireMessage

@Serializable
@SerialName(MessageTypes.ERROR)
data class ErrorMessage(
    val code: String,
    val message: String,
) : WireMessage
