package com.kira.pawlocker.core.protocol

import com.kira.pawlocker.core.crypto.Aead
import com.kira.pawlocker.core.crypto.Base64Url
import com.kira.pawlocker.core.crypto.DeviceIds
import com.kira.pawlocker.core.crypto.DeviceProfile
import com.kira.pawlocker.core.crypto.Hkdf
import com.kira.pawlocker.core.crypto.IdentityKey
import com.kira.pawlocker.core.crypto.PairSecret
import com.kira.pawlocker.core.crypto.PlatformCrypto
import com.kira.pawlocker.core.crypto.ProtocolLabels
import com.kira.pawlocker.core.crypto.constantTimeEquals
import com.kira.pawlocker.core.platform.UserIdentity
import com.kira.pawlocker.core.trust.PeerRole
import com.kira.pawlocker.core.trust.TrustRecord
import kotlinx.serialization.Serializable

/**
 * 配对失败。对外只暴露 [code]（[ErrorCodes] 中的一个）与人类可读的 [message]。
 */
class PairingException(val code: String, message: String) : Exception(message)

/**
 * 配对协议的公共部分。
 *
 * ## 防中间人的关键设计
 *
 * 配对的唯一「带外信任锚」是 **Windows 屏幕上那串 6 位配对码**。
 * 用户能同时看到电脑屏幕和手机屏幕，这个物理前提是攻击者无法伪造的。
 *
 * 但光有配对码还不够 —— 攻击者如果只是转发报文（relay），
 * 配对码保护不了什么。所以协议里把**双方公钥都绑进了配对码保护的 HMAC**：
 *
 * ```
 * confirmTag  = HMAC(K_code, "confirm"  || winPub || phonePub || pid)
 * serverTag   = HMAC(K_code, "confirm2" || winPub || phonePub || pid)
 * ```
 *
 * 任何替换公钥的行为都会让另一端的 tag 校验失败；
 * 而不知道配对码的攻击者根本算不出正确的 tag。
 * 配对码本身不参与加密密钥的生成，只用于「证明你知道它」——
 * 这样即使配对码被短时偷看，也无法事后解密已完成的配对流量。
 */
object PairingProtocol {

    /** 配对码保护密钥：K_code = HKDF(配对码, salt = pairingId, info = 标签) */
    fun derivePairingKey(code: String, pairingId: String): ByteArray =
        Hkdf.derive(
            ikm = code.encodeToByteArray(),
            salt = pairingId.encodeToByteArray(),
            info = ProtocolLabels.PAIRING_KEY,
            length = 32,
        )

    /**
     * AEAD 附加数据。
     * 把 pairingId 与 nonce 一起绑进去，防止攻击者把 A 会话的密文搬到 B 会话重用。
     */
    fun aad(pairingId: String, nonce: String): ByteArray =
        "pair|${Protocol.VERSION}|$pairingId|$nonce".encodeToByteArray()

    fun confirmTag(
        key: ByteArray,
        label: String,
        computerPublicKey: ByteArray,
        phonePublicKey: ByteArray,
        pairingId: String,
    ): ByteArray = PlatformCrypto.hmacSha256(
        key,
        label.encodeToByteArray() + computerPublicKey + phonePublicKey + pairingId.encodeToByteArray(),
    )

    /** 生成 6 位数字配对码，使用密码学安全随机源。 */
    fun randomCode(): String {
        val b = PlatformCrypto.randomBytes(4)
        val value = ((b[0].toInt() and 0x7F) shl 24) or
            ((b[1].toInt() and 0xFF) shl 16) or
            ((b[2].toInt() and 0xFF) shl 8) or
            (b[3].toInt() and 0xFF)
        return (value % 1_000_000).toString().padStart(Protocol.PAIRING_CODE_DIGITS, '0')
    }

    fun newPairingId(): String = Base64Url.encode(PlatformCrypto.randomBytes(16))

    fun newNonce(): String = Base64Url.encode(PlatformCrypto.randomBytes(Aead.NONCE_SIZE))
}

// ——————————————————————————————————————————————————————————————
// 配对凭据（QR 码 / 深链承载的内容）
// ——————————————————————————————————————————————————————————————

/**
 * Windows 端生成的「配对邀请」。
 *
 * 同时用于两条路径：
 *  - **扫码**：编码成 `pawlocker://pair?d=<Base64Url(JSON)>`，手机扫一下全都有了
 *  - **手动**：用户在电脑上读出 `主机:端口` 与 6 位码，手输到手机
 *
 * 把配对码放进 QR 是否降低安全性？不会 ——
 * 能看到 QR 的物理位置和能看到配对码的物理位置是同一个（电脑屏幕），
 * 所以两者泄露风险等价，但扫码体验好得多。
 */
@Serializable
data class PairingOffer(
    val v: Int = Protocol.VERSION,
    val pairingId: String,
    val code: String,
    val computerDeviceId: String,
    val computerDisplayName: String,
    val computerPublicKey: String,
    /**
     * 这台电脑当前登录的 Windows 账户（连在绑定链中间的那一环）。
     *
     * 放进邀请里是为了让手机**明确知道自己配的是哪个账户** ——
     * 用户能看到「正在与 书房主机 · Kira（S-1-5-21-…）配对」，而不是只看到一个机器名。
     * 手机端还会把它原样回传，电脑端据此拒绝「拿着 A 账户的邀请去配 B 账户」这类错配。
     */
    val windowsUserSid: String = "",
    val windowsUserName: String = "",
    val endpoints: List<Endpoint>,
    val expiresAt: Long,
) {

    fun toDeepLink(): String =
        "${Protocol.DEEP_LINK_SCHEME}://pair?d=" + Base64Url.encode(
            kotlinx.serialization.json.Json.encodeToString(serializer(), this).encodeToByteArray(),
        )

    companion object {

        fun fromDeepLink(raw: String): PairingOffer? {
            val prefix = "${Protocol.DEEP_LINK_SCHEME}://pair?d="
            if (!raw.startsWith(prefix)) return null
            return runCatching {
                val bytes = Base64Url.decode(raw.removePrefix(prefix))
                kotlinx.serialization.json.Json.decodeFromString(
                    serializer(),
                    bytes.decodeToString(),
                )
            }.getOrNull()
        }
    }
}

// ——————————————————————————————————————————————————————————————
// 手机侧
// ——————————————————————————————————————————————————————————————

/**
 * Android 端的配对会话。
 *
 * 用法：
 * ```
 * val session = PhonePairingSession(offer, code, phoneKey, profile, now)
 * val request = session.buildRequest(now)          // 发出去
 * val record  = session.acceptResponse(response)   // 收到回复后校验并落库
 * ```
 */
class PhonePairingSession(
    val pairingId: String,
    val code: String,
    val computerPublicKey: ByteArray,
    val computerDisplayName: String,
    /**
     * 邀请里声明的目标 Windows 账户 —— 手机会在配对请求里原样回传。
     * 没有默认值：调用方必须显式决定「这次配的是哪个账户」，
     * 不能因为忘了传而退化成「不绑定账户」。
     */
    val windowsUserSid: String,
    val windowsUserName: String,
    private val phoneKey: IdentityKey,
    private val phoneProfile: DeviceProfile,
    val startedAt: Long,
) {

    private val pairingKey: ByteArray = PairingProtocol.derivePairingKey(code, pairingId)

    private var requestNonce: String? = null

    /** 构造 [PairRequest]：内部明文用 K_code 加密，攻击者看不到手机公钥。 */
    fun buildRequest(now: Long): PairRequest {
        val nonce = PairingProtocol.newNonce()
        requestNonce = nonce

        val payload = PairRequest.Payload(
            phoneDeviceId = DeviceIds.fromPublicKey(phoneKey.publicKey),
            phoneDisplayName = phoneProfile.displayName,
            phoneModel = phoneProfile.model,
            phonePublicKey = Base64Url.encode(phoneKey.publicKey),
            confirmTag = Base64Url.encode(
                PairingProtocol.confirmTag(
                    key = pairingKey,
                    label = "confirm",
                    computerPublicKey = computerPublicKey,
                    phonePublicKey = phoneKey.publicKey,
                    pairingId = pairingId,
                ),
            ),
            windowsUserSid = windowsUserSid,
            requestedAt = now,
        )

        val plaintext = kotlinx.serialization.json.Json
            .encodeToString(PairRequest.Payload.serializer(), payload)
            .encodeToByteArray()

        val sealed = Aead.seal(
            key = pairingKey,
            plaintext = plaintext,
            aad = PairingProtocol.aad(pairingId, nonce),
            nonce = Base64Url.decode(nonce),
        )

        return PairRequest(
            pairingId = pairingId,
            nonce = nonce,
            ciphertext = Base64Url.encode(sealed.ciphertext),
        )
    }

    /**
     * 校验电脑返回的 [PairResponse] 并派生长期密钥。
     *
     * 校验链：
     *  1. pairingId 必须与会话一致
     *  2. AEAD 解密必须成功（证明对方持有配对码）
     *  3. accepted 必须为 true
     *  4. serverConfirmTag 必须匹配（证明对方的公钥没有被替换过）
     *
     * 全通过才做 ECDH —— 顺序很重要，绝不能先把共享秘密算出来再校验。
     */
    fun acceptResponse(response: PairResponse, now: Long): TrustRecord {
        if (response.pairingId != pairingId) {
            throw PairingException(ErrorCodes.PAIRING_CLOSED, "配对会话不匹配")
        }

        val nonce = requestNonce
            ?: throw PairingException(ErrorCodes.INTERNAL, "尚未发送配对请求")

        val plaintext = runCatching {
            Aead.open(
                key = pairingKey,
                nonce = Base64Url.decode(response.nonce),
                ciphertext = Base64Url.decode(response.ciphertext),
                aad = PairingProtocol.aad(pairingId, nonce),
            )
        }.getOrElse {
            throw PairingException(ErrorCodes.DECRYPT_FAILED, "配对响应无法解密，可能被中间人篡改")
        }

        val payload = runCatching {
            kotlinx.serialization.json.Json.decodeFromString(
                PairResponse.Payload.serializer(),
                plaintext.decodeToString(),
            )
        }.getOrElse {
            throw PairingException(ErrorCodes.INTERNAL, "配对响应格式错误")
        }

        if (!payload.accepted) {
            throw PairingException(
                payload.code ?: ErrorCodes.PAIRING_CLOSED,
                payload.message ?: "电脑端拒绝了本次配对",
            )
        }

        // 电脑确认的账户必须与邀请里声明的一致。
        // 不一致意味着「本机账户在配对窗口期内被切换过」或「响应被中间人替换」，
        // 两种情况下都不能把这条配对记下来。
        if (payload.windowsUserSid != windowsUserSid) {
            throw PairingException(
                ErrorCodes.USER_MISMATCH,
                "电脑端返回的 Windows 账户与邀请不符，配对已中止",
            )
        }

        val computerPub = Base64Url.decode(payload.windowsPublicKey)
        val expectedTag = PairingProtocol.confirmTag(
            key = pairingKey,
            label = "confirm2",
            computerPublicKey = computerPub,
            phonePublicKey = phoneKey.publicKey,
            pairingId = pairingId,
        )
        if (!constantTimeEquals(expectedTag, Base64Url.decode(payload.serverConfirmTag))) {
            throw PairingException(
                ErrorCodes.PAIRING_CODE_MISMATCH,
                "配对校验失败：电脑公钥与配对码不匹配（可能存在中间人）",
            )
        }

        // 到这里才允许做密钥协商
        val sharedSecret = phoneKey.agree(computerPub)
        val secret = PairSecret.derive(
            sharedSecret = sharedSecret,
            pairingId = pairingId,
            windowsPublicKey = computerPub,
            phonePublicKey = phoneKey.publicKey,
            windowsUserSid = payload.windowsUserSid,
        )
        PlatformCrypto.wipe(sharedSecret)
        PlatformCrypto.wipe(pairingKey)

        return TrustRecord(
            deviceId = payload.windowsDeviceId,
            role = PeerRole.COMPUTER,
            displayName = payload.windowsDisplayName,
            model = payload.windowsModel,
            platform = "Windows",
            publicKey = Base64Url.encode(computerPub),
            secret = secret.encode(),
            endpoints = payload.endpoints,
            pairedAt = payload.pairedAt.coerceAtLeast(now),
            windowsUserSid = payload.windowsUserSid,
            windowsUserName = payload.windowsUserName,
        )
    }
}

// ——————————————————————————————————————————————————————————————
// Windows 侧
// ——————————————————————————————————————————————————————————————

/**
 * Windows 端的配对会话。由管理页「添加手机」按钮创建，有效期 [Protocol.PAIRING_TTL_MILLIS]。
 *
 * 一次性：成功配对后立即销毁，防止同一个配对码被第二台手机复用。
 */
class ComputerPairingSession(
    val pairingId: String,
    val code: String,
    private val computerKey: IdentityKey,
    private val computerProfile: DeviceProfile,
    /**
     * 发起配对时本机登录的 Windows 账户。
     * 它会进入邀请、参与密钥派生、并被写进信任记录 —— 绑定链的中间一环。
     */
    val windowsUser: UserIdentity,
    val createdAt: Long,
    val ttlMillis: Long = Protocol.PAIRING_TTL_MILLIS,
) {

    private val pairingKey: ByteArray = PairingProtocol.derivePairingKey(code, pairingId)

    /** 已被某一台手机占用后置为 true —— 一个配对会话只服务一次配对。 */
    var consumed: Boolean = false
        private set

    fun isExpired(now: Long): Boolean = now - createdAt > ttlMillis

    fun expiresAt(): Long = createdAt + ttlMillis

    fun offer(endpoints: List<Endpoint>): PairingOffer = PairingOffer(
        pairingId = pairingId,
        code = code,
        computerDeviceId = DeviceIds.fromPublicKey(computerKey.publicKey),
        computerDisplayName = computerProfile.displayName,
        computerPublicKey = Base64Url.encode(computerKey.publicKey),
        windowsUserSid = windowsUser.bindingKey,
        windowsUserName = windowsUser.displayName,
        endpoints = endpoints,
        expiresAt = expiresAt(),
    )

    /**
     * 解密并校验手机发来的配对请求。
     * @throws PairingException 任何一步不过都抛，由调用方转成 [ErrorMessage] 回给手机。
     */
    fun decryptRequest(request: PairRequest, now: Long): PairRequest.Payload {
        if (consumed) {
            throw PairingException(ErrorCodes.PAIRING_CLOSED, "该配对会话已被使用")
        }
        if (isExpired(now)) {
            throw PairingException(ErrorCodes.PAIRING_EXPIRED, "配对码已过期，请在电脑上重新生成")
        }
        if (request.pairingId != pairingId) {
            throw PairingException(ErrorCodes.PAIRING_CLOSED, "配对会话不匹配")
        }

        val plaintext = runCatching {
            Aead.open(
                key = pairingKey,
                nonce = Base64Url.decode(request.nonce),
                ciphertext = Base64Url.decode(request.ciphertext),
                aad = PairingProtocol.aad(pairingId, request.nonce),
            )
        }.getOrElse {
            throw PairingException(ErrorCodes.PAIRING_CODE_MISMATCH, "配对码不正确")
        }

        val payload = runCatching {
            kotlinx.serialization.json.Json.decodeFromString(
                PairRequest.Payload.serializer(),
                plaintext.decodeToString(),
            )
        }.getOrElse {
            throw PairingException(ErrorCodes.INTERNAL, "配对请求格式错误")
        }

        val phonePub = Base64Url.decode(payload.phonePublicKey)
        if (phonePub.size != com.kira.pawlocker.core.crypto.EcKeys.RAW_PUBLIC_KEY_SIZE) {
            throw PairingException(ErrorCodes.INTERNAL, "手机公钥格式错误")
        }

        val expected = PairingProtocol.confirmTag(
            key = pairingKey,
            label = "confirm",
            computerPublicKey = computerKey.publicKey,
            phonePublicKey = phonePub,
            pairingId = pairingId,
        )
        if (!constantTimeEquals(expected, Base64Url.decode(payload.confirmTag))) {
            throw PairingException(ErrorCodes.PAIRING_CODE_MISMATCH, "配对码不正确")
        }

        // 设备 ID 必须由公钥派生，不接受手机自报的 ID，杜绝 ID 冒用
        if (payload.phoneDeviceId != DeviceIds.fromPublicKey(phonePub)) {
            throw PairingException(ErrorCodes.INTERNAL, "设备标识与公钥不匹配")
        }

        // 绑定链的中间一环：手机回传的 Windows 账户必须就是本机当前账户。
        // 不匹配的典型原因是「配对窗口开着的时候有人切换了登录账户」，
        // 更坏的情况是响应被换成了另一个账户的邀请 —— 两种都必须中止。
        if (payload.windowsUserSid != windowsUser.bindingKey) {
            throw PairingException(
                ErrorCodes.USER_MISMATCH,
                "本次配对请求绑定的 Windows 账户与本机当前账户不一致",
            )
        }

        return payload
    }

    /**
     * 构造配对响应。
     *
     * @param accepted 用户在电脑上点了「允许」还是「拒绝」
     */
    fun buildResponse(
        request: PairRequest,
        payload: PairRequest.Payload,
        accepted: Boolean,
        endpoints: List<Endpoint>,
        now: Long,
        message: String? = null,
    ): PairResponse {
        val phonePub = Base64Url.decode(payload.phonePublicKey)

        val body = PairResponse.Payload(
            accepted = accepted,
            message = message,
            windowsDeviceId = DeviceIds.fromPublicKey(computerKey.publicKey),
            windowsDisplayName = computerProfile.displayName,
            windowsModel = computerProfile.model,
            windowsPublicKey = Base64Url.encode(computerKey.publicKey),
            serverConfirmTag = Base64Url.encode(
                PairingProtocol.confirmTag(
                    key = pairingKey,
                    label = "confirm2",
                    computerPublicKey = computerKey.publicKey,
                    phonePublicKey = phonePub,
                    pairingId = pairingId,
                ),
            ),
            windowsUserSid = windowsUser.bindingKey,
            windowsUserName = windowsUser.displayName,
            endpoints = endpoints,
            pairedAt = now,
        )

        val plaintext = kotlinx.serialization.json.Json
            .encodeToString(PairResponse.Payload.serializer(), body)
            .encodeToByteArray()

        // 用手机请求里的 nonce 作为 AAD，保证响应只能配对这个请求
        val sealed = Aead.seal(
            key = pairingKey,
            plaintext = plaintext,
            aad = PairingProtocol.aad(pairingId, request.nonce),
        )

        return PairResponse(
            pairingId = pairingId,
            nonce = Base64Url.encode(sealed.nonce),
            ciphertext = Base64Url.encode(sealed.ciphertext),
        )
    }

    /**
     * 用户点了「允许」之后，生成需要落库的信任记录。
     * 调用此方法即视为该会话已消费。
     */
    fun complete(payload: PairRequest.Payload, now: Long): TrustRecord {
        val phonePub = Base64Url.decode(payload.phonePublicKey)
        val sharedSecret = computerKey.agree(phonePub)
        val secret = PairSecret.derive(
            sharedSecret = sharedSecret,
            pairingId = pairingId,
            windowsPublicKey = computerKey.publicKey,
            phonePublicKey = phonePub,
            windowsUserSid = windowsUser.bindingKey,
        )
        PlatformCrypto.wipe(sharedSecret)
        PlatformCrypto.wipe(pairingKey)
        consumed = true

        return TrustRecord(
            deviceId = payload.phoneDeviceId,
            role = PeerRole.PHONE,
            displayName = payload.phoneDisplayName,
            model = payload.phoneModel,
            platform = "Android",
            publicKey = payload.phonePublicKey,
            secret = secret.encode(),
            endpoints = emptyList(),
            pairedAt = now,
            lastSeenAt = now,
            lastCounter = 0,
            windowsUserSid = windowsUser.bindingKey,
            windowsUserName = windowsUser.displayName,
        )
    }
}
