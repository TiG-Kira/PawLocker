package com.kira.pawlocker.core.protocol

import com.kira.pawlocker.core.crypto.Aead
import com.kira.pawlocker.core.crypto.Base64Url
import com.kira.pawlocker.core.crypto.IdentityKey
import com.kira.pawlocker.core.crypto.PairSecret
import com.kira.pawlocker.core.crypto.PlatformCrypto
import com.kira.pawlocker.core.crypto.ProtocolLabels
import com.kira.pawlocker.core.crypto.constantTimeEquals

class UnlockRejectedException(val code: String, message: String) : Exception(message)

/**
 * 解锁指令的封装与校验。
 *
 * ## 为什么是「先加密再签名」而不是反过来
 *
 * `encrypt-then-sign` 是唯一不引入额外攻击面的组合方式：
 * 签名覆盖密文，所以密文一个字节都改不了；而解密只在签名验过之后才做，
 * 攻击者无法拿伪造的密文去喂解密器（padding-oracle / 侧信道类攻击的前提被掐断）。
 *
 * ## 三层防护的分工
 *
 * | 层 | 手段 | 挡住什么 |
 * |---|---|---|
 * | 来源认证 | ECDSA-P256 签名（手机长期身份私钥） | 冒名顶替、伪造指令 |
 * | 机密性 | AES-256-GCM（配对时协商的 KEK） | 抓包、篡改 |
 * | 新鲜性 | 时间戳 + 单调计数器 + nonce | 重放、录播攻击 |
 *
 * 注意签名用的是手机的**身份密钥**，而不是共享秘密派生的对称密钥 ——
 * 这样 Windows 端在解密之前就能确认「这条指令确实来自那台已配对的手机」。
 */
object UnlockProtocol {

    /** 手机侧：把一条解锁指令封装成可发送的 [UnlockRequest]。 */
    fun seal(
        secret: PairSecret,
        phoneKey: IdentityKey,
        phoneDeviceId: String,
        clientDisplayName: String,
        /**
         * 要解锁的 Windows 账户 —— 由信任记录提供，**不是**从当前环境实时取的。
         * 手机只知道「我配的是哪个账户」，它不该、也无法猜测电脑现在登录了谁。
         */
        targetWindowsUserSid: String,
        counter: Long,
        now: Long,
        action: String = UnlockAction.UNLOCK,
    ): UnlockRequest {
        val nonce = PairingProtocol.newNonce()

        // 先拼一个「部分」请求，用它的 aad() 作为 AEAD 附加数据
        val header = UnlockRequest(
            deviceId = phoneDeviceId,
            targetUserSid = targetWindowsUserSid,
            counter = counter,
            requestedAt = now,
            nonce = nonce,
            ciphertext = "",
            signature = "",
        )

        val payload = UnlockRequest.Payload(
            action = action,
            issuedAt = now,
            clientDisplayName = clientDisplayName,
        )
        val plaintext = kotlinx.serialization.json.Json
            .encodeToString(UnlockRequest.Payload.serializer(), payload)
            .encodeToByteArray()

        val sealed = Aead.seal(
            key = secret.encKey,
            plaintext = plaintext,
            aad = header.aad(),
            nonce = Base64Url.decode(nonce),
        )

        val withCiphertext = header.copy(ciphertext = Base64Url.encode(sealed.ciphertext))
        val signature = phoneKey.sign(withCiphertext.signedBytes())

        return withCiphertext.copy(signature = Base64Url.encode(signature))
    }

    /**
     * Windows 侧：校验并解出指令。
     *
     * @param phonePublicKey 来自**信任记录**，绝不能用报文里带的公钥
     * @param expectedWindowsUserSid 本机**真实**的 Windows 账户标识；
     *        与指令里声明的目标不一致就整条拒绝（绑定链的中间一环）
     * @param guard 进程级共享的防重放守卫
     * @throws UnlockRejectedException 任一环节失败
     */
    fun open(
        request: UnlockRequest,
        phonePublicKey: ByteArray,
        secret: PairSecret,
        expectedWindowsUserSid: String,
        guard: ReplayGuard,
        now: Long,
    ): UnlockRequest.Payload {
        // ① 来源认证 —— 先验签，未通过就不再做任何后续处理
        val signatureOk = runCatching {
            PlatformCrypto.verifyEcdsa(
                publicKeyUncompressed = phonePublicKey,
                data = request.signedBytes(),
                signatureDer = Base64Url.decode(request.signature),
            )
        }.getOrDefault(false)

        if (!signatureOk) {
            throw UnlockRejectedException(
                ErrorCodes.BAD_SIGNATURE,
                "指令签名校验失败：不是已信任手机发出的指令",
            )
        }

        // ② 绑定链 —— 目标 Windows 账户必须是本机当前账户。
        // 放在防重放之前：一条「账户不对」的指令不该消耗掉计数器额度，
        // 否则同一台手机切到别的账户发一次指令，就能把它自己的正常解锁挤掉。
        if (request.targetUserSid != expectedWindowsUserSid) {
            throw UnlockRejectedException(
                ErrorCodes.USER_MISMATCH,
                "这条指令指向的 Windows 账户（${request.targetUserSid.ifBlank { "未声明" }}）" +
                    "与本机当前账户不一致，已拒绝执行",
            )
        }

        // ③ 新鲜性 —— 时间窗口 / 计数器 / nonce
        val replay = guard.validate(
            deviceId = request.deviceId,
            counter = request.counter,
            timestampMillis = request.requestedAt,
            nonce = request.nonce,
            now = now,
        )
        if (replay != null) {
            throw UnlockRejectedException(
                if (replay is ReplayFailure.ClockSkew) ErrorCodes.CLOCK_SKEW else ErrorCodes.REPLAY_DETECTED,
                replay.message,
            )
        }

        // ④ 机密性与完整性
        val plaintext = runCatching {
            Aead.open(
                key = secret.encKey,
                nonce = Base64Url.decode(request.nonce),
                ciphertext = Base64Url.decode(request.ciphertext),
                aad = request.aad(),
            )
        }.getOrElse {
            throw UnlockRejectedException(ErrorCodes.DECRYPT_FAILED, "指令解密失败")
        }

        return runCatching {
            kotlinx.serialization.json.Json.decodeFromString(
                UnlockRequest.Payload.serializer(),
                plaintext.decodeToString(),
            )
        }.getOrElse {
            throw UnlockRejectedException(ErrorCodes.INTERNAL, "指令载荷格式错误")
        }
    }

    // ——————————————————————————————————————————————————————————
    // 回执
    // ——————————————————————————————————————————————————————————

    private fun ackSignatureInput(ok: Boolean, counter: Long, serverTime: Long): ByteArray =
        "ack|${Protocol.VERSION}|$ok|$counter|$serverTime".encodeToByteArray()

    /** Windows 侧：给回执打 MAC，让手机端能确认回执确实来自可信电脑。 */
    fun buildAck(
        secret: PairSecret,
        ok: Boolean,
        counter: Long,
        serverTime: Long,
        code: String? = null,
        message: String? = null,
    ): UnlockAck = UnlockAck(
        ok = ok,
        code = code,
        message = message,
        serverTime = serverTime,
        counter = counter,
        mac = Base64Url.encode(
            PlatformCrypto.hmacSha256(secret.macKey, ackSignatureInput(ok, counter, serverTime)),
        ),
    )

    /** 手机侧：校验回执来源。 */
    fun verifyAck(secret: PairSecret, ack: UnlockAck): Boolean {
        val mac = ack.mac ?: return false
        val expected = PlatformCrypto.hmacSha256(
            secret.macKey,
            ackSignatureInput(ack.ok, ack.counter, ack.serverTime),
        )
        return constantTimeEquals(expected, Base64Url.decode(mac))
    }
}
