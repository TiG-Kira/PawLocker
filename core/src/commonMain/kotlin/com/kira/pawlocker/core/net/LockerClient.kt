package com.kira.pawlocker.core.net

import com.kira.pawlocker.core.crypto.Base64Url
import com.kira.pawlocker.core.crypto.DeviceIds
import com.kira.pawlocker.core.crypto.DeviceProfile
import com.kira.pawlocker.core.crypto.IdentityKey
import com.kira.pawlocker.core.platform.PlatformEnv
import com.kira.pawlocker.core.protocol.ClientHello
import com.kira.pawlocker.core.protocol.Endpoint
import com.kira.pawlocker.core.protocol.ErrorCodes
import com.kira.pawlocker.core.protocol.ErrorMessage
import com.kira.pawlocker.core.protocol.PairPending
import com.kira.pawlocker.core.protocol.PairResponse
import com.kira.pawlocker.core.protocol.PairingException
import com.kira.pawlocker.core.protocol.PairingOffer
import com.kira.pawlocker.core.protocol.PairingProtocol
import com.kira.pawlocker.core.protocol.PhonePairingSession
import com.kira.pawlocker.core.protocol.Protocol
import com.kira.pawlocker.core.protocol.ServerHello
import com.kira.pawlocker.core.protocol.UnlockAction
import com.kira.pawlocker.core.protocol.UnlockAck
import com.kira.pawlocker.core.protocol.UnlockProtocol
import com.kira.pawlocker.core.trust.TrustRecord
import kotlinx.coroutines.withTimeoutOrNull

/**
 * Android 端发起连接的入口。
 *
 * 无状态设计：不持有长连接，每次操作都是「连上 → 握手 → 交换 → 断开」。
 * 看起来笨，但换来两个关键好处：
 *  1. 内网穿透隧道与 NAT 会主动回收空闲连接，长连接需要复杂的重连与状态恢复逻辑
 *  2. 解锁是极低频操作（一天几次），完全没必要养一条常驻连接增加攻击面
 *
 * 端上真正的「状态」只有信任列表，以及每台电脑的计数器。
 */
class LockerClient(
    private val identity: IdentityKey,
    private val profile: DeviceProfile,
) {

    private val phoneDeviceId: String = DeviceIds.fromPublicKey(identity.publicKey)

    // ——————————————————————————————————————————————————————————
    // 配对 · 扫码路径
    // ——————————————————————————————————————————————————————————

    /**
     * 扫码配对。二维码里已经带了 `pairingId`、电脑公钥与可达地址，
     * 所以这一步不需要先连上去问。
     */
    suspend fun pair(
        offer: PairingOffer,
        code: String,
        now: Long = PlatformEnv.currentTimeMillis(),
    ): PairAttemptResult {
        if (offer.v != Protocol.VERSION) {
            return PairAttemptResult.Rejected(
                ErrorCodes.VERSION_MISMATCH,
                "配对二维码来自不兼容的版本（v${offer.v}）",
            )
        }
        if (now > offer.expiresAt) {
            return PairAttemptResult.Rejected(ErrorCodes.PAIRING_EXPIRED, "配对码已过期，请重新生成")
        }

        val attempts = mutableListOf<EndpointAttempt>()
        val connected = connectFirst(offer.endpoints, attempts)
            ?: return PairAttemptResult.Unreachable(UNREACHABLE_HINT, attempts)

        return try {
            val hello = handshake(connected.connection)
                ?: return PairAttemptResult.Rejected(ErrorCodes.INTERNAL, "电脑端握手失败，请确认两端版本一致")

            if (!hello.pairingOpen) {
                return PairAttemptResult.Rejected(
                    ErrorCodes.PAIRING_CLOSED,
                    "电脑端尚未开启配对，请在电脑管理页点击「添加手机」",
                )
            }

            val session = PhonePairingSession(
                pairingId = offer.pairingId,
                code = code,
                computerPublicKey = Base64Url.decode(offer.computerPublicKey),
                computerDisplayName = hello.displayName,
                // 邀请里已经写明这次配对绑定的是电脑上的哪个 Windows 账户
                windowsUserSid = offer.windowsUserSid,
                windowsUserName = offer.windowsUserName,
                phoneKey = identity,
                phoneProfile = profile,
                startedAt = now,
            )

            exchange(connected.connection, connected.endpoint, session, attempts)
        } catch (error: Throwable) {
            PairAttemptResult.Unreachable(error.message ?: "配对过程中连接中断", attempts)
        } finally {
            runCatching { connected.connection.close() }
        }
    }

    // ——————————————————————————————————————————————————————————
    // 配对 · 手动输入路径
    // ——————————————————————————————————————————————————————————

    /**
     * 手动配对：用户只在手机上填「主机 + 端口 + 电脑屏幕上那 6 位数字」。
     *
     * `pairingId` 与电脑公钥从 [ServerHello] 里拿 ——
     * 这一步不泄露任何机密（公钥本来就是公开的，pairingId 也不是信任锚），
     * 真正的门槛始终是那 6 位配对码。
     *
     * 安全性与扫码路径完全等价：
     * 中间人即使伪造 `ServerHello` 塞进自己的公钥，也拿不到配对码，
     * 算不出正确的 `confirmTag`，手机端的校验会直接失败。
     */
    suspend fun pairManually(
        endpoint: Endpoint,
        code: String,
        now: Long = PlatformEnv.currentTimeMillis(),
    ): PairAttemptResult {
        val attempts = mutableListOf<EndpointAttempt>()
        val connected = connectFirst(listOf(endpoint), attempts)
            ?: return PairAttemptResult.Unreachable(UNREACHABLE_HINT, attempts)

        return try {
            val hello = handshake(connected.connection)
                ?: return PairAttemptResult.Rejected(ErrorCodes.INTERNAL, "电脑端握手失败，请确认地址与端口是否正确")

            if (!hello.pairingOpen) {
                return PairAttemptResult.Rejected(
                    ErrorCodes.PAIRING_CLOSED,
                    "已连上「${hello.displayName}」，但它还没开启配对窗口。请先在电脑管理页点「添加手机」",
                )
            }

            val pairingId = hello.activePairingId
                ?: return PairAttemptResult.Rejected(
                    ErrorCodes.PAIRING_CLOSED,
                    "电脑端没有可用的配对会话，请重新点击「添加手机」",
                )

            val session = PhonePairingSession(
                pairingId = pairingId,
                code = code,
                computerPublicKey = Base64Url.decode(hello.publicKey),
                computerDisplayName = hello.displayName,
                // 手动路径没有二维码，账户信息从 ServerHello 里取
                windowsUserSid = hello.windowsUserSid,
                windowsUserName = hello.windowsUserName,
                phoneKey = identity,
                phoneProfile = profile,
                startedAt = now,
            )

            exchange(connected.connection, connected.endpoint, session, attempts)
        } catch (error: Throwable) {
            PairAttemptResult.Unreachable(error.message ?: "配对过程中连接中断", attempts)
        } finally {
            runCatching { connected.connection.close() }
        }
    }

    /**
     * 两条配对路径共用的报文交换。
     *
     * 电脑端会先回一个 `pair.pending`（表示「已收到，等用户点确认」），
     * 再回最终结果 —— 这样手机端不会因为用户思考了几秒钟就超时。
     */
    private suspend fun exchange(
        connection: Connection,
        endpoint: Endpoint,
        session: PhonePairingSession,
        attempts: List<EndpointAttempt>,
    ): PairAttemptResult {
        connection.send(session.buildRequest(PlatformEnv.currentTimeMillis()))

        var response: PairResponse? = null
        var round = 0
        while (round < MAX_PAIR_MESSAGES && response == null) {
            round += 1
            when (val message = connection.receive()) {
                is PairPending -> Unit

                is PairResponse -> response = message

                is ErrorMessage -> return PairAttemptResult.Rejected(message.code, message.message)

                null -> return PairAttemptResult.Rejected(
                    ErrorCodes.INTERNAL,
                    "电脑端提前断开了连接（可能是配对窗口已关闭）",
                )

                else -> Unit
            }
        }

        val finalResponse = response
            ?: return PairAttemptResult.Rejected(ErrorCodes.INTERNAL, "电脑端未返回配对结果")

        return try {
            PairAttemptResult.Success(
                record = session.acceptResponse(finalResponse, PlatformEnv.currentTimeMillis()),
                endpoint = endpoint,
            )
        } catch (error: PairingException) {
            PairAttemptResult.Rejected(error.code, error.message ?: "配对失败")
        }
    }

    // ——————————————————————————————————————————————————————————
    // 解锁
    // ——————————————————————————————————————————————————————————

    /**
     * 向已配对的电脑发送解锁指令。
     *
     * **调用前必须已经完成生物识别校验** —— 本方法不做任何用户身份判断，
     * 它只负责把「已授权的动作」安全地送达。
     */
    suspend fun unlock(
        record: TrustRecord,
        action: String = UnlockAction.UNLOCK,
        now: Long = PlatformEnv.currentTimeMillis(),
    ): UnlockAttemptResult {
        val secret = record.resolveSecret()
        val counter = record.lastCounter + 1

        val attempts = mutableListOf<EndpointAttempt>()
        val connected = connectFirst(record.endpoints, attempts)
            ?: return UnlockAttemptResult.Unreachable(
                "找不到这台电脑。可能不在同一网络，或内网穿透已断开。",
                attempts,
            )

        return try {
            handshake(connected.connection)
                ?: return UnlockAttemptResult.Rejected(ErrorCodes.INTERNAL, "电脑端握手失败")

            val request = UnlockProtocol.seal(
                secret = secret,
                phoneKey = identity,
                phoneDeviceId = phoneDeviceId,
                clientDisplayName = profile.displayName,
                // 目标账户取自信任记录：这条记录是为哪个账户配的对，就只解锁哪个账户
                targetWindowsUserSid = record.windowsUserSid,
                counter = counter,
                now = now,
                action = action,
            )

            connected.connection.send(request)

            val ack = withTimeoutOrNull(ACK_TIMEOUT_MILLIS) { connected.connection.receive() }
                ?: return UnlockAttemptResult.Unreachable("等待电脑确认超时", attempts)

            when (ack) {
                is UnlockAck -> {
                    // 回执也要验 MAC：否则伪造的「成功」会让用户以为门已经开了
                    if (!UnlockProtocol.verifyAck(secret, ack)) {
                        return UnlockAttemptResult.Rejected(
                            ErrorCodes.BAD_SIGNATURE,
                            "回执校验失败，连接可能被劫持",
                        )
                    }
                    if (!ack.ok) {
                        return UnlockAttemptResult.Rejected(
                            ack.code ?: ErrorCodes.UNLOCK_REJECTED,
                            ack.message ?: "电脑端拒绝了解锁",
                        )
                    }
                    UnlockAttemptResult.Success(
                        serverTime = ack.serverTime,
                        endpoint = connected.endpoint,
                        updatedRecord = record.copy(
                            lastCounter = counter,
                            lastSeenAt = PlatformEnv.currentTimeMillis(),
                        ),
                    )
                }

                is ErrorMessage -> UnlockAttemptResult.Rejected(ack.code, ack.message)

                else -> UnlockAttemptResult.Rejected(ErrorCodes.INTERNAL, "电脑端返回了意外的报文")
            }
        } catch (error: Throwable) {
            UnlockAttemptResult.Unreachable(error.message ?: "发送指令失败", attempts)
        } finally {
            runCatching { connected.connection.close() }
        }
    }

    /**
     * 连通性探测。设备详情页的「测试连接」用它，
     * 只做握手不做解锁，因此不需要生物识别。
     */
    suspend fun probe(record: TrustRecord): List<EndpointAttempt> {
        val attempts = mutableListOf<EndpointAttempt>()
        for (endpoint in ordered(record.endpoints)) {
            val started = PlatformEnv.currentTimeMillis()
            try {
                val connection = Transport.connect(endpoint, connectTimeoutMillis = PROBE_TIMEOUT_MILLIS)
                try {
                    val hello = handshake(connection)
                    val latency = PlatformEnv.currentTimeMillis() - started
                    attempts += EndpointAttempt(
                        endpoint = endpoint,
                        success = hello != null,
                        detail = if (hello != null) {
                            "已连上「${hello.displayName}」，往返 ${latency}ms"
                        } else {
                            "握手失败"
                        },
                    )
                } finally {
                    runCatching { connection.close() }
                }
            } catch (error: Throwable) {
                attempts += EndpointAttempt(
                    endpoint = endpoint,
                    success = false,
                    detail = error.message ?: "连接失败",
                )
            }
        }
        return attempts
    }

    /** 手动添加/编辑地址后，验证用户填的 host:port 是否真的是 PawLocker 服务。 */
    suspend fun probeRaw(host: String, port: Int): EndpointAttempt {
        val endpoint = Endpoint(
            kind = com.kira.pawlocker.core.protocol.TransportKind.MANUAL,
            host = host,
            port = port,
            label = "手动配置",
        )
        return try {
            val connection = Transport.connect(endpoint, connectTimeoutMillis = PROBE_TIMEOUT_MILLIS)
            try {
                val hello = handshake(connection)
                EndpointAttempt(
                    endpoint = endpoint,
                    success = hello != null,
                    detail = if (hello != null) {
                        "已连上「${hello.displayName}」，配对窗口${if (hello.pairingOpen) "已开启" else "未开启"}"
                    } else {
                        "对端不是 PawLocker 服务"
                    },
                )
            } finally {
                runCatching { connection.close() }
            }
        } catch (error: Throwable) {
            EndpointAttempt(endpoint, false, error.message ?: "连接失败")
        }
    }

    // ——————————————————————————————————————————————————————————
    // 内部工具
    // ——————————————————————————————————————————————————————————

    private class Connected(val connection: Connection, val endpoint: Endpoint)

    private fun ordered(endpoints: List<Endpoint>): List<Endpoint> =
        endpoints.sortedWith(Endpoint.preferredOrder)

    /**
     * 按优先级依次尝试所有地址。
     * 只有「连不上」才换下一个；一旦 TCP 连上就认定该地址可用，
     * 后续失败属于协议层问题，换地址也没用。
     */
    private suspend fun connectFirst(
        endpoints: List<Endpoint>,
        attempts: MutableList<EndpointAttempt>,
    ): Connected? {
        if (endpoints.isEmpty()) return null
        for (endpoint in ordered(endpoints)) {
            try {
                val connection = Transport.connect(endpoint)
                attempts += EndpointAttempt(endpoint, success = true, detail = "已连接")
                return Connected(connection, endpoint)
            } catch (error: Throwable) {
                attempts += EndpointAttempt(
                    endpoint = endpoint,
                    success = false,
                    detail = error.message ?: "连接失败",
                )
            }
        }
        return null
    }

    /** 发送 ClientHello 并读取 ServerHello。 */
    private suspend fun handshake(connection: Connection): ServerHello? {
        connection.send(
            ClientHello(
                deviceId = phoneDeviceId,
                displayName = profile.displayName,
                model = profile.model,
                publicKey = Base64Url.encode(identity.publicKey),
                nonce = PairingProtocol.newNonce(),
            ),
        )
        return when (val message = connection.receive()) {
            is ServerHello -> message

            is ErrorMessage -> throw IllegalStateException("${message.code}: ${message.message}")

            else -> null
        }
    }

    private companion object {
        const val MAX_PAIR_MESSAGES = 4
        const val ACK_TIMEOUT_MILLIS = 20_000L
        const val PROBE_TIMEOUT_MILLIS = 5_000

        const val UNREACHABLE_HINT =
            "所有地址都连不上。请确认电脑端服务已启动，或检查内网穿透是否在线。"
    }
}
