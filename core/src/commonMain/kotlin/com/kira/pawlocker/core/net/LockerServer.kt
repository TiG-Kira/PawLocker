package com.kira.pawlocker.core.net

import com.kira.pawlocker.core.crypto.DeviceIds
import com.kira.pawlocker.core.crypto.DeviceProfile
import com.kira.pawlocker.core.crypto.IdentityKey
import com.kira.pawlocker.core.platform.PlatformEnv
import com.kira.pawlocker.core.platform.UserIdentity
import com.kira.pawlocker.core.protocol.ClientHello
import com.kira.pawlocker.core.protocol.ComputerPairingSession
import com.kira.pawlocker.core.protocol.Endpoint
import com.kira.pawlocker.core.protocol.ErrorCodes
import com.kira.pawlocker.core.protocol.ErrorMessage
import com.kira.pawlocker.core.protocol.PairingException
import com.kira.pawlocker.core.protocol.PairingOffer
import com.kira.pawlocker.core.protocol.PairPending
import com.kira.pawlocker.core.protocol.PairRequest
import com.kira.pawlocker.core.protocol.Ping
import com.kira.pawlocker.core.protocol.Pong
import com.kira.pawlocker.core.protocol.Protocol
import com.kira.pawlocker.core.protocol.ReplayGuard
import com.kira.pawlocker.core.protocol.ServerHello
import com.kira.pawlocker.core.protocol.UnlockProtocol
import com.kira.pawlocker.core.protocol.UnlockRejectedException
import com.kira.pawlocker.core.protocol.UnlockRequest
import com.kira.pawlocker.core.protocol.WireMessage
import com.kira.pawlocker.core.trust.TrustRecord
import com.kira.pawlocker.core.trust.TrustStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull

/**
 * Windows 端的监听服务。
 *
 * 一个 [LockerServer] 对应「监听端口 + 维护信任列表 + 执行解锁」这一整条链路。
 * UI 只负责调用 [start] / [stop] / [openPairingWindow]，以及实现 [ServerHooks]。
 *
 * 线程模型：所有网络操作跑在自己的 [CoroutineScope] 里，
 * 每个进来的连接一个协程，互不阻塞。UI 线程永远不会被网络 IO 卡住。
 */
class LockerServer(
    private val identity: IdentityKey,
    private val profile: DeviceProfile,
    /**
     * 本机当前登录的 Windows 账户 —— 三元绑定链（设备 / 账户 / 手机）的中间一环。
     *
     * 由平台侧解析后注入，而不是在这里现取：一来解析要拉进程、不想每次解锁都拉，
     * 二来测试需要能构造一个确定的账户来验证「账户不匹配必须拒绝」。
     */
    private val localUser: UserIdentity,
    private val trustStore: TrustStore,
    private val hooks: ServerHooks,
    private val guard: ReplayGuard = ReplayGuard(),
    private val limiter: RateLimiter = RateLimiter(),
    private val throttle: AuthThrottle = AuthThrottle(),
) {

    private var scope: CoroutineScope? = null
    private var handle: ServerHandle? = null

    @Volatile
    private var pairingSession: ComputerPairingSession? = null

    @Volatile
    private var advertisedEndpoints: List<Endpoint> = emptyList()

    val isRunning: Boolean get() = handle != null

    val pairingOpen: Boolean get() = pairingSession != null

    /** 当前有效（且未过期）的配对邀请；UI 用它渲染二维码与配对码。 */
    fun currentPairingOffer(): PairingOffer? {
        val session = pairingSession ?: return null
        if (session.isExpired(PlatformEnv.currentTimeMillis())) {
            pairingSession = null
            return null
        }
        return session.offer(advertisedEndpoints)
    }

    fun setEndpoints(endpoints: List<Endpoint>) {
        advertisedEndpoints = endpoints
    }

    /** 从信任列表里恢复防重放基线，必须在 [start] 之前调用。 */
    fun restoreReplayBaseline() {
        trustStore.all()
            .filter { it.role == com.kira.pawlocker.core.trust.PeerRole.PHONE }
            .forEach { guard.seed(it.deviceId, it.lastCounter) }
    }

    suspend fun start(port: Int, bindAddress: String = "0.0.0.0") {
        if (isRunning) return

        val serverScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        scope = serverScope

        val serverHandle = Transport.listen(port, bindAddress) { connection ->
            serverScope.launch {
                handleClient(connection)
            }
        }

        handle = serverHandle
        hooks.onEvent(
            ServerEvent(
                at = PlatformEnv.currentTimeMillis(),
                kind = ServerEventKind.STARTED,
                message = "服务已启动，监听 $bindAddress:${serverHandle.boundPort}",
            ),
        )
    }

    fun stop() {
        handle?.close()
        handle = null
        pairingSession = null
        scope?.cancel()
        scope = null
        hooks.onEvent(
            ServerEvent(
                at = PlatformEnv.currentTimeMillis(),
                kind = ServerEventKind.STOPPED,
                message = "服务已停止",
            ),
        )
    }

    // ——————————————————————————————————————————————————————————
    // 配对窗口
    // ——————————————————————————————————————————————————————————

    /**
     * 开启配对窗口：生成配对码与配对邀请。
     * 调用方（管理页）拿到 [PairingOffer] 后展示 QR 与 6 位码。
     */
    fun openPairingWindow(now: Long = PlatformEnv.currentTimeMillis()): PairingOffer {
        val session = ComputerPairingSession(
            pairingId = com.kira.pawlocker.core.protocol.PairingProtocol.newPairingId(),
            code = com.kira.pawlocker.core.protocol.PairingProtocol.randomCode(),
            computerKey = identity,
            computerProfile = profile,
            windowsUser = localUser,
            createdAt = now,
        )
        pairingSession = session
        hooks.onEvent(
            ServerEvent(
                now,
                ServerEventKind.PAIRING_OPENED,
                "已开启配对窗口，有效期 120 秒；本次配对将绑定账户「${localUser.description}」",
            ),
        )
        return session.offer(advertisedEndpoints)
    }

    fun closePairingWindow() {
        if (pairingSession == null) return
        pairingSession = null
        hooks.onEvent(
            ServerEvent(
                PlatformEnv.currentTimeMillis(),
                ServerEventKind.PAIRING_CLOSED,
                "配对窗口已关闭",
            ),
        )
    }

    // ——————————————————————————————————————————————————————————
    // 信任列表
    // ——————————————————————————————————————————————————————————

    fun trustedPhones(): List<TrustRecord> =
        trustStore.all().filter { it.role == com.kira.pawlocker.core.trust.PeerRole.PHONE }

    /** 删除一台信任手机。下一次它再发指令会被直接拒绝。 */
    fun revoke(deviceId: String) {
        val record = trustStore.byId(deviceId) ?: return
        trustStore.remove(deviceId)
        hooks.onEvent(
            ServerEvent(
                PlatformEnv.currentTimeMillis(),
                ServerEventKind.DEVICE_REVOKED,
                "已移除信任手机「${record.displayName}」",
                record.displayName,
            ),
        )
    }

    // ——————————————————————————————————————————————————————————
    // 连接处理
    // ——————————————————————————————————————————————————————————

    private suspend fun handleClient(connection: Connection) {
        val remote = connection.remoteDescription
        val now = PlatformEnv.currentTimeMillis()

        try {
            if (!limiter.tryAcquire(remote, now)) {
                connection.send(ErrorMessage(ErrorCodes.RATE_LIMITED, "请求过于频繁"))
                return
            }
            if (throttle.isBlocked(remote, now)) {
                connection.send(ErrorMessage(ErrorCodes.RATE_LIMITED, "认证失败次数过多，请稍后再试"))
                return
            }

            val hello = connection.receive() as? ClientHello
                ?: return connection.send(ErrorMessage(ErrorCodes.INTERNAL, "缺少握手报文"))

            if (hello.v != Protocol.VERSION) {
                connection.send(
                    ErrorMessage(
                        ErrorCodes.VERSION_MISMATCH,
                        "协议版本不一致：电脑 v${Protocol.VERSION}，手机 v${hello.v}",
                    ),
                )
                return
            }

            hooks.onEvent(
                ServerEvent(
                    at = PlatformEnv.currentTimeMillis(),
                    kind = ServerEventKind.CLIENT_CONNECTED,
                    message = "设备「${hello.displayName}」已连接",
                    deviceName = hello.displayName,
                ),
            )

            val activePairing = pairingSession

            connection.send(
                ServerHello(
                    deviceId = DeviceIds.fromPublicKey(identity.publicKey),
                    displayName = profile.displayName,
                    model = profile.model,
                    publicKey = com.kira.pawlocker.core.crypto.Base64Url.encode(identity.publicKey),
                    nonce = com.kira.pawlocker.core.protocol.PairingProtocol.newNonce(),
                    pairingOpen = activePairing != null && !activePairing.isExpired(PlatformEnv.currentTimeMillis()),
                    activePairingId = activePairing?.pairingId,
                    windowsUserSid = localUser.bindingKey,
                    windowsUserName = localUser.displayName,
                    serverTime = PlatformEnv.currentTimeMillis(),
                    trustedDeviceCount = trustedPhones().size,
                ),
            )

            while (true) {
                val message = connection.receive() ?: break
                when (message) {
                    is PairRequest -> handlePairRequest(connection, message, remote)
                    is UnlockRequest -> handleUnlockRequest(connection, message, remote)
                    is Ping -> connection.send(
                        Pong(message.at, PlatformEnv.currentTimeMillis()),
                    )

                    else -> connection.send(
                        ErrorMessage(
                            ErrorCodes.INTERNAL,
                            "当前状态下不接受类型为 ${message::class.simpleName} 的报文",
                        ),
                    )
                }
            }
        } catch (error: Throwable) {
            PlatformEnv.log(TAG, "连接 $remote 处理异常: ${error.message}")
        } finally {
            runCatching { connection.close() }
        }
    }

    private suspend fun handlePairRequest(
        connection: Connection,
        request: PairRequest,
        remote: String,
    ) {
        val now = PlatformEnv.currentTimeMillis()
        val session = pairingSession
        if (session == null) {
            connection.send(ErrorMessage(ErrorCodes.PAIRING_CLOSED, "电脑端未开启配对，请在管理页点击「添加手机」"))
            return
        }

        val payload = try {
            session.decryptRequest(request, now)
        } catch (error: PairingException) {
            throttle.recordFailure(remote, now)
            connection.send(ErrorMessage(error.code, error.message ?: "配对失败"))
            return
        }

        // 先告诉手机「请求已收到，等电脑确认」，避免它超时重试
        connection.send(PairPending(session.pairingId, now))

        val approved = withTimeoutOrNull(PAIRING_APPROVAL_TIMEOUT) {
            hooks.confirmPairing(
                phoneDisplayName = payload.phoneDisplayName,
                phoneModel = payload.phoneModel,
                phoneDeviceId = payload.phoneDeviceId,
            )
        } ?: false

        val reason = if (approved) null else "电脑端拒绝了本次配对（或确认超时）"

        // 顺序很重要：buildResponse 还要用配对码保护密钥，complete() 会把它擦掉
        val response = session.buildResponse(
            request = request,
            payload = payload,
            accepted = approved,
            endpoints = advertisedEndpoints,
            now = PlatformEnv.currentTimeMillis(),
            message = reason,
        )
        connection.send(response)

        if (approved) {
            val record = session.complete(payload, PlatformEnv.currentTimeMillis())
            trustStore.upsert(record)
            guard.seed(record.deviceId, record.lastCounter)
            pairingSession = null
            throttle.recordSuccess(remote)
            hooks.onEvent(
                ServerEvent(
                    at = PlatformEnv.currentTimeMillis(),
                    kind = ServerEventKind.DEVICE_PAIRED,
                    message = "已配对手机「${record.displayName}」",
                    deviceName = record.displayName,
                ),
            )
        } else {
            throttle.recordFailure(remote, now)
            hooks.onEvent(
                ServerEvent(
                    at = PlatformEnv.currentTimeMillis(),
                    kind = ServerEventKind.PAIRING_REJECTED,
                    message = "已拒绝「${payload.phoneDisplayName}」的配对请求",
                    deviceName = payload.phoneDisplayName,
                ),
            )
        }
    }

    private suspend fun handleUnlockRequest(
        connection: Connection,
        request: UnlockRequest,
        remote: String,
    ) {
        val now = PlatformEnv.currentTimeMillis()
        val record = trustStore.byId(request.deviceId)

        if (record == null) {
            throttle.recordFailure(remote, now)
            connection.send(
                ErrorMessage(
                    ErrorCodes.DEVICE_NOT_TRUSTED,
                    "该设备不在信任列表中，请在电脑管理页重新配对",
                ),
            )
            return
        }

        // ——— 绑定链的第二环：账户 ———
        // 设备对上了，还要确认这条信任关系是为**本机当前账户**建立的。
        // 少了这一步，「给账户 A 配对的手机」就能把同机账户 B 一起解开 ——
        // 家用电脑多账户、共用电脑的场景下这不是理论问题。
        if (record.windowsUserSid != localUser.bindingKey) {
            throttle.recordFailure(remote, now)
            val boundTo = record.windowsUserName.ifBlank { record.windowsUserSid.ifBlank { "未知账户" } }
            connection.send(
                ErrorMessage(
                    ErrorCodes.USER_MISMATCH,
                    "「${record.displayName}」是为 Windows 账户「$boundTo」配对的，" +
                        "不能解锁当前账户「${localUser.description}」。请在该账户下重新配对。",
                ),
            )
            hooks.onEvent(
                ServerEvent(
                    at = PlatformEnv.currentTimeMillis(),
                    kind = ServerEventKind.UNLOCK_FAILED,
                    message = "「${record.displayName}」绑定的账户（$boundTo）与当前账户不符，已拒绝",
                    deviceName = record.displayName,
                ),
            )
            return
        }

        val secret = record.resolveSecret()

        val payload = try {
            UnlockProtocol.open(
                request = request,
                phonePublicKey = record.publicKeyBytes(),
                secret = secret,
                expectedWindowsUserSid = localUser.bindingKey,
                guard = guard,
                now = now,
            )
        } catch (error: UnlockRejectedException) {
            throttle.recordFailure(remote, now)
            connection.send(
                UnlockProtocol.buildAck(
                    secret = secret,
                    ok = false,
                    counter = request.counter,
                    serverTime = PlatformEnv.currentTimeMillis(),
                    code = error.code,
                    message = error.message,
                ),
            )
            hooks.onEvent(
                ServerEvent(
                    at = PlatformEnv.currentTimeMillis(),
                    kind = ServerEventKind.UNLOCK_FAILED,
                    message = "来自「${record.displayName}」的指令被拒绝：${error.message}",
                    deviceName = record.displayName,
                ),
            )
            return
        }

        throttle.recordSuccess(remote)

        val outcome = hooks.onUnlock(payload, record)
        val ok = outcome is UnlockOutcome.Success

        // 记录使用过的最高计数器，重启后据此拒绝更旧的指令
        trustStore.upsert(
            record.copy(
                lastSeenAt = PlatformEnv.currentTimeMillis(),
                lastCounter = maxOf(record.lastCounter, request.counter),
            ),
        )

        connection.send(
            UnlockProtocol.buildAck(
                secret = secret,
                ok = ok,
                counter = request.counter,
                serverTime = PlatformEnv.currentTimeMillis(),
                code = (outcome as? UnlockOutcome.Failure)?.code,
                message = (outcome as? UnlockOutcome.Failure)?.message,
            ),
        )

        hooks.onEvent(
            ServerEvent(
                at = PlatformEnv.currentTimeMillis(),
                kind = if (ok) ServerEventKind.UNLOCK_SUCCEEDED else ServerEventKind.UNLOCK_FAILED,
                message = if (ok) {
                    "「${record.displayName}」完成了解锁"
                } else {
                    "「${record.displayName}」解锁失败：${(outcome as? UnlockOutcome.Failure)?.message}"
                },
                deviceName = record.displayName,
            ),
        )
    }

    private companion object {
        const val TAG = "LockerServer"
        /** 用户在电脑上确认配对的最长等待时间。 */
        const val PAIRING_APPROVAL_TIMEOUT = 60_000L
    }
}
