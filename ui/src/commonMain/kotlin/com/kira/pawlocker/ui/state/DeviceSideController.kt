package com.kira.pawlocker.ui.state

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.kira.pawlocker.core.crypto.DeviceProfile
import com.kira.pawlocker.core.crypto.IdentityKey
import com.kira.pawlocker.core.net.EndpointAttempt
import com.kira.pawlocker.core.net.LockerClient
import com.kira.pawlocker.core.net.PairAttemptResult
import com.kira.pawlocker.core.net.UnlockAttemptResult
import com.kira.pawlocker.core.platform.PlatformEnv
import com.kira.pawlocker.core.protocol.Endpoint
import com.kira.pawlocker.core.protocol.ErrorCodes
import com.kira.pawlocker.core.protocol.PairingOffer
import com.kira.pawlocker.core.protocol.Protocol
import com.kira.pawlocker.core.protocol.TransportKind
import com.kira.pawlocker.core.trust.PeerRole
import com.kira.pawlocker.core.trust.TrustRecord
import com.kira.pawlocker.core.trust.TrustStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Android 端的界面状态持有者。
 *
 * 刻意做成普通类 + `mutableStateOf`，而不是 ViewModel：
 *  - 状态量小（一页设备列表 + 一个操作进度）
 *  - 屏幕轮转时由 Activity 重建，重新从 [TrustStore] 读一次即可，
 *    没有需要跨配置变更保留的复杂中间态
 *  - 少一层依赖，跨平台（Windows 端也用同一套写法）保持一致
 */
class DeviceSideController(
    val identity: IdentityKey,
    private val trustStore: TrustStore,
    private val profile: DeviceProfile,
    private val scope: CoroutineScope,
) {

    private val client = LockerClient(identity, profile)

    var devices: List<TrustRecord> by mutableStateOf(emptyList())
        private set

    var lastAttempt: List<EndpointAttempt> by mutableStateOf(emptyList())
        private set

    /** 当前正在执行的解锁任务；null 表示空闲。 */
    var unlockingDeviceId: String? by mutableStateOf(null)
        private set

    var unlockingStage: UnlockStage by mutableStateOf(UnlockStage.Idle)
        private set

    var lastMessage: UiMessage? by mutableStateOf(null)
        private set

    /** 刚配对成功、需要展示 SAS 校验串的设备。 */
    var pendingSasVerification: TrustRecord? by mutableStateOf(null)
        private set

    fun refresh() {
        devices = trustStore.all()
            .filter { it.role == PeerRole.COMPUTER }
            .sortedByDescending { it.lastSeenAt }
    }

    fun clearMessage() {
        lastMessage = null
    }

    fun dismissSasVerification() {
        val record = pendingSasVerification ?: return
        trustStore.upsert(record.copy(sasVerified = true))
        pendingSasVerification = null
        refresh()
    }

    // ——————————————————————————————————————————————————————————
    // 解锁
    // ——————————————————————————————————————————————————————————

    /**
     * 解锁入口。**必须先过生物识别**才会走到发指令那一步。
     */
    fun unlock(record: TrustRecord) {
        if (unlockingDeviceId != null) return
        unlockingDeviceId = record.deviceId
        unlockingStage = UnlockStage.VerifyingIdentity

        scope.launch {
            val gate = biometricGateProvider?.invoke()
            if (gate == null || !gate.isAvailable) {
                finishUnlock(
                    UiMessage.Error(
                        "本机没有可用的生物识别，无法安全地解锁",
                        "请在系统设置中录入指纹或设置设备 PIN",
                    ),
                )
                return@launch
            }

            when (val auth = gate.authenticate(
                title = "解锁「${record.displayName}」",
                subtitle = "验证通过后将向该电脑发送解锁指令",
            )) {
                is com.kira.pawlocker.ui.platform.BiometricResult.Success -> Unit

                is com.kira.pawlocker.ui.platform.BiometricResult.Cancelled -> {
                    finishUnlock(null)
                    return@launch
                }

                is com.kira.pawlocker.ui.platform.BiometricResult.Failed -> {
                    finishUnlock(UiMessage.Error("身份验证失败", auth.message))
                    return@launch
                }

                is com.kira.pawlocker.ui.platform.BiometricResult.Unavailable -> {
                    finishUnlock(UiMessage.Error("生物识别不可用", auth.message))
                    return@launch
                }
            }

            unlockingStage = UnlockStage.SendingCommand
            liveProgress = null
            val result = try {
                client.unlock(record, onProgress = ::onEndpointProgress)
            } finally {
                liveProgress = null
            }
            when (result) {
                is UnlockAttemptResult.Success -> {
                    trustStore.upsert(result.updatedRecord)
                    refresh()
                    finishUnlock(
                        UiMessage.Success(
                            "已解锁「${record.displayName}」",
                            "经由${result.endpoint.kind.displayName} ${result.endpoint.display}",
                        ),
                    )
                }

                is UnlockAttemptResult.Rejected -> finishUnlock(
                    UiMessage.Error(
                        "电脑端拒绝了解锁",
                        friendlyReason(result.code, result.message),
                    ),
                )

                is UnlockAttemptResult.Unreachable -> {
                    lastAttempt = result.attempts
                    finishUnlock(
                        UiMessage.Error(
                            "找不到这台电脑",
                            buildString {
                                appendLine(result.message)
                                appendLine()
                                append("已尝试的地址：")
                                append(result.attempts.joinToString("、") { it.endpoint.display })
                            },
                        ),
                    )
                }
            }
        }
    }

    private fun finishUnlock(message: UiMessage?) {
        unlockingDeviceId = null
        unlockingStage = UnlockStage.Idle
        lastMessage = message
    }

    // ——————————————————————————————————————————————————————————
    // 配对
    // ——————————————————————————————————————————————————————————

    /** 从扫码结果或手动输入构造出的配对邀请。 */
    var manualPairing: ManualPairingDraft by mutableStateOf(ManualPairingDraft())
        private set

    var pairingStage: PairingStage by mutableStateOf(PairingStage.Idle)
        private set

    /**
     * 配对/解锁过程中正在尝试的地址文案，例如「正在尝试 192.168.31.253:28900（1/2）」。
     *
     * 候选地址里只要有一个连不通，一次 `connect()` 就要等到 TCP 超时。
     * 没有这条提示的话，那段等待在用户眼里就是「点了没反应」。
     */
    var liveProgress: String? by mutableStateOf(null)
        private set

    fun updateManualPairing(transform: (ManualPairingDraft) -> ManualPairingDraft) {
        manualPairing = transform(manualPairing)
    }

    /** 由 [LockerClient] 的进度回调驱动，转成一句人能读的话。 */
    private fun onEndpointProgress(endpoint: Endpoint, index: Int, total: Int) {
        liveProgress = if (total <= 1) {
            "正在连接 ${endpoint.display}"
        } else {
            "正在尝试 ${endpoint.display}（${index + 1}/$total）"
        }
    }

    /** 扫码得到的深链，直接进入配对。 */
    fun pairFromDeepLink(raw: String) {
        val offer = PairingOffer.fromDeepLink(raw)
        if (offer == null) {
            lastMessage = UiMessage.Error("二维码无法识别", "请确认扫的是 PawLocker 配对页生成的二维码")
            return
        }
        startPairing(offer, offer.code)
    }

    /** 手动输入：host + port + 电脑屏幕上的 6 位配对码。 */
    fun pairManually() {
        val draft = manualPairing
        val host = draft.host.trim()
        val port = draft.port.toIntOrNull()

        if (host.isBlank()) {
            lastMessage = UiMessage.Error("缺少电脑地址", "请填写电脑端配对页上显示的主机地址，例如 192.168.1.10")
            return
        }
        if (port == null || port !in 1..65535) {
            lastMessage = UiMessage.Error(
                "端口不合法",
                "端口应是 1–65535 之间的数字，默认 ${Protocol.DEFAULT_PORT}",
            )
            return
        }
        if (draft.code.length != Protocol.PAIRING_CODE_DIGITS || draft.code.any { !it.isDigit() }) {
            lastMessage = UiMessage.Error(
                "配对码格式不对",
                "配对码是电脑屏幕上显示的 ${Protocol.PAIRING_CODE_DIGITS} 位数字",
            )
            return
        }

        pairingStage = PairingStage.InProgress
        liveProgress = null
        scope.launch {
            val endpoint = Endpoint(
                kind = draft.transportKind,
                host = host,
                port = port,
                label = "手动配置",
            )
            try {
                handlePairResult(
                    client.pairManually(endpoint, draft.code, PlatformEnv.currentTimeMillis(), ::onEndpointProgress),
                )
            } finally {
                liveProgress = null
            }
        }
    }

    private fun startPairing(offer: PairingOffer, code: String) {
        pairingStage = PairingStage.InProgress
        liveProgress = null
        scope.launch {
            try {
                handlePairResult(
                    client.pair(offer, code, PlatformEnv.currentTimeMillis(), ::onEndpointProgress),
                )
            } finally {
                liveProgress = null
            }
        }
    }

    private fun handlePairResult(result: PairAttemptResult) {
        pairingStage = PairingStage.Idle
        when (result) {
            is PairAttemptResult.Success -> {
                trustStore.upsert(result.record)
                refresh()
                pendingSasVerification = result.record
                lastMessage = UiMessage.Success(
                    "已配对「${result.record.displayName}」",
                    "请核对校验图案与电脑屏幕上的是否一致",
                )
            }

            is PairAttemptResult.Rejected -> {
                lastMessage = UiMessage.Error("配对失败", friendlyReason(result.code, result.message))
            }

            is PairAttemptResult.Unreachable -> {
                lastAttempt = result.attempts
                lastMessage = UiMessage.Error(
                    "连不上电脑",
                    buildString {
                        appendLine(result.message)
                        append("已尝试：")
                        append(
                            result.attempts.joinToString("、") {
                                "${it.endpoint.display}（${it.detail}）"
                            },
                        )
                    },
                )
            }
        }
    }

    // ——————————————————————————————————————————————————————————
    // 设备详情
    // ——————————————————————————————————————————————————————————

    fun probe(record: TrustRecord) {
        scope.launch {
            lastAttempt = withContext(Dispatchers.Default) { client.probe(record) }
        }
    }

    fun forget(record: TrustRecord) {
        trustStore.remove(record.deviceId)
        refresh()
        lastMessage = UiMessage.Success("已删除「${record.displayName}」", "如需再次使用，请在电脑端重新配对")
    }

    /**
     * 「重置本机」：清空全部配对记录。
     *
     * 刻意**不动身份密钥** —— 身份是设备的长期身份，删掉它会让这台手机在
     * 所有电脑上变成「一台新设备」，但并不会提升安全性（配对关系已经清干净了）。
     * 保留身份，重新配对时电脑端还能看出「还是上次那台手机」。
     */
    fun forgetAll() {
        trustStore.clear()
        refresh()
        lastMessage = UiMessage.Success(
            "已清除本机全部配对",
            "这台手机上不再保留任何电脑的密钥。如需再次使用，请在电脑端重新配对",
        )
    }

    /**
     * 重置本机身份：删除身份密钥与全部配对记录。
     *
     * 顺序很关键 —— **先清信任记录再删密钥**。反过来的话，如果删密钥成功、
     * 清记录失败，就会留下一堆「有记录但私钥已换」的废条目，
     * 每次解锁都会签名校验失败，且用户无法通过重新配对修复。
     */
    fun wipeIdentity() {
        trustStore.clear()
        com.kira.pawlocker.core.crypto.IdentityKeyFactory.delete(identity.alias)
        refresh()
        lastMessage = UiMessage.Success(
            "本机身份已重置",
            "请重启应用以生成新的身份密钥，然后到每台电脑上重新配对",
        )
    }

    /** 由 App 注入，避免 `ui` 层直接依赖 Android 的 Activity 上下文。 */
    var biometricGateProvider: (() -> com.kira.pawlocker.ui.platform.BiometricGate?)? = null
}

enum class UnlockStage {
    Idle,
    VerifyingIdentity,
    SendingCommand,
}

enum class PairingStage {
    Idle,
    InProgress,
}

data class ManualPairingDraft(
    val host: String = "",
    val port: String = Protocol.DEFAULT_PORT.toString(),
    val code: String = "",
    val transportKind: TransportKind = TransportKind.MANUAL,
)

/** 一次性提示，用 [Snackbar] 呈现。 */
sealed interface UiMessage {

    val title: String
    val detail: String

    data class Success(override val title: String, override val detail: String) : UiMessage

    data class Error(override val title: String, override val detail: String) : UiMessage

    val isError: Boolean get() = this is Error
}

/** 把协议错误码翻译成人话，别把 `bad_signature` 直接甩给用户。 */
internal fun friendlyReason(code: String, raw: String): String = when (code) {
    ErrorCodes.DEVICE_NOT_TRUSTED -> "这台电脑上已经没有你的配对记录了，请在电脑管理页重新配对"
    ErrorCodes.DEVICE_REVOKED -> "你已被这台电脑移除信任，请重新配对"

    // 下面两条是配对阶段最常见的失败，而且**症状都是「电脑没反应」**。
    // 不说清楚的话，用户只会反复点「添加手机」，而真正的原因是码已经过期。
    ErrorCodes.PAIRING_CLOSED ->
        "电脑端没有可用的配对窗口。请在电脑上点「添加手机」重新生成"
    ErrorCodes.PAIRING_EXPIRED ->
        "配对码只有 2 分钟有效期，已经过期了。请在电脑上点「添加手机」重新生成，" +
            "然后立刻用新码配对"

    ErrorCodes.PAIRING_CODE_MISMATCH -> "配对码不对，请核对电脑屏幕上显示的 6 位数字"
    ErrorCodes.USER_MISMATCH ->
        "这台手机是为另一个 Windows 账户配对的。请用当前登录的账户重新配对"
    ErrorCodes.CLOCK_SKEW -> "手机与电脑的时间差太大，请检查两端时间是否同步"
    ErrorCodes.REPLAY_DETECTED -> "指令被判定为重复，请重试"
    ErrorCodes.RATE_LIMITED -> "尝试太频繁了，等一会儿再试"
    ErrorCodes.VERSION_MISMATCH -> "两端版本不一致，请把 App 升级到同一版本"
    ErrorCodes.BAD_SIGNATURE -> "凭据校验失败，建议在电脑端删除本机后重新配对"

    // 握手阶段没有拿到 ServerHello 时走这里，最常见的原因就是地址/端口不对。
    ErrorCodes.INTERNAL -> raw.ifBlank { "连接已建立但握手失败，请确认两端版本一致" }

    else -> raw
}
