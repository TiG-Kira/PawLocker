package com.kira.pawlocker.core.net

import com.kira.pawlocker.core.protocol.Endpoint

/** 一次连接尝试的结果，用于在 UI 上展示「试了哪几个地址」。 */
data class EndpointAttempt(
    val endpoint: Endpoint,
    val success: Boolean,
    val detail: String? = null,
)

/** 解锁动作的执行结果。 */
sealed interface UnlockOutcome {

    data class Success(val serverTime: Long = 0) : UnlockOutcome

    data class Failure(val code: String, val message: String) : UnlockOutcome
}

/** 手机端发起解锁的最终结果。 */
sealed interface UnlockAttemptResult {

    data class Success(
        val serverTime: Long,
        val endpoint: Endpoint,
        /** 计数器已推进后的记录，调用方直接落库即可。 */
        val updatedRecord: com.kira.pawlocker.core.trust.TrustRecord,
    ) : UnlockAttemptResult

    data class Rejected(val code: String, val message: String) : UnlockAttemptResult

    data class Unreachable(
        val message: String,
        val attempts: List<EndpointAttempt>,
    ) : UnlockAttemptResult
}

/** 手机端发起配对的最终结果。 */
sealed interface PairAttemptResult {

    data class Success(
        val record: com.kira.pawlocker.core.trust.TrustRecord,
        val endpoint: Endpoint,
    ) : PairAttemptResult

    data class Rejected(val code: String, val message: String) : PairAttemptResult

    data class Unreachable(
        val message: String,
        val attempts: List<EndpointAttempt>,
    ) : PairAttemptResult
}

/** Windows 端上报给 UI 的事件流。 */
data class ServerEvent(
    val at: Long,
    val kind: ServerEventKind,
    val message: String,
    val deviceName: String? = null,
)

enum class ServerEventKind {
    STARTED,
    STOPPED,
    CLIENT_CONNECTED,
    PAIRING_OPENED,
    PAIRING_CLOSED,
    DEVICE_PAIRED,
    DEVICE_REVOKED,
    PAIRING_REJECTED,
    UNLOCK_SUCCEEDED,
    UNLOCK_FAILED,
    ERROR,
}

/** Windows 端需要 UI 参与的两个回调。 */
interface ServerHooks {

    /**
     * 执行真正的解锁动作。UI 层不参与判断 —— 到这里说明密码学校验已经全部通过。
     */
    suspend fun onUnlock(
        request: com.kira.pawlocker.core.protocol.UnlockRequest.Payload,
        phone: com.kira.pawlocker.core.trust.TrustRecord,
    ): UnlockOutcome

    /**
     * 弹出「手机 XXX 请求配对，是否允许」的确认框。
     * 挂起直到用户操作或超时；返回 true 表示允许。
     */
    suspend fun confirmPairing(
        phoneDisplayName: String,
        phoneModel: String,
        phoneDeviceId: String,
    ): Boolean

    fun onEvent(event: ServerEvent)
}
