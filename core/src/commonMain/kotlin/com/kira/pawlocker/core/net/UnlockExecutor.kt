package com.kira.pawlocker.core.net

/**
 * 真正的「解锁动作」执行者。
 *
 * 到这一层说明密码学校验已经**全部通过** —— 调用方不应该再做任何身份判断，
 * 只负责把动作落地。这样切分的好处是：安全逻辑可以单测，
 * 平台动作可以按需替换（开发机用模拟实现，生产用 Credential Provider）。
 */
interface UnlockExecutor {

    val displayName: String

    /**
     * @param action [com.kira.pawlocker.core.protocol.UnlockAction] 中的取值
     */
    suspend fun execute(action: String): UnlockOutcome
}

/** 固定返回成功的实现，用于 UI 预览、单元测试与「只验证链路」的调试模式。 */
class SimulatedUnlockExecutor(
    override val displayName: String = "模拟执行器（不会真正解锁）",
    private val delayMillis: Long = 120,
) : UnlockExecutor {

    override suspend fun execute(action: String): UnlockOutcome {
        kotlinx.coroutines.delay(delayMillis)
        com.kira.pawlocker.core.platform.PlatformEnv.log(
            "SimulatedUnlockExecutor",
            "模拟执行解锁动作: $action",
        )
        return UnlockOutcome.Success(com.kira.pawlocker.core.platform.PlatformEnv.currentTimeMillis())
    }
}
