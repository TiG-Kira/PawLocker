package com.kira.pawlocker.core.protocol

/**
 * 防重放守卫。
 *
 * 三重防线，任一不过即拒绝：
 *  1. **时间戳窗口** —— 报文时间与本地时间相差超过 [clockSkewMillis] 直接丢
 *  2. **单调计数器** —— 同一设备的计数器必须严格递增，攻击者即使截获旧报文也放不出来
 *  3. **nonce 去重** —— 窗口期内出现过的 nonce 一律拒绝，兜住计数器被回滚的极端情况
 *
 * 纯内存实现，进程重启后计数器基线从信任列表里恢复（见 `TrustRecord.lastCounter`）。
 * 这也是为什么计数器必须落盘：只要落过盘，重启也不能让旧指令复活。
 */
class ReplayGuard(
    private val clockSkewMillis: Long = Protocol.CLOCK_SKEW_MILLIS,
    private val windowMillis: Long = Protocol.REPLAY_WINDOW_MILLIS,
    private val maxTrackedNonces: Int = 2048,
) {

    private val counters = mutableMapOf<String, Long>()
    private val nonces = LinkedHashMap<String, Long>()

    /** 用信任列表里的历史计数器初始化基线。 */
    fun seed(deviceId: String, lastCounter: Long) {
        val current = counters[deviceId]
        if (current == null || lastCounter > current) counters[deviceId] = lastCounter
    }

    /**
     * @return null 表示通过；否则返回拒绝原因。
     * 注意：**只有通过校验的调用才会推进计数器**，被拒绝的报文不会污染状态。
     */
    fun validate(
        deviceId: String,
        counter: Long,
        timestampMillis: Long,
        nonce: String,
        now: Long,
    ): ReplayFailure? {
        // 1. 时间窗口
        val skew = now - timestampMillis
        if (skew > clockSkewMillis || skew < -clockSkewMillis) {
            return ReplayFailure.ClockSkew(skew)
        }

        // 2. 单调计数器
        val last = counters[deviceId]
        if (last != null && counter <= last) {
            return ReplayFailure.CounterRollback(expected = last + 1, actual = counter)
        }

        // 3. nonce 去重
        evictExpired(now)
        if (nonces.containsKey(nonce)) {
            return ReplayFailure.NonceReused(nonce)
        }

        counters[deviceId] = counter
        nonces[nonce] = now
        trimNonces()
        return null
    }

    private fun evictExpired(now: Long) {
        val iterator = nonces.entries.iterator()
        while (iterator.hasNext()) {
            if (now - iterator.next().value > windowMillis) iterator.remove() else break
        }
    }

    private fun trimNonces() {
        while (nonces.size > maxTrackedNonces) {
            val oldest = nonces.keys.firstOrNull() ?: break
            nonces.remove(oldest)
        }
    }

    fun reset() {
        counters.clear()
        nonces.clear()
    }
}

sealed interface ReplayFailure {
    val message: String

    data class ClockSkew(val skewMillis: Long) : ReplayFailure {
        override val message: String
            get() = "设备时钟偏差 " + (skewMillis / 1000) + " 秒，超出允许范围"
    }

    data class CounterRollback(val expected: Long, val actual: Long) : ReplayFailure {
        override val message: String
            get() = "计数器回滚：期望 > $expected，实际 $actual"
    }

    data class NonceReused(val nonce: String) : ReplayFailure {
        override val message: String get() = "nonce 重复使用"
    }
}
