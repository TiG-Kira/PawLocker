package com.kira.pawlocker.core.net

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * 限流与认证节流。
 *
 * 监听端口一旦经内网穿透暴露到公网，6 位配对码面对的是「几分钟就能跑完」的
 * 在线爆破。限流是这套方案能不能上公网的前提，不是可选项。
 */
class RateLimiterTest {

    @Test
    fun `令牌桶按容量放行`() {
        val limiter = RateLimiter(capacity = 3.0, refillPerSecond = 1.0)

        assertTrue(limiter.tryAcquire("1.2.3.4", now = 0))
        assertTrue(limiter.tryAcquire("1.2.3.4", now = 0))
        assertTrue(limiter.tryAcquire("1.2.3.4", now = 0))
        assertFalse(limiter.tryAcquire("1.2.3.4", now = 0), "令牌耗尽后必须拒绝")
    }

    @Test
    fun `令牌按时间匀速补充`() {
        val limiter = RateLimiter(capacity = 2.0, refillPerSecond = 1.0)

        assertTrue(limiter.tryAcquire("ip", now = 0))
        assertTrue(limiter.tryAcquire("ip", now = 0))
        assertFalse(limiter.tryAcquire("ip", now = 500), "半秒只补半个令牌，不够一次请求")

        assertTrue(limiter.tryAcquire("ip", now = 1000), "满一秒应补足一个令牌")
        assertFalse(limiter.tryAcquire("ip", now = 1000))
    }

    @Test
    fun `补充不会超过容量上限`() {
        val limiter = RateLimiter(capacity = 2.0, refillPerSecond = 100.0)

        limiter.tryAcquire("ip", now = 0)
        limiter.tryAcquire("ip", now = 0)

        // 放置很久也不应该攒出无限令牌：容量就是并发上限
        assertTrue(limiter.tryAcquire("ip", now = 1_000_000))
        assertTrue(limiter.tryAcquire("ip", now = 1_000_000))
        assertFalse(limiter.tryAcquire("ip", now = 1_000_000))
    }

    @Test
    fun `不同来源互不影响`() {
        val limiter = RateLimiter(capacity = 1.0, refillPerSecond = 0.0)

        assertTrue(limiter.tryAcquire("attacker", now = 0))
        assertFalse(limiter.tryAcquire("attacker", now = 0))
        // 一个 IP 被打满不能牵连其他 IP，否则攻击者可以用这点做拒绝服务
        assertTrue(limiter.tryAcquire("legit-phone", now = 0))
    }

    @Test
    fun `时间倒流不会凭空生成令牌`() {
        val limiter = RateLimiter(capacity = 1.0, refillPerSecond = 1.0)

        assertTrue(limiter.tryAcquire("ip", now = 10_000))
        // 系统时钟回拨（NTP 校正、用户改时间）不应变成「令牌无限」
        assertFalse(limiter.tryAcquire("ip", now = 0))
    }

    @Test
    fun `跟踪的键数量有上限`() {
        val limiter = RateLimiter(capacity = 1.0, refillPerSecond = 0.0, maxTrackedKeys = 8)

        for (i in 0 until 200) limiter.tryAcquire("ip-$i", now = 0)

        // 只要没抛内存错误即说明有淘汰；再确认具体行为：最早的键已被移除
        assertTrue(limiter.tryAcquire("ip-199", now = 0).not(), "最近的键应仍在跟踪")
        assertTrue(limiter.tryAcquire("ip-0", now = 0), "最早的键应已被淘汰，重新计数")
    }

    @Test
    fun `reset 清空全部计数`() {
        val limiter = RateLimiter(capacity = 1.0, refillPerSecond = 0.0)
        assertTrue(limiter.tryAcquire("ip", now = 0))
        assertFalse(limiter.tryAcquire("ip", now = 0))

        limiter.reset()
        assertTrue(limiter.tryAcquire("ip", now = 0))
    }

    @Test
    fun `节流器在阈值前不拦截`() {
        val throttle = AuthThrottle(threshold = 3, baseBackoffMillis = 1_000, maxBackoffMillis = 60_000)

        assertFalse(throttle.isBlocked("ip", now = 0))
        throttle.recordFailure("ip", now = 0)
        throttle.recordFailure("ip", now = 0)
        assertFalse(throttle.isBlocked("ip", now = 0), "两次失败还未达阈值")
    }

    @Test
    fun `达到阈值后开始拦截并在退避结束后恢复`() {
        val throttle = AuthThrottle(threshold = 3, baseBackoffMillis = 1_000, maxBackoffMillis = 60_000)

        throttle.recordFailure("ip", now = 0)
        throttle.recordFailure("ip", now = 0)
        throttle.recordFailure("ip", now = 0)

        assertTrue(throttle.isBlocked("ip", now = 999))
        assertFalse(throttle.isBlocked("ip", now = 1_000), "退避到点应放行")
    }

    @Test
    fun `退避时长随失败次数指数增长`() {
        val throttle = AuthThrottle(threshold = 3, baseBackoffMillis = 1_000, maxBackoffMillis = 300_000)

        repeat(3) { throttle.recordFailure("ip", now = 0) }
        assertFalse(throttle.isBlocked("ip", now = 1_000))

        // 第 4 次失败：2^1 * 1000 = 2000
        throttle.recordFailure("ip", now = 1_000)
        assertTrue(throttle.isBlocked("ip", now = 2_999))
        assertFalse(throttle.isBlocked("ip", now = 3_000))

        // 第 5 次失败：2^2 * 1000 = 4000
        throttle.recordFailure("ip", now = 3_000)
        assertTrue(throttle.isBlocked("ip", now = 6_999))
        assertFalse(throttle.isBlocked("ip", now = 7_000))
    }

    @Test
    fun `退避时长有上限不会被无限放大`() {
        val throttle = AuthThrottle(threshold = 1, baseBackoffMillis = 1_000, maxBackoffMillis = 5_000)

        repeat(50) { throttle.recordFailure("ip", now = 0) }

        assertTrue(throttle.isBlocked("ip", now = 4_999))
        assertFalse(throttle.isBlocked("ip", now = 5_000), "必须被 maxBackoffMillis 封顶")
    }

    @Test
    fun `认证成功清除该来源的失败记录`() {
        val throttle = AuthThrottle(threshold = 3, baseBackoffMillis = 60_000, maxBackoffMillis = 60_000)

        repeat(3) { throttle.recordFailure("ip", now = 0) }
        assertTrue(throttle.isBlocked("ip", now = 0))

        throttle.recordSuccess("ip")
        assertFalse(throttle.isBlocked("ip", now = 0), "成功一次后不应再被拦截")

        // 再次累计需要重新从 0 开始，而不是接着之前的次数
        throttle.recordFailure("ip", now = 0)
        assertFalse(throttle.isBlocked("ip", now = 0))
    }

    @Test
    fun `节流按来源隔离`() {
        val throttle = AuthThrottle(threshold = 2, baseBackoffMillis = 60_000, maxBackoffMillis = 60_000)

        throttle.recordFailure("attacker", now = 0)
        throttle.recordFailure("attacker", now = 0)

        assertTrue(throttle.isBlocked("attacker", now = 0))
        assertFalse(throttle.isBlocked("legit-phone", now = 0))
    }

    @Test
    fun `节流器 reset 清空状态`() {
        val throttle = AuthThrottle(threshold = 1, baseBackoffMillis = 60_000, maxBackoffMillis = 60_000)
        throttle.recordFailure("ip", now = 0)
        assertTrue(throttle.isBlocked("ip", now = 0))

        throttle.reset()
        assertFalse(throttle.isBlocked("ip", now = 0))
    }
}
