package com.kira.pawlocker.core.protocol

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * 防重放三重防线。
 *
 * 这是「攻击者录下一条解锁指令再放一遍」的唯一屏障，
 * 每条防线都必须能独立生效 —— 任何一条失效都不该被另两条掩盖。
 */
class ReplayGuardTest {

    private val now = 1_700_000_000_000L

    @Test
    fun `首次报文通过`() {
        val guard = ReplayGuard()
        assertNull(guard.validate("phone-a", 1, now, "n1", now))
    }

    @Test
    fun `计数器严格递增`() {
        val guard = ReplayGuard()
        assertNull(guard.validate("phone-a", 1, now, "n1", now))
        assertNull(guard.validate("phone-a", 2, now, "n2", now))
        assertNull(guard.validate("phone-a", 3, now, "n3", now))
    }

    @Test
    fun `计数器相等或回滚被拒绝`() {
        val guard = ReplayGuard()
        guard.validate("phone-a", 5, now, "n1", now)

        val same = guard.validate("phone-a", 5, now, "n2", now)
        assertTrue(same is ReplayFailure.CounterRollback, "相等也应拒绝：$same")
        assertEquals(6, same.expected)

        val older = guard.validate("phone-a", 4, now, "n3", now)
        assertTrue(older is ReplayFailure.CounterRollback, "回滚应拒绝：$older")
    }

    @Test
    fun `不同设备的计数器互不干扰`() {
        val guard = ReplayGuard()
        assertNull(guard.validate("phone-a", 7, now, "na", now))
        // phone-b 是另一台手机，不能因为它自己的计数从 0 开始就被判回滚
        assertNull(guard.validate("phone-b", 1, now, "nb", now))
        assertNull(guard.validate("phone-a", 8, now, "na2", now))
    }

    @Test
    fun `时间戳过旧被拒绝`() {
        val guard = ReplayGuard()
        val stale = guard.validate("phone-a", 1, now - 120_000, "n1", now)
        assertTrue(stale is ReplayFailure.ClockSkew, "过旧时间戳应拒绝：$stale")
        assertEquals(120_000, stale.skewMillis)
    }

    @Test
    fun `时间戳来自未来被拒绝`() {
        val guard = ReplayGuard()
        val future = guard.validate("phone-a", 1, now + 120_000, "n1", now)
        assertTrue(future is ReplayFailure.ClockSkew, "未来时间戳应拒绝：$future")
        assertEquals(-120_000, future.skewMillis)
    }

    @Test
    fun `窗口边界值被接受`() {
        val guard = ReplayGuard()
        assertNull(guard.validate("phone-a", 1, now - Protocol.CLOCK_SKEW_MILLIS, "n1", now))
        assertNull(guard.validate("phone-b", 1, now + Protocol.CLOCK_SKEW_MILLIS, "n2", now))
    }

    @Test
    fun `nonce 重复使用被拒绝`() {
        val guard = ReplayGuard()
        assertNull(guard.validate("phone-a", 1, now, "same-nonce", now))

        // 计数器递增、时间也新鲜，只有 nonce 重复 —— 必须靠第三道防线兜住
        val reused = guard.validate("phone-a", 2, now, "same-nonce", now)
        assertTrue(reused is ReplayFailure.NonceReused, "重复 nonce 应拒绝：$reused")
        assertEquals("same-nonce", reused.nonce)
    }

    @Test
    fun `被拒绝的报文不会污染计数器状态`() {
        val guard = ReplayGuard()

        // 时间戳超窗被拒 —— 此时不应写入计数器
        guard.validate("phone-a", 100, now - 999_999, "n1", now)

        // 随后一条合法报文用较小的计数器也必须能通过，否则攻击者只要发一条
        // 「签名无效但计数器很大」的报文就能把合法手机永久锁死
        assertNull(guard.validate("phone-a", 1, now, "n2", now))
    }

    @Test
    fun `被拒绝的 nonce 不会被记为已使用`() {
        val guard = ReplayGuard()
        guard.validate("phone-a", 1, now, "n1", now)

        // 计数器回滚被拒，此时 nonce "n2" 不应进入去重表
        guard.validate("phone-a", 1, now, "n2", now)
        assertNull(guard.validate("phone-a", 2, now, "n2", now))
    }

    @Test
    fun `seed 恢复重启前的计数器基线`() {
        val guard = ReplayGuard()
        guard.seed("phone-a", 42)

        val rollback = guard.validate("phone-a", 42, now, "n1", now)
        assertTrue(rollback is ReplayFailure.CounterRollback, "seed 之后回滚到基线应拒绝")
        assertNull(guard.validate("phone-a", 43, now, "n2", now))
    }

    @Test
    fun `seed 不会把基线倒退`() {
        val guard = ReplayGuard()
        guard.seed("phone-a", 10)
        guard.seed("phone-a", 3) // 更小的值必须被忽略

        assertTrue(guard.validate("phone-a", 5, now, "n1", now) is ReplayFailure.CounterRollback)
        assertNull(guard.validate("phone-a", 11, now, "n2", now))
    }

    @Test
    fun `超出保留窗口的 nonce 会被清理`() {
        val guard = ReplayGuard(clockSkewMillis = 1_000, windowMillis = 1_000)

        assertNull(guard.validate("phone-a", 1, 0, "n1", 0))
        // 窗口已过，去重表应已淘汰 n1；此时复用不算重放
        assertNull(guard.validate("phone-a", 2, 2_000, "n1", 2_000))
    }

    @Test
    fun `nonce 去重表容量有上限且会淘汰最早的条目`() {
        val guard = ReplayGuard(maxTrackedNonces = 4)
        val base = now

        for (i in 0 until 20) {
            assertNull(guard.validate("phone-$i", 1, base, "nonce-$i", base))
        }

        // 最早的 nonce 已被淘汰，换个设备 ID 复用不会命中 nonce 规则
        assertNull(
            guard.validate("fresh-device", 1, base, "nonce-0", base),
            "最早写入的 nonce 应已被容量上限淘汰",
        )

        // 但同一设备的计数器仍然在，回滚依旧会被拦住
        val reused = guard.validate("phone-19", 1, base, "nonce-19", base)
        assertTrue(reused is ReplayFailure.CounterRollback, "应命中计数器而非 nonce：$reused")
    }

    @Test
    fun `reset 清空全部状态`() {
        val guard = ReplayGuard()
        guard.validate("phone-a", 5, now, "n1", now)
        guard.reset()

        assertNull(guard.validate("phone-a", 1, now, "n1", now))
    }

    @Test
    fun `拒绝原因的中文描述可读`() {
        val guard = ReplayGuard()
        guard.validate("phone-a", 5, now, "n1", now)

        val rollback = guard.validate("phone-a", 1, now, "n2", now)!!
        assertTrue(rollback.message.isNotBlank())
        assertTrue(rollback.message.contains("计数器"))
    }
}
