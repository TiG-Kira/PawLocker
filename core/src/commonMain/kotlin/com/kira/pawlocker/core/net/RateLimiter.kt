package com.kira.pawlocker.core.net

import com.kira.pawlocker.core.platform.PlatformEnv

/**
 * 极简令牌桶限流，按来源 IP 计数。
 *
 * 监听端口一旦通过内网穿透暴露到公网，就会立刻开始被全网扫描。
 * 限流不是「锦上添花」，而是防止爆破配对码与拖垮 CPU 的必要手段。
 * 6 位配对码只有 100 万种组合，没有限流的话跑起来也就是几分钟的事。
 */
class RateLimiter(
    private val capacity: Double = 20.0,
    private val refillPerSecond: Double = 1.0,
    private val maxTrackedKeys: Int = 512,
) {

    private class Bucket(var tokens: Double, var lastRefillAt: Long)

    private val buckets = LinkedHashMap<String, Bucket>()

    @Synchronized
    fun tryAcquire(key: String, now: Long = PlatformEnv.currentTimeMillis()): Boolean {
        val bucket = buckets.getOrPut(key) {
            if (buckets.size >= maxTrackedKeys) {
                buckets.keys.firstOrNull()?.let { buckets.remove(it) }
            }
            Bucket(capacity, now)
        }
        val elapsedSeconds = (now - bucket.lastRefillAt).coerceAtLeast(0) / 1000.0
        bucket.tokens = (bucket.tokens + elapsedSeconds * refillPerSecond).coerceAtMost(capacity)
        bucket.lastRefillAt = now

        if (bucket.tokens < 1.0) return false
        bucket.tokens -= 1.0
        return true
    }

    @Synchronized
    fun reset() = buckets.clear()
}

/**
 * 认证失败的累计节流器。
 *
 * 单调递增的退避：同一 IP 连续认证失败 N 次后，拒绝对该 IP 服务 [backoffMillis] 毫秒。
 * 目的是把「在线爆破配对码」的可行速率压到实际上不可行的量级。
 */
class AuthThrottle(
    private val threshold: Int = 5,
    private val baseBackoffMillis: Long = 2_000,
    private val maxBackoffMillis: Long = 300_000,
) {

    private class Entry(var failures: Int, var blockedUntil: Long)

    private val entries = LinkedHashMap<String, Entry>()

    @Synchronized
    fun isBlocked(key: String, now: Long): Boolean {
        val entry = entries[key] ?: return false
        return now < entry.blockedUntil
    }

    @Synchronized
    fun recordFailure(key: String, now: Long) {
        val entry = entries.getOrPut(key) { Entry(0, 0) }
        entry.failures += 1
        if (entry.failures >= threshold) {
            val exponent = (entry.failures - threshold).coerceAtMost(10)
            val backoff = (baseBackoffMillis shl exponent).coerceAtMost(maxBackoffMillis)
            entry.blockedUntil = now + backoff
        }
        // 控制内存占用
        if (entries.size > 1024) entries.keys.firstOrNull()?.let { entries.remove(it) }
    }

    @Synchronized
    fun recordSuccess(key: String) {
        entries.remove(key)
    }

    @Synchronized
    fun reset() = entries.clear()
}
