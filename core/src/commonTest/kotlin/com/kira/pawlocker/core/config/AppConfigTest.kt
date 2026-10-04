package com.kira.pawlocker.core.config

import com.kira.pawlocker.core.protocol.Protocol
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * 监听端口的默认值与迁移。
 *
 * 这里守的是一次**真实的破坏性变更**：默认端口从 9898 换到 28900。
 * 已经在跑的实例，配置文件里早就把 9898 写死了（`encodeDefaults = true`），
 * 光改常量对它们无效 —— 必须有一条**只针对旧默认值**的迁移。
 *
 * 迁移的边界比迁移本身更重要。范围放松一点点，用户的自选端口就会被改掉，
 * 而症状是「手机再也连不上，但电脑这边界面上一切正常」——
 * 排查时会从网络、配对、手机一路怀疑过去，最后才想到端口被改了。
 */
class AppConfigTest {

    @Test
    fun `默认配置用当前默认端口`() {
        assertEquals(Protocol.DEFAULT_PORT, AppConfig().listenPort)
    }

    @Test
    fun `停在旧默认端口的配置会被升到新默认端口`() {
        val legacy = AppConfig(listenPort = Protocol.LEGACY_DEFAULT_PORT)

        assertEquals(
            Protocol.DEFAULT_PORT,
            legacy.normalized().listenPort,
            "老配置里存的是 9898，不迁的话改常量等于没改",
        )
    }

    @Test
    fun `用户自选的其它端口一律不动`() {
        // 覆盖两侧：比旧值小的、夹在两个默认值之间的、比新值大的、贴边界的
        for (port in listOf(80, 1024, 12345, 28901, 49000, 65535)) {
            assertEquals(
                port,
                AppConfig(listenPort = port).normalized().listenPort,
                "$port 是用户自己选的，迁移不该动它",
            )
        }
    }

    @Test
    fun `越界端口回落到默认值`() {
        for (port in listOf(0, -1, -9898, 65536, Int.MAX_VALUE)) {
            assertEquals(
                Protocol.DEFAULT_PORT,
                AppConfig(listenPort = port).normalized().listenPort,
                "$port 不在 1..65535 内",
            )
        }
    }

    @Test
    fun `迁移是幂等的`() {
        val once = AppConfig(listenPort = Protocol.LEGACY_DEFAULT_PORT).normalized()
        val twice = once.normalized()

        assertEquals(Protocol.DEFAULT_PORT, once.listenPort)
        assertEquals(
            once.listenPort,
            twice.listenPort,
            "反复 normalized 不该产生新的变化，否则每次读配置都在改写端口",
        )
    }

    @Test
    fun `新旧默认端口必须不同`() {
        assertTrue(
            Protocol.LEGACY_DEFAULT_PORT != Protocol.DEFAULT_PORT,
            "两者相等的话迁移逻辑会退化成恒等变换，等于没写 —— 这条断言就是防这个",
        )
    }

    @Test
    fun `frpc 配置里的本地端口与代理名跟着监听端口走`() {
        val toml = FrpcConfigWriter.toToml(AppConfig(listenPort = Protocol.DEFAULT_PORT))

        assertTrue(
            toml.contains("localPort = ${Protocol.DEFAULT_PORT}"),
            "frp 要转发的是真实监听端口，写错就白穿一层隧道：$toml",
        )
        assertTrue(
            toml.contains("""name = "pawlocker-${Protocol.DEFAULT_PORT}""""),
            "代理名带端口号，方便在 frps 仪表盘上分辨多个映射：$toml",
        )
    }
}
