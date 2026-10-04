package com.kira.pawlocker.core.platform

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * 「本机地址能不能下发给手机」的判定。
 *
 * 这里的每一条都对应一个**本机自测发现不了**的场景：
 * 电脑上 `connect(自己下发的地址)` 会成功，手机侧却完全够不着。
 * 判定错了不会有任何错误提示，只有「手机试到死地址、卡到超时才换下一个」，
 * 用户看到的就是「扫码之后没反应」。
 */
class LanAddressPolicyTest {

    private fun advertisable(
        address: String,
        nicName: String = "eth0",
        displayName: String = "以太网",
        isVirtual: Boolean = false,
    ): Boolean = LanAddressPolicy.isAdvertisable(
        networkInterfaceName = nicName,
        displayName = displayName,
        isVirtual = isVirtual,
        hostAddress = address,
    )

    // ——————————————————————————————————————————————————————————
    // 常规内网地址：必须保留
    // ——————————————————————————————————————————————————————————

    @Test
    fun `常规内网地址要下发`() {
        assertTrue(advertisable("192.168.31.253"))
        assertTrue(advertisable("10.0.0.5"))
        assertTrue(advertisable("172.16.4.9"))
        assertTrue(advertisable("172.31.255.254"))
    }

    /**
     * 172.32 已经出了 RFC 1918 的 172.16/12 范围，
     * 但它仍然是个合法的公网单播地址 —— 不该当成本地地址拦下来，
     * 排序时排最后即可。
     */
    @Test
    fun `172_16到31之外仍可下发但排序靠后`() {
        assertTrue(advertisable("172.32.0.1"))
        assertTrue(LanAddressPolicy.advertisabilityRank("172.32.0.1") > 2)
    }

    // ——————————————————————————————————————————————————————————
    // Clash / Mihomo TUN：本次问题的直接来源
    // ——————————————————————————————————————————————————————————

    /**
     * 198.18.0.0/15 是 RFC 2544 的基准测试保留段，Clash / Mihomo 的 TUN
     * 默认就占这一段。本机 `connect(198.18.0.1)` 会返回成功（TUN 接口自己应答），
     * 所以**在开发机上无论怎么自测都发现不了它有问题** ——
     * 而手机侧根本没有这个网段，连过去只会一直等到超时。
     *
     * 这一条是整个类存在的主要理由，不要删。
     */
    @Test
    fun `Clash TUN 的基准测试网段不能下发`() {
        assertFalse(advertisable("198.18.0.1", nicName="FlClash", displayName="FlClash"))
        assertFalse(advertisable("198.19.255.254", nicName="FlClash", displayName="FlClash"))
        // 边界：198.17 和 198.20 已经在 /15 之外，属于正常地址
        assertTrue(advertisable("198.17.0.1"))
        assertTrue(advertisable("198.20.0.1"))
    }

    // ——————————————————————————————————————————————————————————
    // 其它明确该挡掉的
    // ——————————————————————————————————————————————————————————

    /** 100.64/10 是 CGNAT 段，Tailscale 用它。那属于「虚拟组网」通道，
     *  应该由用户在 overlay 配置里显式下发，不该混进局域网候选。 */
    @Test
    fun `运营商级NAT段不能下发`() {
        assertFalse(advertisable("100.64.0.1", nicName="Tailscale", displayName="Tailscale"))
        assertFalse(advertisable("100.127.255.254"))
        // 边界：100.63 与 100.128 在 /10 之外
        assertTrue(advertisable("100.63.0.1"))
        assertTrue(advertisable("100.128.0.1"))
    }

    @Test
    fun `标记为虚拟的网卡一律不下发`() {
        assertFalse(advertisable("192.168.1.10", isVirtual = true))
    }

    @Test
    fun `网卡名带虚拟网卡特征的不下发`() {
        assertFalse(advertisable("192.168.1.10", nicName = "tun0"))
        assertFalse(advertisable("192.168.1.10", nicName = "eth0", displayName = "Clash TUN"))
        assertFalse(advertisable("192.168.1.10", nicName = "wintun"))
        assertFalse(advertisable("192.168.1.10", nicName = "tap0"))
        assertFalse(advertisable("192.168.1.10", displayName = "WireGuard VPN"))
    }

    /** 名字里恰好含 "tun" 的真实网卡会被误伤，但这条取舍是刻意的：
     *  漏放一个虚拟网卡 = 用户卡到超时且无从排查；误挡一个真实网卡 =
     *  用户还能在设置页手工指定 `preferredLanHost`。 */
    @Test
    fun `大小写不敏感`() {
        assertFalse(advertisable("192.168.1.10", displayName = "CLASH"))
        assertFalse(advertisable("192.168.1.10", displayName = "Wintun Userspace Tunnel"))
    }

    @Test
    fun `回环链路本地组播都不下发`() {
        assertFalse(advertisable("127.0.0.1"))
        assertFalse(advertisable("169.254.11.22"))
        assertFalse(advertisable("224.0.0.1"))
        assertFalse(advertisable("0.0.0.0"))
        assertFalse(advertisable("255.255.255.255"))
    }

    @Test
    fun `非 IPv4 与畸形输入不下发`() {
        assertFalse(advertisable("fe80::1"))
        assertFalse(advertisable(""))
        assertFalse(advertisable("192.168.1"))
        assertFalse(advertisable("192.168.1.999"))
        assertFalse(advertisable("abc.def.ghi.jkl"))
    }

    @Test
    fun `带网卡后缀的地址同样按网段判定`() {
        // 部分平台上 hostAddress 会带 %eth0 之类的作用域后缀
        assertFalse(advertisable("198.18.0.1%eth0"))
        assertTrue(advertisable("192.168.1.10%eth0"))
    }

    // ——————————————————————————————————————————————————————————
    // 排序
    // ——————————————————————————————————————————————————————————

    @Test
    fun `常规内网段排在其它地址之前`() {
        assertTrue(
            LanAddressPolicy.advertisabilityRank("192.168.1.1") <
                LanAddressPolicy.advertisabilityRank("172.20.0.1"),
        )
        assertTrue(
            LanAddressPolicy.advertisabilityRank("172.20.0.1") <
                LanAddressPolicy.advertisabilityRank("8.8.8.8"),
        )
        assertTrue(
            LanAddressPolicy.advertisabilityRank("10.0.0.1") <
                LanAddressPolicy.advertisabilityRank("8.8.8.8"),
        )
    }
}
