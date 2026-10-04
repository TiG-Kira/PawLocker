package com.kira.pawlocker.core.platform

/**
 * 「本机地址里哪些可以下发给手机」的判定规则。
 *
 * 这条规则看起来琐碎，但它是**扫码配对卡住**这类问题的直接来源：
 * 电脑把一堆自己觉得能连、手机却完全够不着的地址塞进候选列表，
 * 手机逐个尝试，试到死地址就得等到 TCP 超时。两端都不会报错，
 * 用户看到的就是「扫完没反应」。
 *
 * 所以判定逻辑单独抽出来，不藏在 `NetworkInterface` 的遍历里 ——
 * 那样既没法测，也没法说清到底挡掉了什么。
 *
 * ### 挡谁、留谁
 *
 * **挡掉**：
 *  - `198.18.0.0/15` —— RFC 2544 基准测试保留段。Clash / Mihomo 的 TUN 模式
 *    默认就占这一段（本机实测就是 `198.18.0.1`）。它在本机 `connect()` 会成功
 *    （TUN 接口自己应答），所以**本机自测永远发现不了这个问题**，
 *    而手机侧根本没有这个网段。
 *  - `100.64.0.0/10` —— RFC 6598 运营商级 NAT 段。Tailscale 用它做节点地址，
 *    但那属于「虚拟组网」通道，应该由用户显式填到 overlay 配置里下发，
 *    不该在局域网候选里滥竽充数。
 *  - 本机回环、链路本地（169.254.x.x）—— 前者手机够不着，
 *    后者说明 DHCP 没拿到地址，连的也是死地址。
 *  - 名字里带 tun / tap / wintun / clash / vpn / virtual 的虚拟网卡 ——
 *    兜底用。网卡命名没有标准，光靠名字不可靠，所以只作为最后一道闸。
 *
 * **保留**：
 *  - `192.168.x.x`、`10.x.x.x`、`172.16–31.x.x` —— 常规内网段。
 *  - Tailscale / ZeroTier 交给 overlay 通道处理，不在这里拦。
 */
object LanAddressPolicy {

    /** 明确不该作为「局域网直连」下发的网段。 */
    private val BLOCKED_CIDRS: List<String> = listOf(
        "198.18.0.0/15", // RFC 2544 基准测试 —— Clash/Mihomo TUN 默认占用
        "100.64.0.0/10", // RFC 6598 运营商级 NAT —— Tailscale 节点地址
    )

    /** 虚拟网卡名字里常见的片段，全部小写匹配。 */
    private val VIRTUAL_NAME_HINTS: List<String> = listOf(
        "tun", "tap", "wintun", "clash", "mihomo", "vpn",
    )

    /**
     * 这个地址能不能下发给手机。
     *
     * @param networkInterfaceName `NetworkInterface.name`，Windows 上是 `eth0` 这类
     * @param displayName `NetworkInterface.displayName`，Windows 上是用户可见的网卡名
     * @param isVirtual `NetworkInterface.isVirtual`
     * @param hostAddress 点分十进制 IPv4
     */
    fun isAdvertisable(
        networkInterfaceName: String,
        displayName: String,
        isVirtual: Boolean,
        hostAddress: String,
    ): Boolean {
        if (isVirtual) return false
        if (!isUsableUnicastV4(hostAddress)) return false
        if (BLOCKED_CIDRS.any { matchesCidr(hostAddress, it) }) return false

        val haystack = (networkInterfaceName + " " + displayName).lowercase()
        if (VIRTUAL_NAME_HINTS.any { haystack.contains(it) }) return false

        return true
    }

    /**
     * 下发顺序的排序键，越小越靠前。
     *
     * 常规私网段优先 —— 手机连它们的成功率最高；
     * 其余（比如公网直连的 IPv4）排在后面做兜底。
     */
    fun advertisabilityRank(hostAddress: String): Int = when {
        matchesCidr(hostAddress, "192.168.0.0/16") -> 0
        matchesCidr(hostAddress, "10.0.0.0/8") -> 1
        matchesCidr(hostAddress, "172.16.0.0/12") -> 2
        else -> 3
    }

    /** 只接受可路由的单播 IPv4 —— 回环、链路本地、组播、0.0.0.0 都排除。 */
    private fun isUsableUnicastV4(address: String): Boolean {
        val octets = parseOctets(address) ?: return false
        val (a, b) = octets
        return when {
            a == 0 -> false                     // 0.0.0.0/8「本网络」
            a == 127 -> false                   // 回环
            a == 169 && b == 254 -> false        // APIPA 链路本地
            a >= 224 -> false                   // 组播与保留
            a == 255 -> false
            else -> true
        }
    }

    private fun parseOctets(address: String): Pair<Int, Int>? {
        val clean = address.substringBefore('%').trim()
        val parts = clean.split('.')
        if (parts.size != 4) return null
        val nums = parts.map { it.toIntOrNull() ?: return null }
        if (nums.any { it !in 0..255 }) return null
        return nums[0] to nums[1]
    }

    /** 极简 CIDR 匹配：只支持 IPv4 与 0–32 的前缀长度。 */
    private fun matchesCidr(address: String, cidr: String): Boolean {
        val (networkText, prefixText) = cidr.split('/').let {
            if (it.size != 2) return false
            it[0] to it[1]
        }
        val prefix = prefixText.toIntOrNull() ?: return false
        if (prefix !in 0..32) return false

        val addressValue = toUInt(address) ?: return false
        val networkValue = toUInt(networkText) ?: return false
        if (prefix == 0) return true

        val mask = (0xFFFFFFFFu shl (32 - prefix)) and 0xFFFFFFFFu
        return (addressValue and mask) == (networkValue and mask)
    }

    private fun toUInt(address: String): UInt? {
        val parts = address.substringBefore('%').trim().split('.')
        if (parts.size != 4) return null
        var value = 0u
        for (part in parts) {
            val octet = part.toIntOrNull() ?: return null
            if (octet !in 0..255) return null
            value = (value shl 8) or octet.toUInt()
        }
        return value
    }
}
