package com.kira.pawlocker.core.platform

import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * 「本机 Windows 账户」这一环。
 *
 * ## 为什么这些测试值钱
 *
 * 三元绑定链（设备 + Windows 账户 + 手机）里，账户是用一串文本标识参与比较与派生的。
 * 这串文本只有一个来源：`whoami /user` 的输出。它的**外壳措辞跟系统语言走**，
 * 但 SID 文本本身与语言无关 —— 所以解析只抓 SID，其余一律不解析。
 *
 * 代价是：解析器必须在各种边角形态下都稳。它一旦返回空串，绑定链会**退化成按账户名匹配**；
 * 一旦抓错，会变成「账户 A 的指令开了账户 B」。两种都比解析失败更糟。
 */
class UserIdentityTest {

    // ——————————————————————————————————————————————————————————
    // SID 解析
    // ——————————————————————————————————————————————————————————

    @Test
    fun `从真实的 whoami 输出里取出 SID`() {
        // `whoami /user /fo csv /nh` 的原样输出（含 CRLF 与引号）
        val output = "\"desktop-9f3k\\kira\",\"S-1-5-21-1004336348-1177238915-682003330-1001\"\r\n"

        assertEquals(
            "S-1-5-21-1004336348-1177238915-682003330-1001",
            extractSidFrom(output),
        )
    }

    @Test
    fun `输出前面有空白行也能解析`() {
        // 某些环境下 whoami 会先吐一个空行，再去掉引号
        val output = "\r\n\r\ndesktop-9f3k\\kira,S-1-5-21-1-2-3-1001\r\n"

        assertEquals("S-1-5-21-1-2-3-1001", extractSidFrom(output))
    }

    @Test
    fun `域账户的 SID 同样能解析`() {
        val output = "CORP\\kira,S-1-5-21-857738222-1974771478-3367111472-1105"

        assertEquals("S-1-5-21-857738222-1974771478-3367111472-1105", extractSidFrom(output))
    }

    @Test
    fun `解析结果与外围措辞完全无关`() {
        // 这正是「只抓 SID」的价值：外壳换成别的语言、别的列顺序都不影响
        val sid = "S-1-5-21-9-9-9-1002"

        assertEquals(sid, extractSidFrom("用户名         SID\n==================\nkira  $sid"))
        assertEquals(sid, extractSidFrom("Benutzername,SID\r\nkira,$sid"))
        assertEquals(sid, extractSidFrom("[$sid]"))
    }

    @Test
    fun `输出里没有 SID 时返回空串而不是乱猜`() {
        // 返回空串是「有意义的失败」：调用方据此知道绑定链要退化为按账户名匹配
        assertEquals("", extractSidFrom(""))
        assertEquals("", extractSidFrom("ERROR: 找不到用户名。"))
        assertEquals("", extractSidFrom("\"desktop\\kira\",\"???\""))
    }

    @Test
    fun `过短的 SID 形态不会被误认成用户 SID`() {
        // `S-1-5-18`（LOCAL SYSTEM）、`S-1-5-32-544`（内置管理员）这类众所周知的 SID
        // 永远不是「某个登录账户」。正则要求 `S-1-5` 之后至少还有两段数字，
        // 于是这两个都不会被当成账户标识 —— 宁可返回空串，也不要绑到一个公共身份上。
        assertEquals("", extractSidFrom("S-1-5-18"))
        assertEquals("", extractSidFrom("S-1-5-19"))
    }

    @Test
    fun `同时出现多个 SID 时取第一个`() {
        // 当前账户的 SID 在 whoami 输出里总是第一个
        assertEquals(
            "S-1-5-21-1-2-3-1001",
            extractSidFrom("kira,S-1-5-21-1-2-3-1001\r\nAdministrators,S-1-5-21-1-2-3-512\r\n"),
        )
    }

    // ——————————————————————————————————————————————————————————
    // bindingKey —— 参与比较与 HKDF 派生的稳定键
    // ——————————————————————————————————————————————————————————

    @Test
    fun `解析成功时用 SID 作为绑定键`() {
        val user = UserIdentity(
            sid = "S-1-5-21-1-2-3-1001",
            accountName = "kira",
            displayName = "Kira",
        )

        assertTrue(user.isResolved)
        assertEquals("S-1-5-21-1-2-3-1001", user.bindingKey)
    }

    @Test
    fun `解析失败时退化为带前缀的账户名`() {
        val user = UserIdentity(sid = "", accountName = "kira", displayName = "Kira")

        assertFalse(user.isResolved)
        assertEquals("name:kira", user.bindingKey)
    }

    @Test
    fun `退化形态永远不会和 SID 形态撞车`() {
        // 前缀 `name:` 的存在意义就是这个：SID 文本以 `S-1-` 开头，
        // 两种形态的取值空间天然不相交。少了前缀，
        // 「账户名恰好长得像 SID」或「两边都取不到」都可能让比较意外通过。
        val byName = UserIdentity(sid = "", accountName = "S-1-5-21-1-2-3-1001")
        val bySid = UserIdentity(sid = "S-1-5-21-1-2-3-1001", accountName = "kira")

        assertNotEquals(byName.bindingKey, bySid.bindingKey)

        // 两个都取不到时，绑定键是 `name:`（非空）——
        // 于是「两边都空」不会因为相等而被放行，只会因为空账户名而无意义地相等，
        // 真正拦住它的是「空账户名根本解析不出账户」这件事本身
        assertEquals("name:", UserIdentity.Unknown.bindingKey)
        assertTrue(UserIdentity.Unknown.bindingKey.isNotBlank())
    }

    @Test
    fun `未识别账户不会与任何真实账户相等`() {
        val real = UserIdentity(sid = "S-1-5-21-1-2-3-1001", accountName = "kira")

        assertNotEquals(UserIdentity.Unknown.bindingKey, real.bindingKey)
        assertFalse(UserIdentity.Unknown.isResolved)

        // 退化匹配不等于「一律放行」：两个账户名不同的未解析账户仍然可区分
        assertNotEquals(
            UserIdentity(sid = "", accountName = "kira").bindingKey,
            UserIdentity(sid = "", accountName = "guest").bindingKey,
        )

        // 连账户名都取不到时绑定键固定为 `name:`。它既不等于任何真实 SID，
        // 也不等于 `name:kira` —— 于是一条「账户不明」的记录碰不上任何正常账户，
        // 结果只会是拒绝，而不是误开。
        assertEquals("name:", UserIdentity.Unknown.bindingKey)
        assertNotEquals(
            UserIdentity.Unknown.bindingKey,
            UserIdentity(sid = "", accountName = "kira").bindingKey,
        )
    }

    @Test
    fun `同一账户换了显示名不影响绑定键`() {
        // 显示名是给人看的，可能随「全名」字段变化；SID 才是身份
        val before = UserIdentity(sid = "S-1-5-21-1-2-3-1001", accountName = "kira", displayName = "Kira")
        val after = before.copy(displayName = "极犽 Kira")

        assertEquals(before.bindingKey, after.bindingKey)
        assertNotEquals(before.description, after.description)
    }

    @Test
    fun `显示串在各字段缺失时都能给出一句话`() {
        assertEquals(
            "Kira（S-1-5-21-1-2-3-1001）",
            UserIdentity("S-1-5-21-1-2-3-1001", "kira", "Kira").description,
        )
        assertEquals("Kira", UserIdentity("", "kira", "Kira").description)
        assertEquals("S-1-5-21-1-2-3-1001", UserIdentity("S-1-5-21-1-2-3-1001", "", "").description)
        assertEquals("kira", UserIdentity("", "kira", "").description)
        assertEquals("未识别的账户", UserIdentity.Unknown.description)
    }

    // ——————————————————————————————————————————————————————————
    // 序列化
    // ——————————————————————————————————————————————————————————

    @Test
    fun `账户身份可以序列化往返`() {
        // 它会跟着信任记录一起落盘，字段丢一个就意味着绑定链少一环
        val user = UserIdentity("S-1-5-21-1-2-3-1001", "kira", "Kira")
        val text = Json.encodeToString(UserIdentity.serializer(), user)

        assertEquals(user, Json.decodeFromString(UserIdentity.serializer(), text))
    }

    @Test
    fun `未识别账户序列化后仍是未识别`() {
        val text = Json.encodeToString(UserIdentity.serializer(), UserIdentity.Unknown)
        val restored = Json.decodeFromString(UserIdentity.serializer(), text)

        assertFalse(restored.isResolved)
        assertEquals("name:", restored.bindingKey)
    }
}
