package com.kira.pawlocker.core

import com.kira.pawlocker.core.crypto.DeviceProfile
import com.kira.pawlocker.core.crypto.IdentityKey
import com.kira.pawlocker.core.crypto.IdentityKeyFactory
import com.kira.pawlocker.core.crypto.PairSecret
import com.kira.pawlocker.core.crypto.PlatformCrypto
import com.kira.pawlocker.core.platform.PlatformEnv
import com.kira.pawlocker.core.platform.UserIdentity
import com.kira.pawlocker.core.protocol.ComputerPairingSession
import com.kira.pawlocker.core.protocol.PairingProtocol
import com.kira.pawlocker.core.protocol.PhonePairingSession
import com.kira.pawlocker.core.trust.TrustRecord
import java.io.File

/**
 * 测试运行环境的统一入口。
 *
 * 两个必须处理的现实约束：
 *
 * 1. **不能污染用户真实数据目录。** `PlatformEnv` 默认写到 `%APPDATA%\PawLocker`，
 *    那里放的是用户真实的身份私钥与信任列表。测试必须把它重定向到临时目录 ——
 *    `PlatformEnv.init` 早就为此留了钩子。
 * 2. **身份密钥要走真实代码路径。** 身份钥的生成涉及 DPAPI 封装、
 *    PKCS#8 容器打包、公钥从容器里还原，这些正是最容易出错的地方。
 *    用假实现（fake）会把这些统统绕过去，测试也就失去了意义。
 */
internal object TestEnv {

    /**
     * 测试用的 Windows 账户标识。
     *
     * 刻意用一个**固定的假 SID** 而不是 `currentUserIdentity()`：
     * 绑定链的测试要能构造「账户 A 的记录被拿去解锁账户 B」这种场景，
     * 用机器真实账户反而做不到。
     */
    val testUser = UserIdentity(
        sid = "S-1-5-21-1004336348-1177238915-682003330-1001",
        accountName = "kira",
        displayName = "Kira",
    )

    /** 另一台机器上的另一个账户，用来验证绑定链的拒绝路径。 */
    val otherUser = UserIdentity(
        sid = "S-1-5-21-9999999999-8888888888-7777777777-1002",
        accountName = "someone-else",
        displayName = "另一个账户",
    )

    /**
     * 测试数据根目录。
     *
     * **刻意不用 `by lazy`。**
     *
     * 这里踩过一次坑：用 `by lazy` 时，只有真正访问 `root` 的那个调用才会触发
     * `PlatformEnv.init` 重定向；而 `identity()` 走的是 `IdentityKeyFactory` →
     * `PlatformEnv.readSecure`，**不会**经过 `root`。
     * 结果就是「第一个跑到的身份密钥测试」会把私钥写进用户真实的
     * `%APPDATA%\PawLocker\secure`，而后续测试再把数据目录切到临时目录时，
     * 前面那把密钥已经找不回来了（表现为「文件不存在」）。
     *
     * 改成对象初始化时执行：只要有人碰到 `TestEnv` 的任何一个成员，
     * 类加载就必然先完成重定向，之后才可能发生任何落盘。
     */
    private val root: File = run {
        val dir = File(
            System.getProperty("java.io.tmpdir"),
            "pawlocker-test-${ProcessHandle.current().pid()}-${System.nanoTime()}",
        )
        check(dir.mkdirs() || dir.isDirectory) { "无法创建测试临时目录：$dir" }
        // 必须在任何 readSecure / writeSecure 之前完成重定向
        PlatformEnv.init(dir.absolutePath)
        dir
    }

    val dataDir: File get() = root

    /** 与 `PlatformEnv` 内部的落盘路径保持一致。 */
    fun secureFile(name: String): File = File(File(root, "secure").apply { mkdirs() }, name)

    /** 取一把测试用身份密钥。别名带前缀，避免和真实别名空间混淆。 */
    fun identity(alias: String): IdentityKey = IdentityKeyFactory.loadOrCreate("test-$alias")

    fun uniqueName(prefix: String): String = "$prefix-${System.nanoTime()}.json"

    /**
     * 跑一次完整的配对，返回一对已互信的设备。
     * 解锁协议的所有测试都从这里起步 —— 手搓共享密钥没有意义，
     * 那等于绕开配对协议去测解锁协议。
     */
    fun pairing(tag: String): Pairing {
        val computerKey = identity("pc-$tag")
        val phoneKey = identity("ph-$tag")
        val pairingId = PairingProtocol.newPairingId()
        val code = PairingProtocol.randomCode()
        val now = 1_700_000_000_000L

        val computer = ComputerPairingSession(
            pairingId = pairingId,
            code = code,
            computerKey = computerKey,
            computerProfile = DeviceProfile("测试主机", "Test Desktop", "Windows"),
            windowsUser = testUser,
            createdAt = now,
        )
        val phone = PhonePairingSession(
            pairingId = pairingId,
            code = code,
            computerPublicKey = computerKey.publicKey,
            computerDisplayName = "测试主机",
            windowsUserSid = testUser.bindingKey,
            windowsUserName = testUser.displayName,
            phoneKey = phoneKey,
            phoneProfile = DeviceProfile("测试手机", "Test Phone", "Android"),
            startedAt = now,
        )

        val request = phone.buildRequest(now)
        val payload = computer.decryptRequest(request, now)
        val response = computer.buildResponse(
            request = request,
            payload = payload,
            accepted = true,
            endpoints = emptyList(),
            now = now,
        )
        val phoneRecord = phone.acceptResponse(response, now)
        val computerRecord = computer.complete(payload, now)

        check(phoneRecord.secret == computerRecord.secret) {
            "配对自检失败：两端派生出了不同的长期密钥"
        }

        return Pairing(
            phoneKey = phoneKey,
            computerKey = computerKey,
            phoneRecord = phoneRecord,
            computerRecord = computerRecord,
            secret = computerRecord.resolveSecret(),
        )
    }
}

internal data class Pairing(
    val phoneKey: IdentityKey,
    val computerKey: IdentityKey,
    /** Windows 侧保存的记录（对端是手机） */
    val computerRecord: TrustRecord,
    /** 手机侧保存的记录（对端是电脑） */
    val phoneRecord: TrustRecord,
    val secret: PairSecret,
) {
    val phoneDeviceId: String get() = computerRecord.deviceId
    val computerDeviceId: String get() = phoneRecord.deviceId
    val phonePublicKey: ByteArray get() = phoneKey.publicKey

    /**
     * 这次配对绑定的 Windows 账户 —— 三元绑定链的中间一环。
     *
     * 手机侧发解锁指令时要声明它（`targetUserSid`），
     * 电脑侧要用本机真实账户去比对（`expectedWindowsUserSid`）。
     * 两端都从同一条记录取，所以这里统一暴露。
     */
    val windowsUserSid: String get() = computerRecord.windowsUserSid

    /** 换一条「绑到另一个账户」的记录，用来验证绑定链的拒绝路径。 */
    fun rebindTo(sid: String): TrustRecord = computerRecord.copy(windowsUserSid = sid)
}

/** 造一条结构合法、可直接落库的信任记录。 */
internal fun sampleRecord(
    deviceId: String,
    displayName: String = "设备 $deviceId",
    role: com.kira.pawlocker.core.trust.PeerRole = com.kira.pawlocker.core.trust.PeerRole.PHONE,
    windowsUserSid: String = TestEnv.testUser.bindingKey,
): TrustRecord = TrustRecord(
    deviceId = deviceId,
    role = role,
    displayName = displayName,
    model = "Model",
    platform = "Android",
    publicKey = com.kira.pawlocker.core.crypto.Base64Url.encode(
        ByteArray(65) { (it + 1).toByte() }.also { it[0] = 0x04 },
    ),
    secret = PairSecret(
        PlatformCrypto.randomBytes(32),
        PlatformCrypto.randomBytes(32),
    ).encode(),
    pairedAt = 1_700_000_000_000L,
    windowsUserSid = windowsUserSid,
)
