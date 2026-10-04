package com.kira.pawlocker.core.protocol

import com.kira.pawlocker.core.Pairing
import com.kira.pawlocker.core.TestEnv
import com.kira.pawlocker.core.crypto.Aead
import com.kira.pawlocker.core.crypto.Base64Url
import com.kira.pawlocker.core.crypto.DeviceIds
import com.kira.pawlocker.core.crypto.DeviceProfile
import com.kira.pawlocker.core.crypto.IdentityKey
import com.kira.pawlocker.core.crypto.PairSecret
import com.kira.pawlocker.core.crypto.PlatformCrypto
import com.kira.pawlocker.core.crypto.Sas
import com.kira.pawlocker.core.flipLastBase64Byte
import com.kira.pawlocker.core.trust.PeerRole
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * 配对协议的完整握手，以及全部已知攻击路径的负向验证。
 *
 * ## 这个测试在证明什么
 *
 * 配对是整个系统的信任建立点。一旦它被攻破，后面所有加密都是给攻击者送信的邮筒。
 * 所以这里不只测「正常流程能跑通」，更要逐条证明**已知的几类攻击都不成立**：
 *
 * | 攻击 | 防线 |
 * |---|---|
 * | 不知道配对码，猜 | K_code 保护的 confirmTag |
 * | 知道配对码，但替换公钥（中间人） | 双方公钥都绑进 HMAC；SAS 兜底 |
 * | 长期窃听后事后解密 | 会话密钥来自 ECDH，不由配对码派生 |
 * | 重放已完成的配对 | consumed 一次性标志 |
 * | 用 A 会话的密文冒充 B 会话 | pairingId 进 AAD |
 * | 自报设备 ID 冒充别人 | deviceId 必须等于公钥的哈希 |
 */
class PairingHandshakeTest {

    private val now = 1_700_000_000_000L
    private val endpoints = listOf(
        Endpoint(TransportKind.LAN, "192.168.1.10"),
        Endpoint(TransportKind.TUNNEL, "tunnel.example.com", 18989),
    )

    private val computerProfile = DeviceProfile("书房主机", "Test Desktop", "Windows")
    private val phoneProfile = DeviceProfile("Kira 的手机", "Pixel 9", "Android")

    /**
     * 装配一对会话。
     *
     * 把两把身份密钥一并带出来：会话对象刻意不暴露私钥（生产代码不该有这个出口），
     * 而负向测试需要「对方公钥」来手工构造报文，所以从装配点取。
     */
    private data class Sessions(
        val computer: ComputerPairingSession,
        val phone: PhonePairingSession,
        val code: String,
        val computerKey: IdentityKey,
        val phoneKey: IdentityKey,
    )

    private fun session(
        code: String = PairingProtocol.randomCode(),
        pairingId: String = PairingProtocol.newPairingId(),
    ): Sessions {
        val computerKey = TestEnv.identity("hs-pc-$pairingId")
        val phoneKey = TestEnv.identity("hs-ph-$pairingId")
        val computer = ComputerPairingSession(pairingId, code, computerKey, computerProfile, windowsUser = TestEnv.testUser, createdAt = now)
        val phone = PhonePairingSession(
            pairingId = pairingId,
            code = code,
            computerPublicKey = computerKey.publicKey,
            computerDisplayName = computerProfile.displayName,
            windowsUserSid = TestEnv.testUser.bindingKey,
            windowsUserName = TestEnv.testUser.displayName,
            phoneKey = phoneKey,
            phoneProfile = phoneProfile,
            startedAt = now,
        )
        return Sessions(computer, phone, code, computerKey, phoneKey)
    }

    // ——————————————————————————————————————————————————————————
    // 正向：正常路径
    // ——————————————————————————————————————————————————————————

    @Test
    fun `完整配对两端派生出同一份长期密钥`() {
        val (computer, phone, _) = session()

        val request = phone.buildRequest(now)
        val payload = computer.decryptRequest(request, now)
        val response = computer.buildResponse(request, payload, accepted = true, endpoints = endpoints, now = now)

        val phoneRecord = phone.acceptResponse(response, now)
        assertFalse(computer.consumed, "用户点「允许」之前不应消费配对会话")

        val computerRecord = computer.complete(payload, now)
        assertTrue(computer.consumed, "complete 之后会话必须被标记为已消费")

        // 核心断言：ECDH 是对称的，两端必须算出同一份密钥
        assertEquals(computerRecord.secret, phoneRecord.secret)

        val computerSecret = computerRecord.resolveSecret()
        val phoneSecret = phoneRecord.resolveSecret()
        assertContentEquals(computerSecret.encKey, phoneSecret.encKey)
        assertContentEquals(computerSecret.macKey, phoneSecret.macKey)
        assertEquals(computerSecret.sas, phoneSecret.sas, "SAS 必须一致，否则用户会误判为中间人")
        assertEquals(4, phoneSecret.sas.size)
    }

    @Test
    fun `配对记录的角色与身份字段正确`() {
        val pairing = TestEnv.pairing("roles")

        assertEquals(PeerRole.COMPUTER, pairing.phoneRecord.role)
        assertEquals(PeerRole.PHONE, pairing.computerRecord.role)

        assertEquals(DeviceIds.fromPublicKey(pairing.computerKey.publicKey), pairing.phoneRecord.deviceId)
        assertEquals(DeviceIds.fromPublicKey(pairing.phoneKey.publicKey), pairing.computerRecord.deviceId)

        // 名称取自 TestEnv.pairing 里装配的 DeviceProfile
        assertEquals("Windows", pairing.phoneRecord.platform)
        assertEquals("Android", pairing.computerRecord.platform)
        assertEquals("测试主机", pairing.phoneRecord.displayName)
        assertEquals("测试手机", pairing.computerRecord.displayName)
        assertEquals(0, pairing.computerRecord.lastCounter, "新记录的计数器基线从 0 开始")
        assertEquals(pairing.computerRecord.pairedAt, pairing.computerRecord.lastSeenAt)
    }

    @Test
    fun `可达地址在配对响应里下发给手机`() {
        val (computer, phone, _) = session()
        val request = phone.buildRequest(now)
        val payload = computer.decryptRequest(request, now)
        val response = computer.buildResponse(request, payload, accepted = true, endpoints = endpoints, now = now)

        val record = phone.acceptResponse(response, now)
        assertEquals(endpoints, record.endpoints, "手机配对后立刻拿到全部地址，无需再问一次")
        assertEquals(TransportKind.LAN, record.endpoints.sortedWith(Endpoint.preferredOrder).first().kind)
    }

    @Test
    fun `配对邀请的字段与两份记录一致`() {
        val (computer, phone, code) = session()
        val offer = computer.offer(endpoints)

        assertEquals(code, offer.code)
        assertEquals(computerProfile.displayName, offer.computerDisplayName)
        assertEquals(DeviceIds.fromPublicKey(phone.computerPublicKey), offer.computerDeviceId)
        assertEquals(endpoints, offer.endpoints)
        assertEquals(now + Protocol.PAIRING_TTL_MILLIS, offer.expiresAt)
        assertEquals(offer.expiresAt, computer.expiresAt())
        assertFalse(computer.isExpired(now))
        assertTrue(computer.isExpired(now + Protocol.PAIRING_TTL_MILLIS + 1))
    }

    @Test
    fun `通过深链还原的邀请可以完成配对`() {
        // 这条覆盖真实的扫码路径：二维码里就是 toDeepLink() 的输出
        val computerKey = TestEnv.identity("deeplink-pc")
        val phoneKey = TestEnv.identity("deeplink-ph")
        val pairingId = PairingProtocol.newPairingId()
        val code = PairingProtocol.randomCode()

        val computer = ComputerPairingSession(pairingId, code, computerKey, computerProfile, windowsUser = TestEnv.testUser, createdAt = now)
        val restored = PairingOffer.fromDeepLink(computer.offer(endpoints).toDeepLink())
            ?: error("深链还原失败")

        assertEquals(computer.offer(endpoints), restored)

        val phone = PhonePairingSession(
            pairingId = restored.pairingId,
            code = restored.code,
            computerPublicKey = Base64Url.decode(restored.computerPublicKey),
            computerDisplayName = restored.computerDisplayName,
            windowsUserSid = restored.windowsUserSid,
            windowsUserName = restored.windowsUserName,
            phoneKey = phoneKey,
            phoneProfile = phoneProfile,
            startedAt = now,
        )
        val request = phone.buildRequest(now)
        val payload = computer.decryptRequest(request, now)
        val response = computer.buildResponse(request, payload, true, restored.endpoints, now)
        val record = phone.acceptResponse(response, now)

        assertEquals(restored.computerDeviceId, record.deviceId)
        assertEquals(endpoints, record.endpoints)
    }

    @Test
    fun `SAS 由配对密钥确定性派生`() {
        val pairing = TestEnv.pairing("sas-determinism")

        // Sas.fromKey 是纯函数：同一份 encKey 必然得到同一组 emoji
        assertEquals(Sas.fromKey(pairing.secret.encKey), pairing.secret.sas)
        // 落库再读出来，两端仍要得到同一组
        assertEquals(pairing.secret.sas, pairing.computerRecord.resolveSecret().sas)
        assertEquals(pairing.secret.sas, pairing.phoneRecord.resolveSecret().sas)
        assertEquals(4, pairing.secret.sas.size)
        assertTrue(pairing.secret.sas.all { it.isNotBlank() })

        // 换一次配对就是全新的 ECDH 秘密，SAS 必须不同
        assertNotEquals(pairing.secret.sas, TestEnv.pairing("sas-determinism-other").secret.sas)
    }

    @Test
    fun `每次配对产生互不相同的长期密钥`() {
        val secrets = (0 until 4).map { TestEnv.pairing("fresh-$it").secret.encode() }.toSet()
        assertEquals(4, secrets.size, "不同配对应产生不同密钥")
    }

    // ——————————————————————————————————————————————————————————
    // 负向：攻击路径
    // ——————————————————————————————————————————————————————————

    @Test
    fun `配对码错误时电脑端拒绝解密`() {
        val (computer, phone, code) = session()
        val request = phone.buildRequest(now)
        // 用户手输错了配对码 —— 用另一个码重建会话才能走到这一步
        val wrong = if (code == "000000") "111111" else "000000"
        val forged = PhonePairingSession(
            pairingId = request.pairingId,
            code = wrong,
            computerPublicKey = phone.computerPublicKey,
            computerDisplayName = "x",
            windowsUserSid = TestEnv.testUser.bindingKey,
            windowsUserName = TestEnv.testUser.displayName,
            phoneKey = TestEnv.identity("hs-ph-wrong"),
            phoneProfile = phoneProfile,
            startedAt = now,
        ).buildRequest(now)

        assertEquals(request.pairingId, forged.pairingId)
        val error = assertFailsWith<PairingException> { computer.decryptRequest(forged, now) }
        assertEquals(ErrorCodes.PAIRING_CODE_MISMATCH, error.code)
    }

    @Test
    fun `配对码过期后拒绝处理`() {
        val (computer, phone, _) = session()
        val request = phone.buildRequest(now)

        val error = assertFailsWith<PairingException> {
            computer.decryptRequest(request, now + Protocol.PAIRING_TTL_MILLIS + 1)
        }
        assertEquals(ErrorCodes.PAIRING_EXPIRED, error.code)
    }

    @Test
    fun `一个配对会话只能服务一次配对`() {
        val (computer, phone, _) = session()
        val request = phone.buildRequest(now)
        val payload = computer.decryptRequest(request, now)
        computer.complete(payload, now)

        val error = assertFailsWith<PairingException> { computer.decryptRequest(request, now) }
        assertEquals(ErrorCodes.PAIRING_CLOSED, error.code)
    }

    @Test
    fun `会话 ID 不匹配被拒绝`() {
        val (computer, phone, _) = session()
        val request = phone.buildRequest(now)

        val error = assertFailsWith<PairingException> {
            computer.decryptRequest(request.copy(pairingId = "some-other-session"), now)
        }
        assertEquals(ErrorCodes.PAIRING_CLOSED, error.code)

        // 手机端同样校验：响应里的会话 ID 必须一致
        val error2 = assertFailsWith<PairingException> {
            phone.acceptResponse(
                PairResponse(pairingId = "other", nonce = "n", ciphertext = "ct"),
                now,
            )
        }
        assertEquals(ErrorCodes.PAIRING_CLOSED, error2.code)
    }

    @Test
    fun `请求密文被改动一位就会被发现`() {
        val (computer, phone, _) = session()
        val request = phone.buildRequest(now)

        val error = assertFailsWith<PairingException> {
            computer.decryptRequest(request.copy(ciphertext = request.ciphertext.flipLastBase64Byte()), now)
        }
        assertEquals(ErrorCodes.PAIRING_CODE_MISMATCH, error.code)
    }

    @Test
    fun `响应密文被改动一位就会被发现`() {
        val (computer, phone, _) = session()
        val request = phone.buildRequest(now)
        val payload = computer.decryptRequest(request, now)
        val response = computer.buildResponse(request, payload, true, endpoints, now)

        val error = assertFailsWith<PairingException> {
            phone.acceptResponse(response.copy(ciphertext = response.ciphertext.flipLastBase64Byte()), now)
        }
        assertEquals(ErrorCodes.DECRYPT_FAILED, error.code)
    }

    @Test
    fun `把 A 会话的密文搬到 B 会话里会被拒绝`() {
        val (computerA, phoneA, code) = session()
        val requestA = phoneA.buildRequest(now)

        // 同一个配对码、不同的 pairingId：AAD 里带了 pairingId，密文搬过去必然解不开
        val computerB = ComputerPairingSession(
            pairingId = "another-pairing-id",
            code = code,
            computerKey = TestEnv.identity("hs-pc-b"),
            computerProfile = computerProfile,
            windowsUser = TestEnv.testUser,
            createdAt = now,
        )
        val error = assertFailsWith<PairingException> { computerB.decryptRequest(requestA, now) }
        assertEquals(ErrorCodes.PAIRING_CLOSED, error.code, "pairingId 不匹配应被最早拦下")
    }

    @Test
    fun `自报设备 ID 与公钥不符时被拒绝`() {
        val (computer, phone, code, computerKey, phoneKey) = session()
        val request = phone.buildRequest(now)

        // 手工构造一个「设备 ID 冒用别人」的报文：攻击者持有自己的私钥，
        // 但把 phoneDeviceId 填成受害者。confirmTag 是有效的（他知道配对码），
        // 所以只能靠「deviceId 必须等于公钥哈希」这条挡住。
        val pairingKey = PairingProtocol.derivePairingKey(code, request.pairingId)
        val nonce = PairingProtocol.newNonce()
        val victimId = DeviceIds.fromPublicKey(ByteArray(65) { 0x42 }.also { it[0] = 0x04 })

        val forgedPayload = PairRequest.Payload(
            phoneDeviceId = victimId,
            phoneDisplayName = "冒名者",
            phoneModel = "X",
            phonePublicKey = Base64Url.encode(phoneKey.publicKey),
            confirmTag = Base64Url.encode(
                PairingProtocol.confirmTag(
                    key = pairingKey,
                    label = "confirm",
                    computerPublicKey = computerKey.publicKey,
                    phonePublicKey = phoneKey.publicKey,
                    pairingId = request.pairingId,
                ),
            ),
            requestedAt = now,
        )
        val plaintext = kotlinx.serialization.json.Json
            .encodeToString(PairRequest.Payload.serializer(), forgedPayload)
            .encodeToByteArray()
        val sealed = Aead.seal(
            key = pairingKey,
            plaintext = plaintext,
            aad = PairingProtocol.aad(request.pairingId, nonce),
            nonce = Base64Url.decode(nonce),
        )
        val forged = PairRequest(request.pairingId, nonce, Base64Url.encode(sealed.ciphertext))

        val error = assertFailsWith<PairingException> { computer.decryptRequest(forged, now) }
        assertEquals(ErrorCodes.INTERNAL, error.code, "设备标识与公钥不匹配必须被拒绝")
    }

    @Test
    fun `用户拒绝配对时手机端收到明确原因`() {
        val (computer, phone, _) = session()
        val request = phone.buildRequest(now)
        val payload = computer.decryptRequest(request, now)
        val denied = computer.buildResponse(
            request = request,
            payload = payload,
            accepted = false,
            endpoints = emptyList(),
            now = now,
            message = "用户点了拒绝",
        )

        val error = assertFailsWith<PairingException> { phone.acceptResponse(denied, now) }
        assertEquals("用户点了拒绝", error.message)
        assertEquals(ErrorCodes.PAIRING_CLOSED, error.code)
        assertFalse(computer.consumed, "被拒绝的会话不应被消费，用户还能重试")
    }

    @Test
    fun `尚未发出请求就接受响应会报错`() {
        val (computer, phone, _) = session()
        val request = phone.buildRequest(now)
        val payload = computer.decryptRequest(request, now)
        val response = computer.buildResponse(request, payload, true, endpoints, now)

        val fresh = PhonePairingSession(
            pairingId = response.pairingId,
            code = "000000",
            computerPublicKey = ByteArray(65) { 1 },
            computerDisplayName = "x",
            windowsUserSid = TestEnv.testUser.bindingKey,
            windowsUserName = TestEnv.testUser.displayName,
            phoneKey = TestEnv.identity("hs-ph-fresh"),
            phoneProfile = phoneProfile,
            startedAt = now,
        )
        val error = assertFailsWith<PairingException> { fresh.acceptResponse(response, now) }
        assertEquals(ErrorCodes.INTERNAL, error.code)
    }

    /**
     * 中间人（攻击者知道配对码）无法走协议路径冒充电脑。
     *
     * 手机发出的请求里，`confirmTag` 绑定的是**它被告知的那台电脑的公钥**。
     * 攻击者虽然能算出 K_code，但算不出「真电脑公钥」对应的 tag ——
     * 因为它没有真电脑的私钥，也就无法让 tag 与自己的公钥自洽。
     */
    @Test
    fun `知道配对码的攻击者也无法在协议路径上冒充电脑`() {
        val computerKey = TestEnv.identity("impersonate-real-pc")
        val attackerKey = TestEnv.identity("impersonate-attacker")
        val phoneKey = TestEnv.identity("impersonate-phone")
        val pairingId = PairingProtocol.newPairingId()
        val code = PairingProtocol.randomCode()

        val phone = PhonePairingSession(
            pairingId = pairingId,
            code = code,
            computerPublicKey = computerKey.publicKey,
            computerDisplayName = computerProfile.displayName,
            windowsUserSid = TestEnv.testUser.bindingKey,
            windowsUserName = TestEnv.testUser.displayName,
            phoneKey = phoneKey,
            phoneProfile = phoneProfile,
            startedAt = now,
        )
        val request = phone.buildRequest(now)

        // 攻击者知道配对码与会话 ID，用自己的密钥起一个会话
        val attacker = ComputerPairingSession(
            pairingId, code, attackerKey, DeviceProfile("假主机", "Fake", "Windows"),
            windowsUser = TestEnv.testUser, createdAt = now,
        )

        val error = assertFailsWith<PairingException> { attacker.decryptRequest(request, now) }
        assertEquals(ErrorCodes.PAIRING_CODE_MISMATCH, error.code)
    }

    /**
     * 绑定链的第二环在配对阶段就要生效。
     *
     * 手机回传的 Windows 账户必须就是电脑当前账户。
     * 不匹配的典型成因是「配对窗口开着的时候有人切换了登录账户」——
     * 这时如果放过去，就会产生一条「绑定到 A 账户、但实际上属于 B 账户」的信任记录，
     * 之后所有绑定校验都会被这条脏数据带偏。
     */
    @Test
    fun `配对请求里的 Windows 账户与本机不符时被拒绝`() {
        val computerKey = TestEnv.identity("acct-pc")
        val phoneKey = TestEnv.identity("acct-ph")
        val pairingId = PairingProtocol.newPairingId()
        val code = PairingProtocol.randomCode()

        val computer = ComputerPairingSession(
            pairingId, code, computerKey, computerProfile,
            windowsUser = TestEnv.testUser, createdAt = now,
        )

        // 手机拿着「另一个账户」的邀请来配对
        val phone = PhonePairingSession(
            pairingId = pairingId,
            code = code,
            computerPublicKey = computerKey.publicKey,
            computerDisplayName = computerProfile.displayName,
            windowsUserSid = TestEnv.otherUser.bindingKey,
            windowsUserName = TestEnv.otherUser.displayName,
            phoneKey = phoneKey,
            phoneProfile = phoneProfile,
            startedAt = now,
        )

        val error = assertFailsWith<PairingException> {
            computer.decryptRequest(phone.buildRequest(now), now)
        }
        assertEquals(ErrorCodes.USER_MISMATCH, error.code)
        assertFalse(computer.consumed, "被拒绝的配对不能消耗会话")
    }

    /**
     * 同一条信任关系不能跨账户复用：给账户 A 配对产生的密钥，
     * 在账户 B 下必须派生出**不同的**结果。
     *
     * 这是绑定链里「密码学」那一半 —— 即使有人把信任记录文件里的账户字段改掉，
     * 也只是让解密失败，改不出一个「能用的错绑定」。
     */
    @Test
    fun `不同 Windows 账户派生出不同的配对密钥`() {
        val computerKey = TestEnv.identity("sid-pc")
        val phoneKey = TestEnv.identity("sid-ph")
        val pairingId = PairingProtocol.newPairingId()
        val shared = PairingProtocol.derivePairingKey("123456", pairingId)

        // 用同一份共享秘密、同一对公钥，只换账户
        val sharedSecret = phoneKey.agree(computerKey.publicKey)
        val forKira = PairSecret.derive(sharedSecret, pairingId, computerKey.publicKey, phoneKey.publicKey, TestEnv.testUser.bindingKey)
        val forOther = PairSecret.derive(sharedSecret, pairingId, computerKey.publicKey, phoneKey.publicKey, TestEnv.otherUser.bindingKey)

        assertFalse(forKira.encKey.contentEquals(forOther.encKey), "账户必须影响密钥派生")
        assertFalse(forKira.macKey.contentEquals(forOther.macKey))
        assertNotEquals(forKira.sas, forOther.sas)
        // 同一个账户重复派生必须稳定
        assertTrue(
            forKira.encKey.contentEquals(
                PairSecret.derive(sharedSecret, pairingId, computerKey.publicKey, phoneKey.publicKey, TestEnv.testUser.bindingKey).encKey,
            ),
        )
        assertTrue(shared.isNotEmpty())
    }

    /**
     * 中间人绕过协议层、手工伪造响应 —— 只有 SAS 能发现。
     *
     * 攻击者知道配对码，所以能直接用 K_code 解开手机的请求、拿到手机公钥，
     * 再手工造一份「自洽」的响应（用自己的公钥 + 与之匹配的 confirm2 tag）。
     * 手机端单看协议状态会认为配对成功。
     *
     * 唯一的破绽是 **SAS**：手机与真电脑各自派生的共享秘密不同，
     * 用户肉眼比对 4 个 emoji 就能发现。这条测试把这个事实固定下来。
     */
    @Test
    fun `手工伪造响应的中间人会被 SAS 比对发现`() {
        val computerKey = TestEnv.identity("mitm-real-pc")
        val attackerKey = TestEnv.identity("mitm-attacker")
        val phoneKey = TestEnv.identity("mitm-phone")
        val pairingId = PairingProtocol.newPairingId()
        val code = PairingProtocol.randomCode()

        val realComputer = ComputerPairingSession(pairingId, code, computerKey, computerProfile, windowsUser = TestEnv.testUser, createdAt = now)
        val phone = PhonePairingSession(
            pairingId = pairingId,
            code = code,
            computerPublicKey = computerKey.publicKey,
            computerDisplayName = computerProfile.displayName,
            windowsUserSid = TestEnv.testUser.bindingKey,
            windowsUserName = TestEnv.testUser.displayName,
            phoneKey = phoneKey,
            phoneProfile = phoneProfile,
            startedAt = now,
        )
        val request = phone.buildRequest(now)

        // 攻击者用 K_code 直接解密请求（绕开 confirmTag 校验），拿到手机公钥
        val pairingKey = PairingProtocol.derivePairingKey(code, pairingId)
        val plaintext = Aead.open(
            key = pairingKey,
            nonce = Base64Url.decode(request.nonce),
            ciphertext = Base64Url.decode(request.ciphertext),
            aad = PairingProtocol.aad(pairingId, request.nonce),
        )
        val phonePayload = kotlinx.serialization.json.Json
            .decodeFromString(PairRequest.Payload.serializer(), plaintext.decodeToString())
        assertEquals(phoneKey.publicKey.size, Base64Url.decode(phonePayload.phonePublicKey).size)

        // 用自己的公钥伪造一份完全自洽的响应。
        //
        // 账户字段直接照抄请求里的那份 —— 攻击者本来就已经解开了密文，
        // 抄一个字符串对他来说是免费的。这正是要说清的事：
        // **绑定链拦不住这种攻击**（它拦的是「配给 A 的密钥去开 B」），
        // 唯一的破绽仍然只有 SAS。
        val forgedBody = PairResponse.Payload(
            accepted = true,
            windowsDeviceId = DeviceIds.fromPublicKey(attackerKey.publicKey),
            windowsDisplayName = "假主机",
            windowsModel = "Fake",
            windowsPublicKey = Base64Url.encode(attackerKey.publicKey),
            windowsUserSid = phonePayload.windowsUserSid,
            windowsUserName = "Kira",
            serverConfirmTag = Base64Url.encode(
                PairingProtocol.confirmTag(
                    key = pairingKey,
                    label = "confirm2",
                    computerPublicKey = attackerKey.publicKey,
                    phonePublicKey = phoneKey.publicKey,
                    pairingId = pairingId,
                ),
            ),
            endpoints = endpoints,
            pairedAt = now,
        )
        val sealed = Aead.seal(
            key = pairingKey,
            plaintext = kotlinx.serialization.json.Json
                .encodeToString(PairResponse.Payload.serializer(), forgedBody)
                .encodeToByteArray(),
            aad = PairingProtocol.aad(pairingId, request.nonce),
        )
        val forgedResponse = PairResponse(
            pairingId = pairingId,
            nonce = Base64Url.encode(sealed.nonce),
            ciphertext = Base64Url.encode(sealed.ciphertext),
        )

        // 手机侧「配对成功」—— 协议层拦不住手工伪造
        val phoneRecord = phone.acceptResponse(forgedResponse, now)
        assertEquals("假主机", phoneRecord.displayName, "手机看到的是攻击者声称的名字")

        // 真正的电脑记录的是与手机的真实共享秘密
        val realRecord = realComputer.complete(phonePayload, now)

        assertNotEquals(phoneRecord.secret, realRecord.secret, "两端派生的密钥必须不同")
        assertNotEquals(
            phoneRecord.resolveSecret().sas,
            realRecord.resolveSecret().sas,
            "SAS 必须不同 —— 这是用户发现中间人的唯一途径",
        )
    }

    @Test
    fun `配对密钥不会因为 long-term 窃听而被还原`() {
        // 配对密钥由 ECDH 派生，而不是由配对码派生。
        // 因此即使攻击者完整录下了配对流量，没有任一方私钥也无法算出长期密钥。
        val (computer, phone, _, computerKey, phoneKey) = session()
        val request = phone.buildRequest(now)
        val payload = computer.decryptRequest(request, now)
        val response = computer.buildResponse(request, payload, true, endpoints, now)
        val record = phone.acceptResponse(response, now)

        // 攻击者知道：配对码、pairingId、双方公钥、绑定的 Windows 账户、全部密文
        val attackerGuess = PairSecret.derive(
            sharedSecret = PlatformCrypto.randomBytes(32), // 没有私钥就只能瞎猜
            pairingId = request.pairingId,
            windowsPublicKey = computerKey.publicKey,
            phonePublicKey = phoneKey.publicKey,
            windowsUserSid = record.windowsUserSid,
        )

        assertNotEquals(record.secret, attackerGuess.encode())
        assertNotEquals(record.resolveSecret().sas, attackerGuess.sas)
    }

    @Test
    fun `配对数密钥编解码往返`() {
        val pairing = TestEnv.pairing("secret-codec")
        val encoded = pairing.secret.encode()

        // 64 字节 Base64Url 无填充 = 86 字符
        assertEquals(86, encoded.length)
        val decoded = PairSecret.decode(encoded)
        assertContentEquals(pairing.secret.encKey, decoded.encKey)
        assertContentEquals(pairing.secret.macKey, decoded.macKey)
    }

    @Test
    fun `长度不对的配对数密钥被拒绝`() {
        assertFailsWith<IllegalArgumentException> {
            PairSecret.decode(Base64Url.encode(PlatformCrypto.randomBytes(63)))
        }
        assertFailsWith<IllegalArgumentException> {
            PairSecret.decode(Base64Url.encode(PlatformCrypto.randomBytes(65)))
        }
    }

    @Test
    fun `wipe 之后密钥材料被清零`() {
        val secret = TestEnv.pairing("wipe").secret
        secret.wipe()
        assertContentEquals(ByteArray(32), secret.encKey)
        assertContentEquals(ByteArray(32), secret.macKey)
    }
}
