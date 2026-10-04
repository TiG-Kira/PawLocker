package com.kira.pawlocker.core.protocol

import com.kira.pawlocker.core.Pairing
import com.kira.pawlocker.core.TestEnv
import com.kira.pawlocker.core.crypto.Aead
import com.kira.pawlocker.core.crypto.AeadFailure
import com.kira.pawlocker.core.crypto.Base64Url
import com.kira.pawlocker.core.crypto.PairSecret
import com.kira.pawlocker.core.flipLastBase64Byte
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * 解锁指令的封装与校验。
 *
 * ## 四层防护的独立性
 *
 * 每一层都必须能**单独**拦住对应的攻击，不能被其它层掩盖：
 *  - 篡改头部/密文 → 签名层（第①层）先拦下
 *  - 目标账户不对 → 绑定链（第②层）
 *  - 重放旧指令 → 新鲜性层（第③层）
 *  - 换了对称密钥但签名合法 → 机密性层（第④层）
 *
 * 特别是第④层的用例：签名用的是手机**身份密钥**，与配对协商的对称密钥相互独立。
 * 这让「签名合法但密钥不对」成为可能 —— 也正因如此必须单独验证。
 *
 * ## 关于装配辅助函数
 *
 * `targetWindowsUserSid` / `expectedWindowsUserSid` 在生产代码里**刻意不给默认值**：
 * 忘了传就编译不过，好过悄悄退化成「不绑定账户」。
 * 但测试里绝大多数用例并不关心账户，所以这里用 [seal] / [open] 两个局部辅助
 * 把「账户取自配对记录」这件事一次性收口，与生产代码的严格性并不冲突。
 */
class UnlockProtocolTest {

    private val now = 1_700_000_000_000L
    private val displayName = "Kira 的手机"

    // ——————————————————————————————————————————————————————————
    // 装配辅助
    // ——————————————————————————————————————————————————————————

    /** 用配对记录里绑定的账户封装一条指令。 */
    private fun seal(
        pairing: Pairing,
        counter: Long,
        at: Long = now,
        action: String = UnlockAction.UNLOCK,
        targetWindowsUserSid: String = pairing.windowsUserSid,
    ): UnlockRequest = UnlockProtocol.seal(
        secret = pairing.secret,
        phoneKey = pairing.phoneKey,
        phoneDeviceId = pairing.phoneDeviceId,
        clientDisplayName = displayName,
        targetWindowsUserSid = targetWindowsUserSid,
        counter = counter,
        now = at,
        action = action,
    )

    /** 以「本机当前账户 == 配对时那个账户」为前提校验一条指令。 */
    private fun open(
        request: UnlockRequest,
        pairing: Pairing,
        phonePublicKey: ByteArray = pairing.phoneKey.publicKey,
        secret: PairSecret = pairing.secret,
        guard: ReplayGuard = ReplayGuard(),
        at: Long = now,
        expectedWindowsUserSid: String = pairing.windowsUserSid,
    ): UnlockRequest.Payload = UnlockProtocol.open(
        request = request,
        phonePublicKey = phonePublicKey,
        secret = secret,
        expectedWindowsUserSid = expectedWindowsUserSid,
        guard = guard,
        now = at,
    )

    // ——————————————————————————————————————————————————————————
    // 正向
    // ——————————————————————————————————————————————————————————

    @Test
    fun `完整解锁指令往返`() {
        val pairing = TestEnv.pairing("unlock-happy")
        val request = seal(pairing, counter = 1)

        val payload = open(request, pairing)

        assertEquals(UnlockAction.UNLOCK, payload.action)
        assertEquals(now, payload.issuedAt)
        assertEquals(displayName, payload.clientDisplayName)
        assertEquals(pairing.phoneDeviceId, request.deviceId)
        assertEquals(1, request.counter)
        assertEquals(now, request.requestedAt)
        assertEquals(pairing.windowsUserSid, request.targetUserSid, "指令必须声明目标账户")
    }

    @Test
    fun `三种动作都能被正确解出`() {
        val pairing = TestEnv.pairing("unlock-actions")

        for ((index, action) in listOf(UnlockAction.UNLOCK, UnlockAction.WAKE, UnlockAction.LOCK).withIndex()) {
            val request = seal(pairing, counter = index + 1L, action = action)
            assertEquals(action, open(request, pairing).action)
        }
    }

    @Test
    fun `每次封装使用全新的 nonce 与密文`() {
        val pairing = TestEnv.pairing("unlock-nonce")
        val first = seal(pairing, counter = 1)
        val second = seal(pairing, counter = 1)

        assertNotEquals(first.nonce, second.nonce)
        // 明文完全相同，密文也必须不同 —— 否则攻击者能看出「两条指令内容一样」
        assertNotEquals(first.ciphertext, second.ciphertext)
    }

    @Test
    fun `指令载荷不以明文出现在报文中`() {
        val pairing = TestEnv.pairing("unlock-confidential")
        val request = seal(pairing, counter = 1)

        val decoded = Base64Url.decode(request.ciphertext).decodeToString()
        assertFalse(decoded.contains(displayName), "手机名称不该以明文出现在密文里")
        assertFalse(decoded.contains(UnlockAction.UNLOCK))
        assertFalse(WireCodec.encode(request).decodeToString().contains(displayName))
    }

    // ——————————————————————————————————————————————————————————
    // 第①层：来源认证
    // ——————————————————————————————————————————————————————————

    @Test
    fun `换成陌生人的公钥验签失败`() {
        val pairing = TestEnv.pairing("unlock-stranger")
        val stranger = TestEnv.identity("stranger")

        val error = assertFailsWith<UnlockRejectedException> {
            open(seal(pairing, counter = 1), pairing, phonePublicKey = stranger.publicKey)
        }
        assertEquals(ErrorCodes.BAD_SIGNATURE, error.code)
    }

    @Test
    fun `篡改密文会被签名层先拦下`() {
        // encrypt-then-sign 的直接推论：密文一个字节都动不了，
        // 而且是在「解密」之前就被拒绝，攻击者拿不到任何解密侧的行为差异
        val pairing = TestEnv.pairing("unlock-ct-tamper")
        val request = seal(pairing, counter = 1)

        val error = assertFailsWith<UnlockRejectedException> {
            open(request.copy(ciphertext = request.ciphertext.flipLastBase64Byte()), pairing)
        }
        assertEquals(ErrorCodes.BAD_SIGNATURE, error.code)
    }

    @Test
    fun `篡改计数器或时间戳会被签名层拦下`() {
        val pairing = TestEnv.pairing("unlock-header-tamper")
        val request = seal(pairing, counter = 5)

        // 攻击者想把计数器改大（把合法手机锁死）或改小（绕过防重放）
        for (tampered in listOf(
            request.copy(counter = 999),
            request.copy(counter = 1),
            request.copy(requestedAt = now + 1),
            request.copy(requestedAt = now - 1),
            request.copy(nonce = PairingProtocol.newNonce()),
            request.copy(deviceId = "someone-else"),
            request.copy(targetUserSid = TestEnv.otherUser.bindingKey),
        )) {
            val error = assertFailsWith<UnlockRejectedException> { open(tampered, pairing) }
            assertEquals(ErrorCodes.BAD_SIGNATURE, error.code)
        }
    }

    @Test
    fun `签名被改动一位就失效`() {
        val pairing = TestEnv.pairing("unlock-sig-tamper")
        val request = seal(pairing, counter = 1)

        val error = assertFailsWith<UnlockRejectedException> {
            open(request.copy(signature = request.signature.flipLastBase64Byte()), pairing)
        }
        assertEquals(ErrorCodes.BAD_SIGNATURE, error.code)
    }

    @Test
    fun `空签名与乱码签名都被拒绝`() {
        val pairing = TestEnv.pairing("unlock-bad-sig")
        val request = seal(pairing, counter = 1)

        for (bad in listOf("", "AQID", Base64Url.encode(ByteArray(64)))) {
            val error = assertFailsWith<UnlockRejectedException> {
                open(request.copy(signature = bad), pairing)
            }
            assertEquals(ErrorCodes.BAD_SIGNATURE, error.code)
        }
    }

    // ——————————————————————————————————————————————————————————
    // 第②层：绑定链（设备 + Windows 账户 + 手机）
    // ——————————————————————————————————————————————————————————

    /**
     * 绑定链的核心用例。
     *
     * 场景：家里一台电脑上开着两个 Windows 账户，「Kira」和「Guest」。
     * 手机是配给「Kira」的 —— 它发出的指令里 `targetUserSid` 写死了「Kira」。
     * 如果此刻电脑上登录的是「Guest」，这条指令必须被拒绝，
     * 而不是因为「设备对、签名对、密钥对」就放行。
     */
    @Test
    fun `指令目标账户与本机账户不符时被拒绝`() {
        val pairing = TestEnv.pairing("unlock-user-mismatch")
        val request = seal(pairing, counter = 1)

        val error = assertFailsWith<UnlockRejectedException> {
            open(request, pairing, expectedWindowsUserSid = TestEnv.otherUser.bindingKey)
        }
        assertEquals(ErrorCodes.USER_MISMATCH, error.code)
        // 拒绝原因要把「指令想去哪」说清楚，手机端才能原样展示给用户
        assertTrue(
            error.message!!.contains(request.targetUserSid),
            "拒绝原因应指明指令声明的目标账户，实际是：${error.message}",
        )
    }

    @Test
    fun `声明的目标账户为空时被拒绝`() {
        // 老版本客户端 / 手工构造的报文可能不带账户标识。
        // 「两边都空」绝不能算匹配 —— 否则绑定链等于没做。
        val pairing = TestEnv.pairing("unlock-user-blank")

        val error = assertFailsWith<UnlockRejectedException> {
            open(seal(pairing, counter = 1, targetWindowsUserSid = ""), pairing)
        }
        assertEquals(ErrorCodes.USER_MISMATCH, error.code)
    }

    /**
     * 账户校验必须排在防重放**之前**。
     *
     * 否则会出现这种服务拒绝：同一台手机切到别的账户后随手发了一次指令，
     * 计数器被推高，回到自己的账户反而解不开了。
     */
    @Test
    fun `账户不匹配的指令不会消耗计数器额度`() {
        val pairing = TestEnv.pairing("unlock-user-no-poison")
        val guard = ReplayGuard()

        // 一条「账户不对」但签名完全合法的指令，计数器是 100
        assertFailsWith<UnlockRejectedException> {
            open(
                seal(pairing, counter = 100),
                pairing,
                guard = guard,
                expectedWindowsUserSid = TestEnv.otherUser.bindingKey,
            )
        }

        // 计数器基线没被推高：1 依然可用
        assertNotNull(open(seal(pairing, counter = 1), pairing, guard = guard))
    }

    @Test
    fun `为另一个账户封装的指令解不开本账户的锁`() {
        val pairing = TestEnv.pairing("unlock-cross-account")
        val request = seal(pairing, counter = 1, targetWindowsUserSid = TestEnv.otherUser.bindingKey)

        val error = assertFailsWith<UnlockRejectedException> {
            open(request, pairing, expectedWindowsUserSid = TestEnv.testUser.bindingKey)
        }
        assertEquals(ErrorCodes.USER_MISMATCH, error.code)
    }

    /**
     * 账户标识参与 HKDF 派生 —— 这是比「某处 if 忘了写」更结实的一层。
     *
     * 两台设备即使公钥、pairingId、ECDH 秘密全都一样，只要 Windows 账户不同，
     * 派生出的 encKey 就不同，密文也就解不开。
     */
    @Test
    fun `不同 Windows 账户派生出不同的长期密钥`() {
        val pairing = TestEnv.pairing("unlock-derive-account")

        val sameAccount = PairSecret.derive(
            sharedSecret = ByteArray(32) { 0x11 },
            pairingId = "pid",
            windowsPublicKey = ByteArray(65) { 0x22 },
            phonePublicKey = ByteArray(65) { 0x33 },
            windowsUserSid = TestEnv.testUser.bindingKey,
        )
        val otherAccount = PairSecret.derive(
            sharedSecret = ByteArray(32) { 0x11 },
            pairingId = "pid",
            windowsPublicKey = ByteArray(65) { 0x22 },
            phonePublicKey = ByteArray(65) { 0x33 },
            windowsUserSid = TestEnv.otherUser.bindingKey,
        )

        assertFalse(sameAccount.encKey.contentEquals(otherAccount.encKey))
        assertFalse(sameAccount.macKey.contentEquals(otherAccount.macKey))
        assertNotEquals(sameAccount.sas, otherAccount.sas, "SAS 也会不同，足以被肉眼发现")

        // 同账户必须稳定 —— 否则两端会推出不同的密钥
        assertEquals(
            sameAccount.encode(),
            PairSecret.derive(
                sharedSecret = ByteArray(32) { 0x11 },
                pairingId = "pid",
                windowsPublicKey = ByteArray(65) { 0x22 },
                phonePublicKey = ByteArray(65) { 0x33 },
                windowsUserSid = TestEnv.testUser.bindingKey,
            ).encode(),
        )
    }

    // ——————————————————————————————————————————————————————————
    // 第③层：新鲜性
    // ——————————————————————————————————————————————————————————

    @Test
    fun `同一条指令重放被拒绝`() {
        val pairing = TestEnv.pairing("unlock-replay")
        val guard = ReplayGuard()
        val request = seal(pairing, counter = 1)

        assertNotNull(open(request, pairing, guard = guard))

        val error = assertFailsWith<UnlockRejectedException> {
            open(request, pairing, guard = guard)
        }
        assertEquals(ErrorCodes.REPLAY_DETECTED, error.code)
    }

    @Test
    fun `计数器回滚被拒绝`() {
        val pairing = TestEnv.pairing("unlock-counter")
        val guard = ReplayGuard()

        open(seal(pairing, counter = 5), pairing, guard = guard)

        // nonce 是新的、时间也新鲜，只有计数器倒退
        val error = assertFailsWith<UnlockRejectedException> {
            open(seal(pairing, counter = 4), pairing, guard = guard)
        }
        assertEquals(ErrorCodes.REPLAY_DETECTED, error.code)

        // 递增则放行
        assertNotNull(open(seal(pairing, counter = 6), pairing, guard = guard))
    }

    @Test
    fun `时间戳超出窗口被拒绝并映射为时钟偏差`() {
        val pairing = TestEnv.pairing("unlock-skew")

        val error = assertFailsWith<UnlockRejectedException> {
            open(seal(pairing, counter = 1, at = now - 120_000), pairing)
        }
        assertEquals(ErrorCodes.CLOCK_SKEW, error.code)
        assertTrue(error.message!!.contains("时钟偏差"))
    }

    @Test
    fun `被拒绝的重放不会把合法计数器带偏`() {
        val pairing = TestEnv.pairing("unlock-poison")
        val guard = ReplayGuard()

        // 先放一条计数器很大的报文（签名合法，来自真实手机）
        open(seal(pairing, counter = 100), pairing, guard = guard)

        // 攻击者伪造一条「计数器更大但签名无效」的报文
        assertFailsWith<UnlockRejectedException> {
            open(seal(pairing, counter = 500).copy(counter = 900), pairing, guard = guard)
        }

        // 状态未被污染：101 依然可用
        assertNotNull(open(seal(pairing, counter = 101), pairing, guard = guard))
    }

    // ——————————————————————————————————————————————————————————
    // 第④层：机密性与完整性
    // ——————————————————————————————————————————————————————————

    @Test
    fun `签名合法但配对密钥不对时被解密层拦下`() {
        val a = TestEnv.pairing("unlock-key-a")
        val b = TestEnv.pairing("unlock-key-b")

        // 用 A 的手机身份签名并加密，但用 B 的对称密钥去解：
        // 签名来自 A 的合法身份 → 第①层通过；GCM 认证失败 → 第④层拦下
        val error = assertFailsWith<UnlockRejectedException> {
            open(seal(a, counter = 1), a, secret = b.secret)
        }
        assertEquals(ErrorCodes.DECRYPT_FAILED, error.code)
    }

    /**
     * AAD 把设备 ID、目标账户、计数器、时间戳、nonce 一并绑进密文。
     *
     * 注意这条防线在 `open()` 里其实是**够不到**的 —— 签名覆盖了同一份 AAD，
     * 任何改动都会先被第①层拦下。所以这里直接对 AEAD 原语做验证，
     * 把「即使签名层被绕过，密文也无法跨设备/跨账户搬运」这个事实固定下来。
     */
    @Test
    fun `AAD 把设备 ID 与目标账户绑进密文`() {
        val pairing = TestEnv.pairing("unlock-aad")
        val request = seal(pairing, counter = 1)

        // 用另一个 deviceId 重建 AAD 去解原密文，必须认证失败
        assertFailsWith<AeadFailure> {
            Aead.open(
                key = pairing.secret.encKey,
                nonce = Base64Url.decode(request.nonce),
                ciphertext = Base64Url.decode(request.ciphertext),
                aad = request.copy(deviceId = "another-device-id").aad(),
            )
        }
        // 换个目标账户同样解不开
        assertFailsWith<AeadFailure> {
            Aead.open(
                key = pairing.secret.encKey,
                nonce = Base64Url.decode(request.nonce),
                ciphertext = Base64Url.decode(request.ciphertext),
                aad = request.copy(targetUserSid = TestEnv.otherUser.bindingKey).aad(),
            )
        }
        // 用原 AAD 则能正常打开 —— 说明上面失败确实来自 AAD 差异，而不是别的原因
        assertTrue(
            Aead.open(
                key = pairing.secret.encKey,
                nonce = Base64Url.decode(request.nonce),
                ciphertext = Base64Url.decode(request.ciphertext),
                aad = request.aad(),
            ).isNotEmpty(),
        )
    }

    // ——————————————————————————————————————————————————————————
    // 回执
    // ——————————————————————————————————————————————————————————

    @Test
    fun `成功回执的 MAC 可被手机端校验`() {
        val pairing = TestEnv.pairing("ack-ok")
        val ack = UnlockProtocol.buildAck(pairing.secret, ok = true, counter = 1, serverTime = now)

        assertTrue(ack.ok)
        assertNotNull(ack.mac)
        assertTrue(UnlockProtocol.verifyAck(pairing.secret, ack))
    }

    @Test
    fun `失败回执也带 MAC 并保留原因`() {
        val pairing = TestEnv.pairing("ack-fail")
        val ack = UnlockProtocol.buildAck(
            pairing.secret,
            ok = false,
            counter = 3,
            serverTime = now,
            code = ErrorCodes.UNLOCK_REJECTED,
            message = "解锁策略不允许该动作",
        )

        assertFalse(ack.ok)
        assertEquals(ErrorCodes.UNLOCK_REJECTED, ack.code)
        assertEquals("解锁策略不允许该动作", ack.message)
        assertTrue(UnlockProtocol.verifyAck(pairing.secret, ack), "失败回执同样要能证明来源")
    }

    @Test
    fun `回执任一字段被改动都会导致 MAC 校验失败`() {
        val pairing = TestEnv.pairing("ack-tamper")
        val ack = UnlockProtocol.buildAck(pairing.secret, ok = true, counter = 7, serverTime = now)

        // 攻击者把「失败」改成「成功」，或者篡改计数器把手机带偏
        assertFalse(UnlockProtocol.verifyAck(pairing.secret, ack.copy(ok = false)))
        assertFalse(UnlockProtocol.verifyAck(pairing.secret, ack.copy(counter = 8)))
        assertFalse(UnlockProtocol.verifyAck(pairing.secret, ack.copy(serverTime = now + 1)))
        assertFalse(UnlockProtocol.verifyAck(pairing.secret, ack.copy(mac = null)))
        assertFalse(UnlockProtocol.verifyAck(pairing.secret, ack.copy(mac = Base64Url.encode(ByteArray(32)))))
    }

    @Test
    fun `别的配对密钥无法伪造或验证回执`() {
        val a = TestEnv.pairing("ack-iso-a")
        val b = TestEnv.pairing("ack-iso-b")
        val ack = UnlockProtocol.buildAck(a.secret, ok = true, counter = 1, serverTime = now)

        assertFalse(UnlockProtocol.verifyAck(b.secret, ack))
    }

    @Test
    fun `回执可以放进线路报文往返`() {
        val pairing = TestEnv.pairing("ack-wire")
        val ack = UnlockProtocol.buildAck(pairing.secret, ok = true, counter = 2, serverTime = now)
        val decoded = WireCodec.decode(WireCodec.encode(ack))

        assertEquals(ack, decoded)
        assertTrue(UnlockProtocol.verifyAck(pairing.secret, decoded as UnlockAck))
    }

    // ——————————————————————————————————————————————————————————
    // 拒绝原因的可读性（手机端要把它翻成人话展示）
    // ——————————————————————————————————————————————————————————

    @Test
    fun `各类拒绝都带有非空且可读的原因`() {
        val pairing = TestEnv.pairing("unlock-messages")
        val stranger = TestEnv.identity("stranger-msg")
        val request = seal(pairing, counter = 1)

        val errors = listOf(
            assertFailsWith<UnlockRejectedException> {
                open(request, pairing, phonePublicKey = stranger.publicKey)
            },
            assertFailsWith<UnlockRejectedException> {
                open(request, pairing, secret = TestEnv.pairing("other").secret)
            },
            assertFailsWith<UnlockRejectedException> {
                open(request, pairing, expectedWindowsUserSid = TestEnv.otherUser.bindingKey)
            },
        )

        for (error in errors) {
            assertTrue(error.message!!.isNotBlank())
            assertTrue(error.code.isNotBlank())
        }
    }
}
