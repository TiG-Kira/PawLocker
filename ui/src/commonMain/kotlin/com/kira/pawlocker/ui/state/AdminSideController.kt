package com.kira.pawlocker.ui.state

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.kira.pawlocker.core.config.AppConfig
import com.kira.pawlocker.core.config.ConfigStore
import com.kira.pawlocker.core.config.EndpointResolver
import com.kira.pawlocker.core.config.TunnelLauncher
import com.kira.pawlocker.core.config.WindowsUnlockStrategy
import com.kira.pawlocker.core.config.createTunnelLauncher
import com.kira.pawlocker.core.crypto.DeviceProfile
import com.kira.pawlocker.core.crypto.IdentityKey
import com.kira.pawlocker.core.net.LockerServer
import com.kira.pawlocker.core.net.ServerEvent
import com.kira.pawlocker.core.net.ServerEventKind
import com.kira.pawlocker.core.net.ServerHooks
import com.kira.pawlocker.core.net.UnlockExecutor
import com.kira.pawlocker.core.net.UnlockOutcome
import com.kira.pawlocker.core.platform.CleanupReport
import com.kira.pawlocker.core.platform.PendingStep
import com.kira.pawlocker.core.platform.PlatformEnv
import com.kira.pawlocker.core.platform.RegistrationResult
import com.kira.pawlocker.core.platform.RegistrationState
import com.kira.pawlocker.core.platform.WindowsRegistrar
import com.kira.pawlocker.core.platform.createWindowsRegistrar
import com.kira.pawlocker.core.platform.currentUserIdentity
import com.kira.pawlocker.core.protocol.PairingOffer
import com.kira.pawlocker.core.protocol.UnlockRequest
import com.kira.pawlocker.core.trust.PeerRole
import com.kira.pawlocker.core.trust.TrustRecord
import com.kira.pawlocker.core.trust.TrustStore
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Windows 端的界面状态持有者。
 *
 * 同时扮演两个角色：
 *  1. 给界面提供可观察状态（服务是否在跑、信任手机列表、当前配对口令、事件流）
 *  2. 实现 [ServerHooks]，把协议层的两个「需要人类介入」的点桥接到 UI
 *
 * 第 2 点是这个类存在的主要理由 —— [LockerServer] 是纯逻辑，它不知道
 * 对话框长什么样；这里用 [CompletableDeferred] 把「等用户点允许/拒绝」
 * 变成一个可挂起的操作，协议层只管 `await()`。
 */
class AdminSideController(
    private val identity: IdentityKey,
    private val trustStore: TrustStore,
    private val profile: DeviceProfile,
    private val scope: CoroutineScope,
    private val configStore: ConfigStore = ConfigStore(),
) : ServerHooks {

    private val tunnelLauncher: TunnelLauncher = createTunnelLauncher()

    private val registrar: WindowsRegistrar = createWindowsRegistrar()

    private val server = LockerServer(
        identity = identity,
        profile = profile,
        // 本机当前 Windows 账户 —— 三元绑定链的中间一环。
        // 解析结果在进程内缓存，不会每次解锁都去拉 whoami
        localUser = currentUserIdentity(),
        trustStore = trustStore,
        hooks = this,
    )

    // ——————————————————————————————————————————————————————————
    // 可观察状态
    // ——————————————————————————————————————————————————————————

    var config: AppConfig by mutableStateOf(configStore.load())
        private set

    var isServiceRunning: Boolean by mutableStateOf(false)
        private set

    var boundPort: Int by mutableStateOf(0)
        private set

    var trustedPhones: List<TrustRecord> by mutableStateOf(emptyList())
        private set

    /** 当前有效的配对邀请；非 null 时配对页展示二维码与配对码。 */
    var pairingOffer: PairingOffer? by mutableStateOf(null)
        private set

    /** 非 null 时弹出「某手机请求配对」的确认框。 */
    var pendingApproval: PendingApproval? by mutableStateOf(null)
        private set

    var events: List<ServerEvent> by mutableStateOf(emptyList())
        private set

    var tunnelStatus: String by mutableStateOf("未启用")
        private set

    var lastError: String? by mutableStateOf(null)
        private set

    /** 注册体检结果：防火墙、凭据提供程序、开机启动项各自到位没有。 */
    var registrationState: RegistrationState by mutableStateOf(RegistrationState())
        private set

    /** 最近一次注册操作的结果文案，非 null 时由界面弹提示。 */
    var registrationMessage: String? by mutableStateOf(null)
        private set

    /**
     * 最近一次「清理系统痕迹」的逐项报告，非 null 时由界面展示。
     *
     * 与 [registrationMessage] 分开：清理的结果是五项各自的状态，
     * 压成一句「操作成功」就没有任何信息量了。
     */
    var cleanupReport: CleanupReport? by mutableStateOf(null)
        private set

    /** 由 App 注入具体的执行器（桌面用 Credential Provider 桥，预览用模拟实现）。 */
    var unlockExecutor: UnlockExecutor? = null

    val unlockStrategy: WindowsUnlockStrategy get() = config.unlockStrategy

    /** 当前平台能不能管 Windows 注册项（Android 端恒为 false）。 */
    val registrationSupported: Boolean get() = registrar.isSupported

    /**
     * 首次启动向导是否该出现。
     *
     * 只有「用户没走完向导」才拦在前面；一旦走完（哪怕是点了「稍后再说」跳过），
     * 就不再打扰 —— 后续注册项缺失改用体检结果在设置页里提示。
     * 强制每次都拦，会让「重装系统后注册表清空」变成每次开机都要过的关卡。
     */
    val needsSetupWizard: Boolean get() = !config.setupCompleted

    private var approvalDeferred: CompletableDeferred<Boolean>? = null

    // ——————————————————————————————————————————————————————————
    // 生命周期
    // ——————————————————————————————————————————————————————————

    fun initialize() {
        server.restoreReplayBaseline()
        refreshTrusted()
        refreshRegistration()
        if (config.autoStartService) startService()
    }

    fun startService() {
        if (isServiceRunning) return
        scope.launch {
            try {
                server.start(config.listenPort, config.bindAddress)
                boundPort = config.listenPort
                isServiceRunning = true
                lastError = null

                // 把可达地址同步给服务端，配对时随响应下发给手机
                server.setEndpoints(EndpointResolver.resolve(config, boundPort))

                startTunnelIfNeeded()
            } catch (error: Throwable) {
                lastError = error.message ?: "服务启动失败"
                isServiceRunning = false
            }
        }
    }

    fun stopService() {
        server.stop()
        tunnelLauncher.stop()
        tunnelStatus = "未启用"
        isServiceRunning = false
        boundPort = 0
        pairingOffer = null
    }

    fun restartService() {
        stopService()
        startService()
    }

    private fun startTunnelIfNeeded() {
        if (!config.tunnel.enabled) {
            tunnelStatus = "未启用"
            return
        }
        if (!tunnelLauncher.isSupported) {
            tunnelStatus = "当前平台不支持托管穿透进程"
            return
        }
        val failure = tunnelLauncher.start(config)
        tunnelStatus = failure ?: "运行中（配置：${tunnelLauncher.configFilePath()}）"
    }

    // ——————————————————————————————————————————————————————————
    // 配对
    // ——————————————————————————————————————————————————————————

    fun openPairingWindow() {
        if (!isServiceRunning) {
            lastError = "服务未启动，无法生成配对码"
            return
        }
        server.setEndpoints(EndpointResolver.resolve(config, boundPort))
        pairingOffer = server.openPairingWindow()
    }

    fun closePairingWindow() {
        server.closePairingWindow()
        pairingOffer = null
    }

    /**
     * 配对确认的「允许」/「拒绝」。
     *
     * 由管理页内联卡片的按钮回调驱动，跑在主线程，所以 [pendingApproval] 可以直接写。
     *
     * 无论哪种结果都要 `complete` —— 漏掉的话协议层那个
     * `deferred.await()` 会一直挂到 60 秒超时，手机端表现为「转圈到没」。
     * `complete` 之后再置空是为了让点击立刻收起卡片，不必等 await 的调用方醒来。
     */
    fun resolveApproval(approved: Boolean) {
        val deferred = approvalDeferred
        approvalDeferred = null
        pendingApproval = null
        if (deferred != null) {
            PlatformEnv.log("AdminSideController", "配对确认：${if (approved) "允许" else "拒绝"}")
            deferred.complete(approved)
        } else {
            // 走到这里说明对话框被重复触发过（重组或双击）。
            // 不记日志的话，重复 complete 的异常会被静默吞掉，只剩「界面卡住」。
            PlatformEnv.log("AdminSideController", "配对确认：没有待处理的请求，忽略本次操作")
        }
    }

    // ——————————————————————————————————————————————————————————
    // 信任手机管理
    // ——————————————————————————————————————————————————————————

    fun refreshTrusted() {
        trustedPhones = trustStore.all()
            .filter { it.role == PeerRole.PHONE }
            .sortedByDescending { it.lastSeenAt }
    }

    fun revoke(record: TrustRecord) {
        server.revoke(record.deviceId)
        refreshTrusted()
    }

    // ——————————————————————————————————————————————————————————
    // 配置
    // ——————————————————————————————————————————————————————————

    fun updateConfig(transform: (AppConfig) -> AppConfig) {
        val updated = transform(config).normalized()
        config = updated
        configStore.save(updated)
        if (isServiceRunning) {
            server.setEndpoints(EndpointResolver.resolve(updated, boundPort))
        }
    }

    fun setUnlockStrategy(strategy: WindowsUnlockStrategy) {
        updateConfig { it.copy(unlockStrategy = strategy) }
    }

    fun clearError() {
        lastError = null
    }

    /** 当前对外宣告的地址列表，设置页里展示给用户看「手机将会连哪里」。 */
    fun advertisedEndpoints() = EndpointResolver.resolve(config, boundPort)

    /** 本机身份公钥，设置页里显示指纹用。 */
    fun identityFingerprint(): ByteArray = identity.publicKey

    /** 底层密码学实现标识，排障时有用。 */
    fun cryptoBackend(): String = com.kira.pawlocker.core.crypto.PlatformCrypto.backendName

    // ——————————————————————————————————————————————————————————
    // Windows 注册（首次启动向导与设置页共用）
    // ——————————————————————————————————————————————————————————

    /** 重新体检。只读注册表与 netsh，不会弹 UAC。 */
    fun refreshRegistration() {
        registrationState = registrar.inspect(config.listenPort)
    }

    /**
     * 当前策略下还没做完的注册项。
     *
     * 走 [registrationState] 的派生方法而不是在这里重写判断逻辑 ——
     * 注册项该不该要求，是「策略」的属性，不是控制器的属性。
     */
    fun pendingSetupSteps(): List<PendingStep> =
        registrationState.pendingSteps(config.unlockStrategy).filter {
            // 开机启动单独由设置页的开关控制，不塞进向导的待办里，
            // 否则用户会在「我只是想试试」的阶段被逼着做系统级改动
            it.key != PendingStep.KEY_AUTO_START
        }

    /** 向导里的「稍后再说」：不再拦启动，也不做任何系统改动。 */
    fun dismissSetupWizard() {
        updateConfig { it.copy(setupCompleted = true) }
    }

    /** 完成向导。 */
    fun completeSetupWizard() {
        updateConfig { it.copy(setupCompleted = true) }
        refreshRegistration()
    }

    /** 设置页里的「重新运行首次启动向导」。 */
    fun reopenSetupWizard() {
        updateConfig { it.copy(setupCompleted = false) }
        refreshRegistration()
    }

    fun registerCredentialProvider(dllPath: String): RegistrationResult {
        val path = dllPath.trim().ifBlank { config.credentialProviderDllPath }
        val result = runRegistration { registrar.registerCredentialProvider(path) }
        // 只有成功才记住路径 —— 失败时记住一个错路径，下次重试还得先删
        if (result.isSuccess) updateConfig { it.copy(credentialProviderDllPath = path) }
        return result
    }

    fun unregisterCredentialProvider(): RegistrationResult =
        runRegistration { registrar.unregisterCredentialProvider() }

    /**
     * 清掉本程序留在 Windows 里的全部系统痕迹。
     *
     * 供「我要卸载了」这个场景使用。这些项都是用户在应用里点按钮才写进系统的，
     * MSI 不认识它们，所以控制面板里的卸载不会清 —— 不手动清就会留下一地残留
     * （锁屏上一个点不开的磁贴、一条指向已删程序的防火墙规则）。
     *
     * 走自己的 [runRegistration] 语义但**不覆盖** [registrationMessage]：
     * 清理的结果是逐项报告，塞进一个「操作成功」字符串里会丢掉全部信息量。
     */
    fun cleanupSystemTraces(): CleanupReport {
        val report = registrar.cleanupAllSystemTraces(config.listenPort)
        cleanupReport = report
        PlatformEnv.log("AdminSideController", "清理系统痕迹：${report.summary()}")
        refreshRegistration()
        return report
    }

    fun clearCleanupReport() {
        cleanupReport = null
    }

    /**
     * 信任凭据提供程序 DLL 的签名证书。
     *
     * 指纹取自[registrationState]里最近一次体检的结果，而不是在这里重新探测 ——
     * 用户在界面上看到并确认的是**那一张**证书，写给系统的就必须是那一张。
     * 传错了会让「信任」变成对另一个对象的授权，而用户毫无察觉。
     */
    fun trustDllSignerCertificate(): RegistrationResult {
        val thumbprint = registrationState.credentialProviderSignature.signerThumbprint
            ?: return RegistrationResult.Failed("还没读到签名证书，请先重新体检。")
        return runRegistration { registrar.trustDllSignerCertificate(thumbprint) }
    }

    /** 撤销对签名证书的信任。 */
    fun revokeDllSignerCertificate(): RegistrationResult {
        val thumbprint = registrationState.credentialProviderSignature.signerThumbprint
            ?: return RegistrationResult.Failed("还没读到签名证书，请先重新体检。")
        return runRegistration { registrar.revokeDllSignerCertificate(thumbprint) }
    }

    fun ensureFirewallRule(): RegistrationResult =
        runRegistration { registrar.ensureFirewallRule(config.listenPort) }

    fun removeFirewallRule(): RegistrationResult =
        runRegistration { registrar.removeFirewallRule(config.listenPort) }

    /**
     * 开机启动项（`HKCU\...\Run`）。
     *
     * 注意与 [AppConfig.autoStartService] 区分开：那个是「程序跑起来之后要不要自动开始监听」，
     * 这个是「登录 Windows 后要不要自动把程序拉起来」。前者是应用内行为，后者是系统级注册。
     */
    fun setSystemAutoStart(enabled: Boolean): RegistrationResult =
        runRegistration { registrar.setAutoStart(enabled) }

    fun suggestedCredentialProviderPath(): String = registrar.suggestedCredentialProviderPath()

    fun currentCredentialProviderPath(): String =
        config.credentialProviderDllPath.ifBlank { suggestedCredentialProviderPath() }

    fun clearRegistrationMessage() {
        registrationMessage = null
    }

    /**
     * 包一层：统一把结果翻译成人话、刷新体检、顺手记日志。
     *
     * 三种结果都写日志 —— 「用户点了但 UAC 被拒」这种事发生在系统层面，
     * 应用窗口里没有任何痕迹，只能靠日志回溯。
     */
    private fun runRegistration(block: () -> RegistrationResult): RegistrationResult {
        val result = block()
        registrationMessage = when (result) {
            is RegistrationResult.Success -> "操作成功"
            is RegistrationResult.Cancelled -> "已取消：UAC 未获授权"
            is RegistrationResult.Failed -> result.message
        }
        PlatformEnv.log("AdminSideController", "注册操作结果：$registrationMessage")
        refreshRegistration()
        return result
    }

    // ——————————————————————————————————————————————————————————
    // ServerHooks 实现
    // ——————————————————————————————————————————————————————————

    override suspend fun onUnlock(
        request: UnlockRequest.Payload,
        phone: TrustRecord,
    ): UnlockOutcome {
        val executor = unlockExecutor
            ?: return UnlockOutcome.Failure(
                "internal",
                "未配置解锁执行器，请在设置页选择解锁方式",
            )
        return executor.execute(request.action)
    }

    /**
     * 请求用户在电脑上确认配对。
     *
     * 这里刻意**不设可见的超时**：[LockerServer] 侧已经有 60 秒上限，
     * UI 只需要把对话框摆在那里，超时由协议层兜底。
     *
     * ⚠️ 两个线程相关的要点，缺一个就会出现「手机一直等、电脑不弹窗」：
     *
     * 1. **必须切到主线程写 `pendingApproval`。** 本方法由 `LockerServer` 的
     *    协程（`Dispatchers.Default`）调用，直接写 `mutableStateOf` 属于
     *    后台线程写快照。写本身不会崩，但重组调度不可靠 ——
     *    表现就是「有时候卡片出得来，有时候半天不出」。
     *
     * 2. **`approvalDeferred` 要先赋值再改状态。** 顺序反了会出现
     *    「UI 已经渲染出按钮，但 deferred 还没就绪」的窗口，
     *    用户在这个窗口里点「允许」会静默无效。
     */
    override suspend fun confirmPairing(
        phoneDisplayName: String,
        phoneModel: String,
        phoneDeviceId: String,
    ): Boolean {
        val deferred = CompletableDeferred<Boolean>()
        approvalDeferred = deferred
        withContext(Dispatchers.Main) {
            pendingApproval = PendingApproval(phoneDisplayName, phoneModel, phoneDeviceId)
        }
        return deferred.await()
    }

    override fun onEvent(event: ServerEvent) {
        // 事件流只保留最近 200 条，避免长时间运行后内存无限增长
        events = (listOf(event) + events).take(MAX_EVENTS)

        if (event.kind == ServerEventKind.DEVICE_PAIRED || event.kind == ServerEventKind.DEVICE_REVOKED) {
            refreshTrusted()
            pairingOffer = null
        }
        if (event.kind == ServerEventKind.UNLOCK_SUCCEEDED) {
            lastUnlockAt = event.at
        }
    }

    var lastUnlockAt: Long? by mutableStateOf(null)
        private set

    private companion object {
        const val MAX_EVENTS = 200
    }
}

data class PendingApproval(
    val phoneDisplayName: String,
    val phoneModel: String,
    val phoneDeviceId: String,
)
