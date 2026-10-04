package com.kira.pawlocker.core.platform

import com.kira.pawlocker.core.config.WindowsCredentialStore
import com.kira.pawlocker.core.config.WindowsUnlockStrategy
import com.kira.pawlocker.core.net.UnlockExecutor
import com.kira.pawlocker.core.net.UnlockOutcome
import com.kira.pawlocker.core.protocol.ErrorCodes
import com.sun.jna.platform.win32.Kernel32
import com.sun.jna.platform.win32.User32
import com.sun.jna.platform.win32.WinDef
import com.sun.jna.platform.win32.WinNT
import com.sun.jna.platform.win32.WinUser
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Windows 侧的解锁执行器。
 *
 * ## 为什么不能「简单地自动输入密码」
 *
 * Windows 的锁屏界面跑在一个独立的 **安全桌面**（Winlogon desktop）上。
 * 普通进程（哪怕管理员）既不能向它发 `SendInput`，也读不到它的窗口。
 * 想在上面交互，程序必须以 **UIAccess** 身份运行并被代码签名，
 * 或者以 **Credential Provider** 的形式由 Winlogon 直接加载。
 *
 * 所以这里给出四条路径（见 [WindowsUnlockStrategy]），而不是假装一条就能通吃。
 * [WindowsUnlockStrategy.CREDENTIAL_PROVIDER] 走的是「JVM 侧发信号 + CP DLL 侧执行登录」的桥接：
 *
 * ```
 *   手机指令 → LockerServer 密码学校验通过
 *            → 本执行器 SetEvent("Global\PawLocker.Unlock.<用户>")
 *            → PawLockerProvider.dll 在锁屏界面等到该事件
 *            → 读取 DPAPI 保护的凭据 → 提交给 LogonUI 完成登录
 * ```
 *
 * JVM 侧只负责「发信号」与「存放凭据」，DLL 侧的接口契约见
 * `docs/01-architecture.md` 的「Windows 登录集成」一节。
 */
class WindowsUnlockExecutor(
    private val strategy: WindowsUnlockStrategy,
    private val customCommand: String = "",
    private val customCommandTimeoutMillis: Long = 15_000,
) : UnlockExecutor {

    override val displayName: String get() = strategy.displayName

    override suspend fun execute(action: String): UnlockOutcome = when (strategy) {
        WindowsUnlockStrategy.DRY_RUN -> {
            PlatformEnv.log(TAG, "DRY_RUN：收到动作 $action，不做任何实际处理")
            UnlockOutcome.Success(PlatformEnv.currentTimeMillis())
        }

        WindowsUnlockStrategy.WAKE_ONLY -> wakeDisplay()

        WindowsUnlockStrategy.CREDENTIAL_PROVIDER -> signalCredentialProvider(action)

        WindowsUnlockStrategy.CUSTOM_COMMAND -> runCustomCommand(action)
    }

    // ——————————————————————————————————————————————————————————

    /**
     * 轻推一下鼠标，让显示器从息屏 / 屏保状态恢复。
     *
     * 这是唯一不需要 UIAccess 就能生效的桌面交互 ——
     * 因为它作用于**用户桌面**，而不是锁屏的安全桌面。
     */
    private suspend fun wakeDisplay(): UnlockOutcome = withContext(Dispatchers.IO) {
        if (!isWindows()) {
            return@withContext UnlockOutcome.Failure(ErrorCodes.INTERNAL, "当前不是 Windows 环境")
        }
        runCatching {
            // 只注入「相对鼠标移动」，不碰键盘 —— 避免给这个组件留下
            // 被当作键盘记录器 / 输入注入工具的余地
            val input = WinUser.INPUT().apply {
                // JNA 的 INPUT.type 是 WinDef.DWORD（不是 Int），
                // 而 INPUT_MOUSE 常量挂在 WinUser.INPUT 上，不是 WinUser 上
                type = WinDef.DWORD(WinUser.INPUT.INPUT_MOUSE.toLong())
                input.setType(WinUser.MOUSEINPUT::class.java)
                input.mi.dx = WinDef.LONG(1)
                input.mi.dy = WinDef.LONG(1)
                input.mi.dwFlags = WinDef.DWORD(MOUSEEVENTF_MOVE.toLong())
                write()
            }
            // SendInput 返回的是「成功注入的事件数」，返回 DWORD 而不是 Int。
            // 注意：Kotlin 把 java.lang.Number 映射成 kotlin.Number，只有 toInt()，
            // 没有 intValue() —— 而 DWORD 的数值方法全部继承自 Number。
            val sent: WinDef.DWORD = User32.INSTANCE.SendInput(
                WinDef.DWORD(1L),
                arrayOf(input),
                input.size(),
            )
            if (sent.toInt() == 0) error("SendInput 返回 0，输入被系统丢弃")
            PlatformEnv.log(TAG, "已发送鼠标微动，唤醒显示器")
        }.fold(
            onSuccess = { UnlockOutcome.Success(PlatformEnv.currentTimeMillis()) },
            onFailure = { error -> UnlockOutcome.Failure(ErrorCodes.INTERNAL, "唤醒屏幕失败：${error.message}") },
        )
    }

    /**
     * 给 Credential Provider 发信号，并把凭据现投过去。
     *
     * 三步的顺序不能换：
     *  1. `OpenEvent` —— 先确认组件在不在（不存在就早退，不要白发一个信号）
     *  2. `listen()`  —— 把命名管道挂起来。**必须在置位事件之前**，
     *     否则会出现「CP 被叫醒了但管道还没有」的竞态
     *  3. `SetEvent` + `deliver` —— 通知并投递
     */
    private suspend fun signalCredentialProvider(action: String): UnlockOutcome =
        withContext(Dispatchers.IO) {
            if (!isWindows()) {
                return@withContext UnlockOutcome.Failure(ErrorCodes.INTERNAL, "当前不是 Windows 环境")
            }

            val credential = WindowsCredentialStore.load()
                ?: return@withContext UnlockOutcome.Failure(
                    ErrorCodes.UNLOCK_REJECTED,
                    "尚未在本机保存登录凭据，请先在设置页完成「凭据配置」",
                )

            val localUser = currentUserIdentity()
            val accountName = System.getProperty("user.name").orEmpty()

            // 绑定链的中间一环（主程序侧预检）：
            // 保存的凭据必须是为本机当前账户的。CP 侧还会用 LogonUI 的真实会话再校验一次，
            // 这里先拦一道是为了给出「配错账户了」这种可操作的提示，而不是让用户等到最后一步。
            if (credential.userSid.isNotBlank() &&
                localUser.isResolved &&
                credential.userSid != localUser.sid
            ) {
                return@withContext UnlockOutcome.Failure(
                    ErrorCodes.USER_MISMATCH,
                    "本机保存的凭据属于账户「${credential.userName}」（${credential.userSid}），" +
                        "与当前登录账户「${localUser.description}」不一致。请重新配置凭据。",
                )
            }

            val eventName = UNLOCK_EVENT_PREFIX + accountName
            val handle: WinNT.HANDLE? = runCatching {
                Kernel32.INSTANCE.OpenEvent(EVENT_MODIFY_STATE, false, eventName)
            }.getOrNull()

            if (handle == null) {
                return@withContext UnlockOutcome.Failure(
                    ErrorCodes.UNLOCK_REJECTED,
                    "未检测到 PawLocker 登录组件（PawLockerProvider.dll）。" +
                        "请先安装并注册该组件，或把解锁策略改为「仅唤醒屏幕」/「自定义命令」。",
                )
            }

            val handoff = CredentialHandoff(accountName)
            val session = handoff.listen()
                ?: run {
                    Kernel32.INSTANCE.CloseHandle(handle)
                    return@withContext UnlockOutcome.Failure(
                        ErrorCodes.INTERNAL,
                        "无法建立凭据投递通道（命名管道创建失败）",
                    )
                }

            try {
                // 事件置位 = 「本次解锁已授权」
                if (!Kernel32.INSTANCE.SetEvent(handle)) {
                    val code = Kernel32.INSTANCE.GetLastError()
                    return@withContext UnlockOutcome.Failure(
                        ErrorCodes.INTERNAL,
                        "向登录组件发送信号失败（Win32 错误码 $code）",
                    )
                }

                // CP 收到事件才会来连管道。连不上通常意味着锁屏界面上没有我们的磁贴
                // （比如当前根本没锁屏，或组件刚注册还没生效）。
                if (!session.awaitClient()) {
                    return@withContext UnlockOutcome.Failure(
                        ErrorCodes.UNLOCK_REJECTED,
                        "登录组件没有响应。请确认电脑处于锁屏界面；" +
                            "若刚注册过组件，需要重启一次才生效。",
                    )
                }

                val blob = CredentialBlobCodec.encode(
                    userName = credential.userName,
                    domain = credential.domain,
                    password = credential.password,
                    // 记录里没存 SID 时用本机当前账户兜底 —— CP 侧仍会拿
                    // LogonUI 的真实会话 SID 再校验一次，所以这不是绕过
                    sid = credential.userSid.ifBlank { localUser.sid },
                )

                val delivered = try {
                    session.deliver(blob)
                } finally {
                    // 明文只在这条语句的作用域里存在过，用完立刻抹掉
                    CredentialBlobCodec.wipe(blob)
                }

                if (!delivered) {
                    return@withContext UnlockOutcome.Failure(
                        ErrorCodes.INTERNAL,
                        "凭据投递失败，登录组件没有接收到数据",
                    )
                }

                PlatformEnv.log(TAG, "已向 Credential Provider 投递凭据并请求解锁，动作=$action")
                UnlockOutcome.Success(PlatformEnv.currentTimeMillis())
            } finally {
                Kernel32.INSTANCE.CloseHandle(handle)
            }
        }

    /** 执行用户自定义命令。命令里可以用 `{action}` 占位当前动作。 */
    private suspend fun runCustomCommand(action: String): UnlockOutcome =
        withContext(Dispatchers.IO) {
            if (customCommand.isBlank()) {
                return@withContext UnlockOutcome.Failure(ErrorCodes.INTERNAL, "未配置自定义解锁命令")
            }

            val command = customCommand.replace("{action}", action)
            runCatching {
                val process = ProcessBuilder(command.split(' ').filter { it.isNotBlank() })
                    .redirectErrorStream(true)
                    .start()
                val finished = process.waitFor(
                    customCommandTimeoutMillis,
                    java.util.concurrent.TimeUnit.MILLISECONDS,
                )
                if (!finished) {
                    process.destroyForcibly()
                    error("命令执行超时（${customCommandTimeoutMillis}ms）")
                }
                val output = process.inputStream.bufferedReader().readText().trim()
                PlatformEnv.log(TAG, "自定义命令退出码=${process.exitValue()}，输出=$output")
                if (process.exitValue() != 0) error("命令退出码 ${process.exitValue()}：$output")
            }.fold(
                onSuccess = { UnlockOutcome.Success(PlatformEnv.currentTimeMillis()) },
                onFailure = { error ->
                    UnlockOutcome.Failure(ErrorCodes.INTERNAL, "自定义命令执行失败：${error.message}")
                },
            )
        }

    private fun isWindows(): Boolean =
        System.getProperty("os.name").orEmpty().startsWith("Windows")

    companion object {
        private const val TAG = "WindowsUnlockExecutor"

        /**
         * CP DLL 侧必须监听同名事件。
         * `Global\` 前缀是为了让运行在会话 0 的 Winlogon 也能访问到该内核对象。
         */
        const val UNLOCK_EVENT_PREFIX = "Global\\PawLocker.Unlock."

        private const val EVENT_MODIFY_STATE = 0x0002

        /**
         * `MOUSEEVENTF_MOVE`：相对移动鼠标。
         *
         * 这个值在 JNA 的 `WinUser` 里没有导出，所以按 Win32 文档的原始定义写死。
         * 挪动 1 像素对用户来说无感，但足以让系统认为「有人在用电脑」而点亮屏幕。
         */
        private const val MOUSEEVENTF_MOVE = 0x0001
    }
}
