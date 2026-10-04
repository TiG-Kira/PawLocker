package com.kira.pawlocker.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.kira.pawlocker.core.config.AppConfig
import com.kira.pawlocker.core.crypto.DeviceIds
import com.kira.pawlocker.core.crypto.DeviceProfile
import com.kira.pawlocker.core.crypto.IdentityKeyFactory
import com.kira.pawlocker.core.crypto.PlatformCrypto
import com.kira.pawlocker.core.net.UnlockExecutor
import com.kira.pawlocker.core.platform.PlatformEnv
import com.kira.pawlocker.core.trust.FileTrustStore
import com.kira.pawlocker.core.trust.TrustRecord
import com.kira.pawlocker.ui.components.GroupCard
import com.kira.pawlocker.ui.components.LabeledValue
import com.kira.pawlocker.ui.components.StatusPill
import com.kira.pawlocker.ui.components.StatusTone
import com.kira.pawlocker.ui.platform.PlatformInfo
import com.kira.pawlocker.ui.screens.AdminScreen
import com.kira.pawlocker.ui.screens.DeviceDetailScreen
import com.kira.pawlocker.ui.screens.DeviceListScreen
import com.kira.pawlocker.ui.screens.LoginWindowScreen
import com.kira.pawlocker.ui.screens.PairingScreen
import com.kira.pawlocker.ui.screens.SetupWizardScreen
import com.kira.pawlocker.ui.state.AdminSideController
import com.kira.pawlocker.ui.state.DeviceSideController
import com.kira.pawlocker.ui.theme.PawLockerTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import top.yukonga.miuix.kmp.basic.Button
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.NavigationBar
import top.yukonga.miuix.kmp.basic.NavigationBarItem
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.basic.SmallTopAppBar
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.extended.ScreenMirroring
import top.yukonga.miuix.kmp.icon.extended.Settings
import top.yukonga.miuix.kmp.overlay.OverlayDialog
import top.yukonga.miuix.kmp.theme.MiuixTheme

/** 两端各有一把身份密钥，别名分开，避免同一台设备上装两个 App 时互相覆盖。 */
object IdentityAliases {
    const val PHONE = "pawlocker.android.identity"
    const val COMPUTER = "pawlocker.windows.identity"
}

// ——————————————————————————————————————————————————————————————
// Android 端入口
// ——————————————————————————————————————————————————————————————

/**
 * 手机端应用根。
 *
 * 这里只负责三件事，然后把控制权交给平台外壳（[shell]）：
 * 套主题、异步把身份密钥准备好、把生物识别闸门注入控制器。
 *
 * 为什么外壳要由平台传进来：Android 侧需要 `BackHandler` 与配对深链，
 * 这两者都依赖 `androidx.activity`，commonMain 引用不到。
 * 默认值给一个通用的底部双页外壳，让 desktop 目标也能编译、也方便做预览。
 *
 * 身份密钥的加载是异步的（AndroidKeyStore 生成 P-256 密钥可能要几百毫秒，
 * StrongBox 更慢），所以这里有一个短暂的准备态，而不是在组合期间做磁盘 IO。
 *
 * @param shell 拿到就绪的控制器之后要渲染的界面
 */
@Composable
fun PhoneApp(
    profile: DeviceProfile,
    shell: @Composable (DeviceSideController) -> Unit = { PhoneShell(it) },
) {
    PawLockerTheme {
        val scope = rememberCoroutineScope()
        var controller by remember { mutableStateOf<DeviceSideController?>(null) }
        var fatalError by remember { mutableStateOf<String?>(null) }

        LaunchedEffect(Unit) {
            runCatching {
                withContext(Dispatchers.Default) {
                    val identity = IdentityKeyFactory.loadOrCreate(IdentityAliases.PHONE)
                    DeviceSideController(identity, FileTrustStore(), profile, scope)
                }
            }.onSuccess { created ->
                created.refresh()
                controller = created
            }.onFailure { error ->
                fatalError = error.message ?: "身份密钥初始化失败"
            }
        }

        // 闸门在这里注入一次即可 —— 平台外壳拿到的是同一个控制器实例，
        // 不需要（也不应该）在两边各建一个 BiometricPrompt
        val gate = com.kira.pawlocker.ui.platform.rememberBiometricGate()

        LaunchedEffect(controller, gate) {
            controller?.biometricGateProvider = { gate }
        }

        val current = controller
        when {
            fatalError != null -> StartupFailure(fatalError!!)
            current == null -> LoadingScreen("正在准备安全环境…")
            else -> shell(current)
        }
    }
}

@Composable
private fun PhoneShell(controller: DeviceSideController) {
    var tab by remember { mutableStateOf(PhoneTab.Devices) }
    var route by remember { mutableStateOf<PhoneRoute>(PhoneRoute.Root) }

    when (val current = route) {
        is PhoneRoute.Detail -> {
            DeviceDetailScreen(
                record = current.record,
                controller = controller,
                onBack = { route = PhoneRoute.Root },
            )
            return
        }

        is PhoneRoute.Pairing -> {
            PairingScreen(
                controller = controller,
                onBack = { route = PhoneRoute.Root },
            )
            return
        }

        PhoneRoute.Root -> Unit
    }

    Scaffold(
        bottomBar = {
            NavigationBar {
                NavigationBarItem(
                    selected = tab == PhoneTab.Devices,
                    onClick = { tab = PhoneTab.Devices },
                    icon = MiuixIcons.ScreenMirroring,
                    label = "设备",
                )
                NavigationBarItem(
                    selected = tab == PhoneTab.Settings,
                    onClick = { tab = PhoneTab.Settings },
                    icon = MiuixIcons.Settings,
                    label = "设置",
                )
            }
        },
    ) { innerPadding ->
        Box(modifier = Modifier.fillMaxSize().padding(bottom = innerPadding.calculateBottomPadding())) {
            when (tab) {
                PhoneTab.Devices -> DeviceListScreen(
                    controller = controller,
                    message = controller.lastMessage,
                    onDismissMessage = { controller.clearMessage() },
                    onAddComputer = { route = PhoneRoute.Pairing },
                    onOpenDevice = { record -> route = PhoneRoute.Detail(record) },
                    onOpenSettings = { tab = PhoneTab.Settings },
                )

                PhoneTab.Settings -> PhoneSettingsScreen(controller)
            }
        }
    }
}

private sealed interface PhoneRoute {
    data object Root : PhoneRoute
    data class Detail(val record: TrustRecord) : PhoneRoute
    data object Pairing : PhoneRoute
}

private enum class PhoneTab { Devices, Settings }

@Composable
private fun PhoneSettingsScreen(controller: DeviceSideController) {
    var confirmWipe by remember { mutableStateOf(false) }

    Scaffold(
        topBar = { SmallTopAppBar(title = "设置", subtitle = PlatformInfo.deviceModel) },
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(top = innerPadding.calculateTopPadding())
                .verticalScroll(rememberScrollState()),
        ) {
            GroupCard(title = "本机身份") {
                LabeledValue("设备名", controller.identityFingerprintLabel())
                LabeledValue("设备 ID", DeviceIds.fromPublicKey(controller.rawPublicKey()).take(22) + "…")
                LabeledValue("平台", PlatformInfo.displayName)
                LabeledValue("系统", PlatformInfo.systemDescription)
                LabeledValue("密码学后端", PlatformCrypto.backendName)
                LabeledValue("版本", PlatformInfo.version)
            }

            GroupCard(title = "安全说明") {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "• 本机私钥保存在系统密钥库中，不会以明文落盘\n" +
                            "• 每次解锁都必须通过指纹 / 面容 / 设备 PIN 验证\n" +
                            "• 与电脑之间使用 AES-256-GCM 端到端加密，密钥在配对时协商\n" +
                            "• 每条指令都带单调计数器与时间戳，重放指令会被拒绝",
                        style = MiuixTheme.textStyles.body2,
                        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                    )
                }
            }

            GroupCard(title = "危险操作") {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "重置本机身份会删除身份密钥与全部配对记录。" +
                            "之后需要在每台电脑上重新配对，且旧配对记录需要手动清理。",
                        style = MiuixTheme.textStyles.footnote1,
                        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                    )
                    Spacer(Modifier.height(12.dp))
                    Button(
                        onClick = { confirmWipe = true },
                        colors = ButtonDefaults.buttonColors(),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text("重置本机身份")
                    }
                }
            }

            Spacer(Modifier.height(24.dp))
        }
    }

    if (confirmWipe) {
        OverlayDialog(
            title = "确认重置？",
            summary = "该操作不可撤销。重置后所有电脑都需要重新配对。",
            show = true,
            onDismissRequest = { confirmWipe = false },
        ) {
            Column {
                androidx.compose.foundation.layout.Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    TextButton(
                        text = "取消",
                        onClick = { confirmWipe = false },
                        modifier = Modifier.weight(1f),
                    )
                    TextButton(
                        text = "重置",
                        onClick = {
                            controller.wipeIdentity()
                            confirmWipe = false
                        },
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.textButtonColorsPrimary(),
                    )
                }
            }
        }
    }
}

// ——————————————————————————————————————————————————————————————
// Windows 端入口
// ——————————————————————————————————————————————————————————————

/**
 * 电脑端应用根。
 *
 * @param loginWindowOnly 为 true 时只渲染登录窗口（用于从锁屏/托盘单独唤起一扇小窗）
 * @param createUnlockExecutor 由桌面模块注入，因为具体的解锁执行器依赖 JNA 等平台能力
 */
@Composable
fun ComputerApp(
    profile: DeviceProfile,
    loginWindowOnly: Boolean,
    createUnlockExecutor: (AppConfig) -> UnlockExecutor,
) {
    PawLockerTheme {
        // ⚠️ 这里**必须**用应用级 scope，不能用 rememberCoroutineScope()。
        //
        // rememberCoroutineScope 绑在组合生命周期上：重组导致它重建时，
        // 里面挂起的协程会被一起取消。而配对确认正是「挂起等人点按钮」的操作 ——
        // scope 被取消 = deferred 永远等不到 = 协议层 60 秒后静默超时断开，
        // 两端都没有任何提示。
        //
        // controller 的生命周期必须比任何一个页面都长，所以这个 scope
        // 只在 ComputerApp 整体离开组合时才取消。
        val appScope = rememberCoroutineScope()
        var controller by remember { mutableStateOf<AdminSideController?>(null) }
        var fatalError by remember { mutableStateOf<String?>(null) }

        LaunchedEffect(Unit) {
            runCatching {
                withContext(Dispatchers.Default) {
                    val identity = IdentityKeyFactory.loadOrCreate(IdentityAliases.COMPUTER)
                    AdminSideController(identity, FileTrustStore(), profile, appScope)
                }
            }.onSuccess { created ->
                created.unlockExecutor = createUnlockExecutor(created.config)
                created.initialize()
                controller = created
            }.onFailure { error ->
                fatalError = error.message ?: "身份密钥初始化失败"
            }
        }

        val current = controller
        when {
            fatalError != null -> StartupFailure(fatalError!!)
            current == null -> LoadingScreen("正在启动服务…")

            // 登录窗口是「锁屏时被唤起的小窗」，不该在那时候拦一道首次设置
            loginWindowOnly -> LoginWindowScreen(controller = current, onClose = { })

            // 首次启动：先把系统级注册做完再进管理页。
            // 完成后 completeSetupWizard() 会把 setupCompleted 置位，
            // needsSetupWizard 随之变 false，这里自动切换到管理页 —— 不需要额外的导航状态
            current.needsSetupWizard -> SetupWizardScreen(
                controller = current,
                onFinish = { current.completeSetupWizard() },
            )

            else -> AdminScreen(controller = current, onOpenLoginWindow = { })
        }
    }
}

// ——————————————————————————————————————————————————————————————
// 共用落地页
// ——————————————————————————————————————————————————————————————

@Composable
private fun LoadingScreen(text: String) {
    Scaffold { innerPadding ->
        Box(
            modifier = Modifier.fillMaxSize().padding(innerPadding),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                text = text,
                style = MiuixTheme.textStyles.body1,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
        }
    }
}

@Composable
private fun StartupFailure(message: String) {
    Scaffold { innerPadding ->
        Box(
            modifier = Modifier.fillMaxSize().padding(innerPadding),
            contentAlignment = Alignment.Center,
        ) {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.padding(32.dp),
            ) {
                StatusPill(text = "启动失败", tone = StatusTone.Error)
                Spacer(Modifier.height(16.dp))
                Text(
                    text = message,
                    style = MiuixTheme.textStyles.body2,
                    color = MiuixTheme.colorScheme.onBackground,
                    textAlign = TextAlign.Center,
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    text = "如果反复出现，请查看日志（${PlatformEnv.dataDir}）。",
                    style = MiuixTheme.textStyles.footnote2,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                    textAlign = TextAlign.Center,
                )
            }
        }
    }
}

// ——————————————————————————————————————————————————————————————
// 小工具
// ——————————————————————————————————————————————————————————————

private fun DeviceSideController.rawPublicKey(): ByteArray = identity.publicKey

private fun DeviceSideController.identityFingerprintLabel(): String =
    "设备指纹 " + DeviceIds.fromPublicKey(identity.publicKey).take(12)
