package com.kira.pawlocker.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.kira.pawlocker.core.config.FrpcConfigWriter
import com.kira.pawlocker.core.config.OverlayProvider
import com.kira.pawlocker.core.config.WindowsCredential
import com.kira.pawlocker.core.config.WindowsCredentialStore
import com.kira.pawlocker.core.config.WindowsUnlockStrategy
import com.kira.pawlocker.core.crypto.DeviceIds
import com.kira.pawlocker.core.platform.DllSignatureStatus
import com.kira.pawlocker.ui.components.GroupCard
import com.kira.pawlocker.ui.components.LabeledValue
import com.kira.pawlocker.ui.components.StatusPill
import com.kira.pawlocker.ui.components.StatusTone
import com.kira.pawlocker.ui.platform.PlatformInfo
import top.yukonga.miuix.kmp.basic.Button
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.SmallTitle
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.basic.TextField
import top.yukonga.miuix.kmp.overlay.OverlayDialog
import top.yukonga.miuix.kmp.preference.SwitchPreference
import top.yukonga.miuix.kmp.theme.MiuixTheme

/**
 * Windows 端设置页。
 *
 * 组织方式遵循 Miuix 的分组约定：`SmallTitle` 做分节标，`Card` 装同一组设置，
 * 「有后果需要解释」的项用 [SwitchPreference] 的 summary 承载说明，
 * 而不是在标题里塞一长串字。
 */
@Composable
fun AdminSettingsSection(controller: com.kira.pawlocker.ui.state.AdminSideController) {
    val config = controller.config
    var showFrpcPreview by remember { mutableStateOf(false) }
    var showCredentialDialog by remember { mutableStateOf(false) }

    LazyColumn(contentPadding = PaddingValues(bottom = 32.dp)) {

        // ———— 监听 ————
        item {
            GroupCard(title = "监听") {
                Column(modifier = Modifier.padding(16.dp)) {
                    TextField(
                        value = config.listenPort.toString(),
                        onValueChange = { value ->
                            val port = value.filter(Char::isDigit).take(5).toIntOrNull()
                            controller.updateConfig { it.copy(listenPort = port ?: it.listenPort) }
                        },
                        label = "监听端口",
                        useLabelAsPlaceholder = true,
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    )
                    Spacer(Modifier.height(8.dp))
                    Text(
                        text = "默认 9898。改端口后需要在路由器 / frp 配置里同步修改，手机端不用改 —— " +
                            "配对时会把新端口一起下发。",
                        style = MiuixTheme.textStyles.footnote2,
                        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                    )
                }
                SwitchPreference(
                    title = "开机自动启动服务",
                    summary = "应用启动后立刻开始监听，无需手动点「启动服务」",
                    checked = config.autoStartService,
                    onCheckedChange = { value -> controller.updateConfig { it.copy(autoStartService = value) } },
                )
                SwitchPreference(
                    title = "在锁屏界面显示 PawLocker",
                    summary = "允许从 Windows 锁屏界面唤起 PawLocker 登录窗口（需要安装凭据提供程序）",
                    checked = config.enableLockScreenTile,
                    onCheckedChange = { value -> controller.updateConfig { it.copy(enableLockScreenTile = value) } },
                )
            }
        }

        // ———— 局域网 ————
        item {
            GroupCard(title = "局域网直连") {
                SwitchPreference(
                    title = "向手机宣告内网地址",
                    summary = "同一 Wi-Fi 下手机可以直连，速度最快且不经过公网",
                    checked = config.advertiseLanAddresses,
                    onCheckedChange = { value -> controller.updateConfig { it.copy(advertiseLanAddresses = value) } },
                )
                Column(modifier = Modifier.padding(16.dp)) {
                    TextField(
                        value = config.preferredLanHost,
                        onValueChange = { value -> controller.updateConfig { it.copy(preferredLanHost = value) } },
                        label = "指定内网地址（可选）",
                        useLabelAsPlaceholder = true,
                        singleLine = true,
                    )
                    Spacer(Modifier.height(8.dp))
                    Text(
                        text = "多网卡机器（虚拟机、Docker、双网卡）建议手动指定，否则会把一堆" +
                            "不可达的地址也发给手机，导致手机上连接超时变慢。",
                        style = MiuixTheme.textStyles.footnote2,
                        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                    )
                }
            }
        }

        // ———— 内网穿透 ————
        item {
            GroupCard(title = "内网穿透（frp）") {
                SwitchPreference(
                    title = "启用 frp 反向代理",
                    summary = "把本机 ${config.listenPort} 端口映射到公网服务器，手机不在同一网络时也能连上",
                    checked = config.tunnel.enabled,
                    onCheckedChange = { value ->
                        controller.updateConfig { it.copy(tunnel = it.tunnel.copy(enabled = value)) }
                    },
                )

                if (config.tunnel.enabled) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        StatusPill(
                            text = controller.tunnelStatus,
                            tone = when {
                                controller.tunnelStatus.startsWith("运行中") -> StatusTone.Active
                                controller.tunnelStatus.startsWith("未") -> StatusTone.Neutral
                                else -> StatusTone.Error
                            },
                        )
                        Spacer(Modifier.height(12.dp))

                        TunnelField(
                            label = "frps 服务器地址",
                            value = config.tunnel.serverAddr,
                            hint = "例如 frp.example.com",
                        ) { value ->
                            controller.updateConfig { it.copy(tunnel = it.tunnel.copy(serverAddr = value)) }
                        }
                        TunnelField(
                            label = "frps 控制端口",
                            value = config.tunnel.serverPort.toString(),
                            hint = "frp 默认 7000",
                            numeric = true,
                        ) { value ->
                            controller.updateConfig {
                                it.copy(tunnel = it.tunnel.copy(serverPort = value.toIntOrNull() ?: 7000))
                            }
                        }
                        TunnelField(
                            label = "auth.token",
                            value = config.tunnel.authToken,
                            hint = "与服务端 frps.toml 里的 token 一致",
                            secret = true,
                        ) { value ->
                            controller.updateConfig { it.copy(tunnel = it.tunnel.copy(authToken = value)) }
                        }
                        TunnelField(
                            label = "公网映射端口",
                            value = if (config.tunnel.remotePort > 0) config.tunnel.remotePort.toString() else "",
                            hint = "留空则与本地端口相同",
                            numeric = true,
                        ) { value ->
                            controller.updateConfig {
                                it.copy(tunnel = it.tunnel.copy(remotePort = value.toIntOrNull() ?: 0))
                            }
                        }
                        TunnelField(
                            label = "子域名（可选）",
                            value = config.tunnel.subdomain,
                            hint = "服务端配了 subDomainHost 时可填，优先于端口映射",
                        ) { value ->
                            controller.updateConfig { it.copy(tunnel = it.tunnel.copy(subdomain = value)) }
                        }
                        TunnelField(
                            label = "frpc 可执行文件",
                            value = config.tunnel.frpcPath,
                            hint = "例如 D:\\frp\\frpc.exe，留空则只生成配置不自动启动",
                        ) { value ->
                            controller.updateConfig { it.copy(tunnel = it.tunnel.copy(frpcPath = value)) }
                        }
                        SwitchPreference(
                            title = "启用 frp 传输层加密",
                            summary = "对应 frpc 的 transport.tls.enable，与协议本身的端到端加密互不冲突",
                            checked = config.tunnel.tls,
                            onCheckedChange = { value ->
                                controller.updateConfig { it.copy(tunnel = it.tunnel.copy(tls = value)) }
                            },
                        )
                        SwitchPreference(
                            title = "随应用自动启动 frpc",
                            summary = "关闭后需要自己用命令行启动 frpc",
                            checked = config.tunnel.autoStart,
                            onCheckedChange = { value ->
                                controller.updateConfig { it.copy(tunnel = it.tunnel.copy(autoStart = value)) }
                            },
                        )

                        Spacer(Modifier.height(8.dp))
                        TextButton(
                            text = "查看生成的 frpc 配置",
                            onClick = { showFrpcPreview = true },
                        )
                        TextButton(
                            text = "重启服务以应用更改",
                            onClick = { controller.restartService() },
                            colors = ButtonDefaults.textButtonColorsPrimary(),
                        )
                    }
                }
            }
        }

        // ———— 虚拟组网 ————
        item {
            GroupCard(title = "虚拟组网") {
                SwitchPreference(
                    title = "启用虚拟组网通道",
                    summary = "通过 Tailscale / ZeroTier 等把手机和电脑放进同一个虚拟网络，无需暴露公网端口",
                    checked = config.overlay.enabled,
                    onCheckedChange = { value ->
                        controller.updateConfig { it.copy(overlay = it.overlay.copy(enabled = value)) }
                    },
                )

                if (config.overlay.enabled) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        OverlayProvider.entries.forEach { provider ->
                            Row(
                                modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Text(
                                    text = provider.displayName,
                                    style = MiuixTheme.textStyles.body2,
                                    color = MiuixTheme.colorScheme.onSurface,
                                    modifier = Modifier.width(96.dp),
                                )
                                Text(
                                    text = provider.hint,
                                    style = MiuixTheme.textStyles.footnote2,
                                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                                    modifier = Modifier.weight(1f),
                                )
                                if (provider == config.overlay.provider) {
                                    StatusPill(text = "已选", tone = StatusTone.Active)
                                } else {
                                    TextButton(
                                        text = "选择",
                                        onClick = {
                                            controller.updateConfig {
                                                it.copy(overlay = it.overlay.copy(provider = provider))
                                            }
                                        },
                                    )
                                }
                            }
                        }
                        Spacer(Modifier.height(8.dp))
                        TextField(
                            value = config.overlay.virtualHost,
                            onValueChange = { value ->
                                controller.updateConfig { it.copy(overlay = it.overlay.copy(virtualHost = value)) }
                            },
                            label = "虚拟网卡地址",
                            useLabelAsPlaceholder = true,
                            singleLine = true,
                        )
                    }
                }
            }
        }

        // ———— 解锁方式 ————
        item {
            GroupCard(title = "解锁方式") {
                Column(modifier = Modifier.padding(16.dp)) {
                    WindowsUnlockStrategy.entries.forEach { strategy ->
                        Row(
                            modifier = Modifier.fillMaxWidth().padding(vertical = 10.dp),
                            verticalAlignment = Alignment.Top,
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = strategy.displayName,
                                    style = MiuixTheme.textStyles.main,
                                    color = MiuixTheme.colorScheme.onSurface,
                                )
                                Spacer(Modifier.height(2.dp))
                                Text(
                                    text = strategy.description,
                                    style = MiuixTheme.textStyles.footnote2,
                                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                                )
                            }
                            Spacer(Modifier.width(12.dp))
                            if (strategy == config.unlockStrategy) {
                                StatusPill(text = "当前", tone = StatusTone.Active)
                            } else {
                                TextButton(
                                    text = "选择",
                                    onClick = { controller.setUnlockStrategy(strategy) },
                                )
                            }
                        }
                    }
                }

                if (config.unlockStrategy == WindowsUnlockStrategy.CUSTOM_COMMAND) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        TextField(
                            value = config.customUnlockCommand,
                            onValueChange = { value ->
                                controller.updateConfig { it.copy(customUnlockCommand = value) }
                            },
                            label = "解锁命令",
                            useLabelAsPlaceholder = true,
                            singleLine = true,
                        )
                        Spacer(Modifier.height(8.dp))
                        Text(
                            text = "命令里的 {action} 会被替换成实际动作（unlock / wake / lock）。" +
                                "退出码为 0 视为成功。",
                            style = MiuixTheme.textStyles.footnote2,
                            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                        )
                    }
                }

                if (config.unlockStrategy == WindowsUnlockStrategy.CREDENTIAL_PROVIDER) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        val hasCredential = WindowsCredentialStore.exists()
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            StatusPill(
                                text = if (hasCredential) "已配置凭据" else "尚未配置凭据",
                                tone = if (hasCredential) StatusTone.Active else StatusTone.Warning,
                            )
                            Spacer(Modifier.width(12.dp))
                            TextButton(
                                text = if (hasCredential) "重新配置" else "配置凭据",
                                onClick = { showCredentialDialog = true },
                                colors = ButtonDefaults.textButtonColorsPrimary(),
                            )
                            if (hasCredential) {
                                TextButton(
                                    text = "清除",
                                    onClick = { WindowsCredentialStore.clear() },
                                )
                            }
                        }
                        Spacer(Modifier.height(8.dp))
                        Text(
                            text = "凭据由 DPAPI 以当前用户作用域加密保存，仅本机本人可解。" +
                                "同时还需要安装 PawLockerProvider.dll 并注册到 Winlogon，" +
                                "否则解锁时只会提示「未检测到登录组件」。",
                            style = MiuixTheme.textStyles.footnote2,
                            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                        )
                    }
                }
            }
        }

        // ———— 系统注册 ————
        item {
            GroupCard(title = "Windows 注册状态") {
                val state = controller.registrationState

                if (!controller.registrationSupported) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text(
                            text = "当前平台不支持管理 Windows 注册项。" +
                                "这些设置只在 Windows 电脑上才有意义。",
                            style = MiuixTheme.textStyles.body2,
                            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                        )
                    }
                } else {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text(
                            text = "这些是「手机能不能解锁这台电脑」在系统层面的前提。" +
                                "失效时通常是重装系统、清理注册表或换了网络配置导致的。",
                            style = MiuixTheme.textStyles.footnote2,
                            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                        )
                        Spacer(Modifier.height(4.dp))

                        RegistrationRow(
                            title = "入站防火墙规则",
                            ready = state.firewallRulePresent,
                            readyDetail = state.firewallRuleName,
                            missingDetail = "没有规则时，Windows 会丢弃手机发来的连接",
                            actionLabel = if (state.firewallRulePresent) "移除" else "放行",
                            onAction = {
                                if (state.firewallRulePresent) {
                                    controller.removeFirewallRule()
                                } else {
                                    controller.ensureFirewallRule()
                                }
                            },
                        )

                        RegistrationRow(
                            title = "登录组件（凭据提供程序）",
                            ready = state.credentialProviderRegistered && state.credentialProviderDllPresent,
                            readyDetail = state.credentialProviderDllPath ?: "已注册",
                            missingDetail = when {
                                state.credentialProviderRegistered -> "注册表里有记录，但 DLL 文件不在了"
                                else -> "未注册；只有「凭据提供程序」解锁方式才需要它"
                            },
                            actionLabel = if (state.credentialProviderRegistered) "注销" else "注册",
                            onAction = {
                                if (state.credentialProviderRegistered) {
                                    controller.unregisterCredentialProvider()
                                } else {
                                    controller.registerCredentialProvider(
                                        controller.currentCredentialProviderPath(),
                                    )
                                }
                            },
                        )

                        RegistrationRow(
                            title = "签名证书信任",
                            ready = state.credentialProviderSignature.isReady,
                            readyDetail = state.credentialProviderSignature.signerSubject
                                ?: "签名有效且证书已受信任",
                            missingDetail = when (state.credentialProviderSignature.status) {
                                DllSignatureStatus.NotSigned ->
                                    "DLL 未签名；先用 credential-provider 的 sign.bat 签一遍"

                                DllSignatureStatus.Untrusted ->
                                    "证书未受信任，锁屏会静默拒绝加载"

                                DllSignatureStatus.Broken ->
                                    "签名校验不通过（文件被改过或证书过期），重新签一次"

                                DllSignatureStatus.ProbeFailed ->
                                    state.credentialProviderSignature.probeError ?: "无法确认签名状态"

                                else -> "还没有可检查的 DLL"
                            },
                            actionLabel = if (state.credentialProviderSignature.signerTrustedOnMachine) {
                                "撤销信任"
                            } else {
                                "信任"
                            },
                            onAction = {
                                if (state.credentialProviderSignature.signerTrustedOnMachine) {
                                    controller.revokeDllSignerCertificate()
                                } else {
                                    controller.trustDllSignerCertificate()
                                }
                            },
                        )

                        RegistrationRow(
                            title = "开机自动运行",
                            ready = state.autoStartRegistered,
                            readyDetail = "登录 Windows 后自动启动",
                            missingDetail = "关掉后每次都得手动打开 PawLocker",
                            actionLabel = if (state.autoStartRegistered) "关闭" else "开启",
                            onAction = { controller.setSystemAutoStart(!state.autoStartRegistered) },
                        )

                        Spacer(Modifier.height(8.dp))
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            TextButton(text = "重新体检", onClick = { controller.refreshRegistration() })
                            TextButton(
                                text = "重新运行首次启动向导",
                                onClick = { controller.reopenSetupWizard() },
                                colors = ButtonDefaults.textButtonColorsPrimary(),
                            )
                        }
                    }
                }
            }
        }

        // ———— 关于 ————
        item {
            GroupCard(title = "关于") {
                LabeledValue("平台", PlatformInfo.displayName)
                LabeledValue("系统", PlatformInfo.systemDescription)
                LabeledValue("设备名", PlatformInfo.deviceModel)
                LabeledValue("本机 ID", DeviceIds.fromPublicKey(controller.identityFingerprint()).take(22) + "…")
                LabeledValue("密码学后端", controller.cryptoBackend())
                LabeledValue("版本", PlatformInfo.version)
            }
        }

        item { Spacer(Modifier.height(24.dp)) }
    }

    if (showFrpcPreview) {
        OverlayDialog(
            title = "frpc.toml",
            show = true,
            onDismissRequest = { showFrpcPreview = false },
        ) {
            Text(
                text = FrpcConfigWriter.toToml(config),
                style = MiuixTheme.textStyles.footnote2,
                color = MiuixTheme.colorScheme.onSurface,
            )
            Spacer(Modifier.height(12.dp))
            Button(
                onClick = { showFrpcPreview = false },
                colors = ButtonDefaults.buttonColorsPrimary(),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("关闭")
            }
        }
    }

    if (showCredentialDialog) {
        CredentialDialog(onDismiss = { showCredentialDialog = false })
    }

    // 注册操作（要弹 UAC 的那种）的结果反馈。
    // 用对话框而不是内联提示：这几项操作可能耗时几秒且需要用户切到系统弹窗，
    // 回来时内联提示很可能已经滚出视野了
    controller.registrationMessage?.let { message ->
        OverlayDialog(
            title = "操作结果",
            show = true,
            onDismissRequest = { controller.clearRegistrationMessage() },
        ) {
            Text(
                text = message,
                style = MiuixTheme.textStyles.body2,
                color = MiuixTheme.colorScheme.onSurface,
            )
            Spacer(Modifier.height(16.dp))
            Button(
                onClick = { controller.clearRegistrationMessage() },
                colors = ButtonDefaults.buttonColorsPrimary(),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("知道了")
            }
        }
    }
}

@Composable
private fun TunnelField(
    label: String,
    value: String,
    hint: String,
    numeric: Boolean = false,
    secret: Boolean = false,
    onChange: (String) -> Unit,
) {
    Column(modifier = Modifier.fillMaxWidth().padding(bottom = 12.dp)) {
        TextField(
            value = value,
            onValueChange = { raw -> onChange(if (numeric) raw.filter(Char::isDigit) else raw) },
            label = label,
            useLabelAsPlaceholder = true,
            singleLine = true,
            visualTransformation = if (secret) {
                PasswordVisualTransformation()
            } else {
                androidx.compose.ui.text.input.VisualTransformation.None
            },
            keyboardOptions = KeyboardOptions(
                keyboardType = if (numeric) KeyboardType.Number else KeyboardType.Uri,
            ),
        )
        Spacer(Modifier.height(4.dp))
        Text(
            text = hint,
            style = MiuixTheme.textStyles.footnote2,
            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
        )
    }
}

/**
 * 一行「系统注册项」的体检结果 + 一个补救动作。
 *
 * [ready] 为真时按钮是「撤销」性质的（移除规则 / 注销组件），
 * 为假时是「补做」。把撤销也放在这里，是因为「注册了但想收回」是个真实需求 ——
 * 只在向导里提供正向操作，用户就只能去手动改注册表。
 */
@Composable
private fun RegistrationRow(
    title: String,
    ready: Boolean,
    readyDetail: String,
    missingDetail: String,
    actionLabel: String,
    onAction: () -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = title,
                style = MiuixTheme.textStyles.main,
                color = MiuixTheme.colorScheme.onSurface,
            )
            Spacer(Modifier.height(2.dp))
            Text(
                text = if (ready) readyDetail else missingDetail,
                style = MiuixTheme.textStyles.footnote2,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
        }
        Spacer(Modifier.width(12.dp))
        StatusPill(
            text = if (ready) "已就绪" else "待处理",
            tone = if (ready) StatusTone.Active else StatusTone.Warning,
        )
        Spacer(Modifier.width(8.dp))
        TextButton(text = actionLabel, onClick = onAction)
    }
}

/**
 * Windows 凭据配置。密码只进不出 —— 读回来时只显示「已配置」，
 * 不提供「查看」，避免肩窥。
 */
@Composable
private fun CredentialDialog(onDismiss: () -> Unit) {
    val existing = remember { WindowsCredentialStore.load() }
    var userName by remember { mutableStateOf(existing?.userName.orEmpty()) }
    var domain by remember { mutableStateOf(existing?.domain ?: ".") }
    var password by remember { mutableStateOf("") }

    OverlayDialog(
        title = "Windows 登录凭据",
        show = true,
        onDismissRequest = onDismiss,
    ) {
        Column {
            Text(
                text = "PawLocker 会把这组凭据交给凭据提供程序，用来在锁屏界面完成登录。" +
                    "凭据经 DPAPI 加密，只有当前 Windows 用户能解开。",
                style = MiuixTheme.textStyles.footnote2,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            Spacer(Modifier.height(12.dp))
            TextField(
                value = userName,
                onValueChange = { userName = it },
                label = "用户名",
                useLabelAsPlaceholder = true,
                singleLine = true,
            )
            Spacer(Modifier.height(8.dp))
            TextField(
                value = domain,
                onValueChange = { domain = it },
                label = "域（本地账户填 .）",
                useLabelAsPlaceholder = true,
                singleLine = true,
            )
            Spacer(Modifier.height(8.dp))
            TextField(
                value = password,
                onValueChange = { password = it },
                label = if (existing != null) "密码（留空则保留原值）" else "密码",
                useLabelAsPlaceholder = true,
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            )
        }

        Spacer(Modifier.height(16.dp))
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            TextButton(text = "取消", onClick = onDismiss, modifier = Modifier.weight(1f))
            TextButton(
                text = "保存",
                onClick = {
                    val effectivePassword = password.ifBlank { existing?.password.orEmpty() }
                    if (userName.isNotBlank() && effectivePassword.isNotBlank()) {
                        WindowsCredentialStore.save(
                            WindowsCredential(
                                userName = userName.trim(),
                                domain = domain.trim().ifBlank { "." },
                                password = effectivePassword,
                            ),
                        )
                        onDismiss()
                    }
                },
                modifier = Modifier.weight(1f),
                colors = ButtonDefaults.textButtonColorsPrimary(),
            )
        }
    }
}
