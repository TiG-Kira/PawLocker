package com.kira.pawlocker.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.kira.pawlocker.core.config.WindowsUnlockStrategy
import com.kira.pawlocker.core.platform.PendingStep
import com.kira.pawlocker.core.platform.RegistrationResult
import com.kira.pawlocker.ui.components.GroupCard
import com.kira.pawlocker.ui.components.LabeledValue
import com.kira.pawlocker.ui.components.StatusPill
import com.kira.pawlocker.ui.components.StatusTone
import com.kira.pawlocker.ui.state.AdminSideController
import top.yukonga.miuix.kmp.basic.Button
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.basic.SmallTopAppBar
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.basic.TextField
import top.yukonga.miuix.kmp.theme.MiuixTheme

/**
 * 首次启动向导。
 *
 * ## 为什么要有这一步
 *
 * 「手机解锁电脑」在 Windows 上**不是**一个应用内功能：锁屏界面归 Winlogon 管，
 * 应用想插手必须把凭据提供程序注册进系统，还要放行防火墙让手机连得进来。
 * 这些动作要么需要管理员权限，要么会改变机器的安全边界 —— 都不能偷偷做。
 *
 * 所以首次启动时把这些事摆到台面上，一条条说清楚「为什么需要」，
 * 由用户自己决定每一笔要不要签字。做完之后就不再打扰：
 * 后续注册项丢失由设置页的体检结果提示，而不是每次开机都拦一道路障。
 *
 * ## 三步
 *
 * 1. [WizardStep.Welcome] —— 讲清楚这一步在改什么，给用户拒绝的机会
 * 2. [WizardStep.Strategy] —— 选解锁方式；选什么决定了第 3 步要不要注册 DLL
 * 3. [WizardStep.Register] —— 按待办清单逐项点亮
 */
@Composable
fun SetupWizardScreen(
    controller: AdminSideController,
    onFinish: () -> Unit,
) {
    var step by remember { mutableStateOf(WizardStep.Welcome) }

    Scaffold(
        topBar = {
            SmallTopAppBar(
                title = "首次启动设置",
                subtitle = step.title,
            )
        },
        bottomBar = {
            // 用 Card 而不是给 Row 上背景色：Card 的 surface 色在深浅主题下都已验证过，
            // 手写背景色容易在深色模式下和内容糊在一起
            Card(modifier = Modifier.fillMaxWidth()) {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp),
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    if (step != WizardStep.Welcome) {
                        TextButton(
                            text = "上一步",
                            onClick = { step = step.previous() },
                            modifier = Modifier.weight(1f),
                        )
                    }

                    Button(
                        onClick = {
                            when (step) {
                                // 最后一步交给调用方收尾：「完成」具体意味着什么
                                // （写配置？跳转？）不该由这一屏替它决定
                                WizardStep.Register -> onFinish()
                                else -> step = step.next()
                            }
                        },
                        colors = ButtonDefaults.buttonColorsPrimary(),
                        modifier = Modifier.weight(1f),
                    ) {
                        Text(if (step == WizardStep.Register) "完成" else "下一步")
                    }
                }
            }
        },
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(top = innerPadding.calculateTopPadding())
                .verticalScroll(rememberScrollState())
                .padding(bottom = 16.dp),
        ) {
            when (step) {
                WizardStep.Welcome -> WelcomeStep(
                    onSkip = {
                        controller.dismissSetupWizard()
                        onFinish()
                    },
                )

                WizardStep.Strategy -> StrategyStep(controller)
                WizardStep.Register -> RegisterStep(controller)
            }
        }
    }
}

private enum class WizardStep(val title: String) {
    Welcome("开始之前"),
    Strategy("选择解锁方式"),
    Register("向 Windows 注册"),
    ;

    fun next(): WizardStep = entries[(ordinal + 1).coerceAtMost(entries.lastIndex)]

    fun previous(): WizardStep = entries[(ordinal - 1).coerceAtLeast(0)]
}

// ——————————————————————————————————————————————————————————————
// 第 1 步：开始之前
// ——————————————————————————————————————————————————————————————

@Composable
private fun WelcomeStep(onSkip: () -> Unit) {
    GroupCard(title = "PawLocker 要做什么") {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = "让已配对的手机可以远程解锁这台电脑。手机发出的解锁指令经过端到端加密，" +
                    "电脑校验签名、时间戳与计数器之后才会执行。",
                style = MiuixTheme.textStyles.body2,
                color = MiuixTheme.colorScheme.onSurface,
            )
        }
    }

    GroupCard(title = "接下来会改动系统的哪些地方") {
        BulletLine("放行监听端口", "在 Windows 防火墙里加一条入站规则，只放行这一个 TCP 端口。需要管理员权限。")
        BulletLine("安装登录组件", "可选。把 PawLockerProvider.dll 注册到凭据提供程序，锁屏界面才会出现解锁磁贴。需要管理员权限。")
        BulletLine("开机自动运行", "可选。写一条注册表启动项，登录 Windows 后自动把 PawLocker 拉起来。不需要管理员权限。")

        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = "每一项都会单独弹窗征求你的同意，任何一项都可以跳过。" +
                    "跳过之后功能不全，但程序照常运行 —— 你可以在设置页里随时补上。",
                style = MiuixTheme.textStyles.footnote1,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            Spacer(Modifier.height(8.dp))
            TextButton(text = "先跳过，我自己在设置页里配", onClick = onSkip)
        }
    }
}

// ——————————————————————————————————————————————————————————————
// 第 2 步：选择解锁方式
// ——————————————————————————————————————————————————————————————

@Composable
private fun StrategyStep(controller: AdminSideController) {
    val current = controller.config.unlockStrategy

    GroupCard(title = "解锁方式") {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = "决定收到解锁指令后电脑具体做什么。之后可以在设置页里改。",
                style = MiuixTheme.textStyles.footnote1,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            Spacer(Modifier.height(12.dp))

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
                    if (strategy == current) {
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
    }

    if (current == WindowsUnlockStrategy.CREDENTIAL_PROVIDER) {
        GroupCard(title = "关于凭据提供程序") {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    text = "这是唯一能真正「完成登录」的方式：锁屏界面会出现一个 PawLocker 磁贴，" +
                        "收到手机指令后由它把本机保存的凭据提交给 Winlogon。" +
                        "仅唤醒屏幕只能点亮显示器，不解锁。",
                    style = MiuixTheme.textStyles.body2,
                    color = MiuixTheme.colorScheme.onSurface,
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    text = "下一步需要你指定 PawLockerProvider.dll 的位置。它是需要 MSVC 单独构建的" +
                        "原生产物，本仓库不提供预编译版本 —— 接口契约见仓库的 credential-provider 目录。" +
                        "拿不到 DLL 也没关系：改用「仅唤醒屏幕」或「自定义命令」同样能跑。",
                    style = MiuixTheme.textStyles.footnote2,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                )
            }
        }
    }
}

// ——————————————————————————————————————————————————————————————
// 第 3 步：注册
// ——————————————————————————————————————————————————————————————

@Composable
private fun RegisterStep(controller: AdminSideController) {
    val pending = controller.pendingSetupSteps()
    var dllPath by remember { mutableStateOf(controller.currentCredentialProviderPath()) }
    var lastOutcome by remember { mutableStateOf<RegistrationResult?>(null) }

    // 操作结果的即时反馈。放在最上面，因为用户刚点完按钮，视线还在附近
    val message = controller.registrationMessage
    if (message != null && lastOutcome != null) {
        GroupCard(title = "上一步的结果") {
            Column(modifier = Modifier.padding(16.dp)) {
                StatusPill(
                    text = when (lastOutcome) {
                        is RegistrationResult.Success -> "成功"
                        is RegistrationResult.Cancelled -> "已取消"
                        else -> "失败"
                    },
                    tone = when (lastOutcome) {
                        is RegistrationResult.Success -> StatusTone.Active
                        is RegistrationResult.Cancelled -> StatusTone.Warning
                        else -> StatusTone.Error
                    },
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    text = message,
                    style = MiuixTheme.textStyles.footnote1,
                    color = MiuixTheme.colorScheme.onSurface,
                )
                Spacer(Modifier.height(8.dp))
                TextButton(
                    text = "知道了",
                    onClick = {
                        controller.clearRegistrationMessage()
                        lastOutcome = null
                    },
                )
            }
        }
    }

    if (pending.isEmpty()) {
        GroupCard(title = "注册状态") {
            Column(modifier = Modifier.padding(16.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    StatusPill(text = "已就绪", tone = StatusTone.Active)
                    Spacer(Modifier.width(12.dp))
                    Text(
                        text = "该做的都做完了",
                        style = MiuixTheme.textStyles.main,
                        color = MiuixTheme.colorScheme.onSurface,
                    )
                }
                Spacer(Modifier.height(8.dp))
                Text(
                    text = "点「完成」进入管理页，在那里生成配对码让手机扫码。" +
                        "端口 ${controller.config.listenPort} 已经放行，手机可以直接连过来。",
                    style = MiuixTheme.textStyles.footnote1,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                )
            }
        }
        return
    }

    GroupCard(title = "还需要完成（${pending.size} 项）") {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = "逐项点一下就好。每一项都会弹 UAC，需要你在系统弹窗上点「是」。" +
                    "不想现在做的可以直接跳过，之后在设置页里补。",
                style = MiuixTheme.textStyles.footnote1,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
        }
    }

    pending.forEach { item ->
        when (item.key) {
            PendingStep.KEY_FIREWALL -> FirewallStep(
                item = item,
                port = controller.config.listenPort,
                onRun = {
                    lastOutcome = controller.ensureFirewallRule()
                },
            )

            PendingStep.KEY_CREDENTIAL_PROVIDER -> CredentialProviderStep(
                item = item,
                dllPath = dllPath,
                onDllPathChange = { dllPath = it },
                onRun = {
                    lastOutcome = controller.registerCredentialProvider(dllPath)
                },
            )

            else -> GenericStep(item)
        }
    }

    GroupCard(title = "本机信息") {
        LabeledValue("监听端口", controller.config.listenPort.toString())
        LabeledValue("解锁方式", controller.config.unlockStrategy.displayName)
        controller.registrationState.executablePath?.let { path ->
            LabeledValue("程序路径", path)
        }
    }
}

@Composable
private fun FirewallStep(
    item: PendingStep,
    port: Int,
    onRun: () -> Unit,
) {
    GroupCard(title = item.title) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = item.detail,
                style = MiuixTheme.textStyles.body2,
                color = MiuixTheme.colorScheme.onSurface,
            )
            Spacer(Modifier.height(8.dp))
            Text(
                text = "不加这条规则时，手机能连上路由器也连不进这台电脑 —— " +
                    "Windows 防火墙默认会丢弃来自局域网的新连接。",
                style = MiuixTheme.textStyles.footnote2,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            Spacer(Modifier.height(12.dp))
            Button(
                onClick = onRun,
                colors = ButtonDefaults.buttonColorsPrimary(),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("放行 TCP $port")
            }
        }
    }
}

@Composable
private fun CredentialProviderStep(
    item: PendingStep,
    dllPath: String,
    onDllPathChange: (String) -> Unit,
    onRun: () -> Unit,
) {
    GroupCard(title = item.title) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = item.detail,
                style = MiuixTheme.textStyles.body2,
                color = MiuixTheme.colorScheme.onSurface,
            )
            Spacer(Modifier.height(12.dp))
            TextField(
                value = dllPath,
                onValueChange = onDllPathChange,
                label = "PawLockerProvider.dll 路径",
                useLabelAsPlaceholder = true,
                singleLine = true,
            )
            Spacer(Modifier.height(8.dp))
            Text(
                text = "这里只写注册表，**不会**把 DLL 复制到别处 —— " +
                    "往系统目录里放文件应该是你自己的决定。请先把 DLL 放到一个不会随手删掉的位置。",
                style = MiuixTheme.textStyles.footnote2,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            Spacer(Modifier.height(12.dp))
            Button(
                onClick = onRun,
                colors = ButtonDefaults.buttonColorsPrimary(),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("注册到 Windows")
            }
        }
    }
}

@Composable
private fun GenericStep(item: PendingStep) {
    GroupCard(title = item.title) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = item.detail,
                style = MiuixTheme.textStyles.body2,
                color = MiuixTheme.colorScheme.onSurface,
            )
        }
    }
}

// ——————————————————————————————————————————————————————————————
// 小部件
// ——————————————————————————————————————————————————————————————

@Composable
private fun BulletLine(title: String, detail: String) {
    Column(modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp)) {
        Text(
            text = title,
            style = MiuixTheme.textStyles.main,
            color = MiuixTheme.colorScheme.onSurface,
        )
        Spacer(Modifier.height(2.dp))
        Text(
            text = detail,
            style = MiuixTheme.textStyles.footnote2,
            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
        )
    }
}
