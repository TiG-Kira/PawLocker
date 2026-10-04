package com.kira.pawlocker.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.kira.pawlocker.ui.components.StatusPill
import com.kira.pawlocker.ui.components.StatusTone
import com.kira.pawlocker.ui.platform.PlatformInfo
import com.kira.pawlocker.ui.state.AdminSideController
import top.yukonga.miuix.kmp.basic.Button
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.basic.SmallTopAppBar
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.extended.Lock
import top.yukonga.miuix.kmp.icon.extended.ScreenMirroring
import top.yukonga.miuix.kmp.icon.extended.Unlock
import top.yukonga.miuix.kmp.theme.MiuixTheme

/**
 * Windows 端「登录窗口」。
 *
 * 这是登录页面上被唤起的那一扇窗。它的职责不是自己判断谁能登录 ——
 * 它只是把「请用手机确认」这件事摆到用户面前，然后等 [AdminSideController]
 * 背后的服务收到一条校验通过的解锁指令。
 *
 * 窗口做得很小、居中最前，因为它要和 Windows 锁屏界面抢注意力：
 * 用户此刻的注意力在手机上，屏幕上只要有一个明确的「在等」的反馈就够。
 *
 * ## 与真实锁屏的关系
 *
 * 这个窗口本身**不替代** Winlogon。要让它出现在真正的锁屏界面上，
 * 需要把它做成 UIAccess 应用（需代码签名），或走 PawLockerProvider.dll
 * 的凭据提供程序路径。两条路径的说明见 `docs/01-architecture.md`。
 * 在未安装 CP 的机器上，这个窗口仍然可用作「应用内二次确认」的入口。
 */
@Composable
fun LoginWindowScreen(
    controller: AdminSideController,
    onClose: () -> Unit,
) {
    var stage by remember { mutableStateOf(LoginStage.WaitingForPhone) }
    var detail by remember { mutableStateOf<String?>(null) }
    var lastHandledUnlockAt by remember { mutableStateOf(controller.lastUnlockAt) }

    // 监听「最近一次成功解锁」。控制器每次成功解锁都会更新 lastUnlockAt，
    // 这里只处理「比上次看到的时间更新」的那一次，避免重复触发。
    LaunchedEffect(controller.lastUnlockAt) {
        val current = controller.lastUnlockAt
        if (current != null && current != lastHandledUnlockAt) {
            lastHandledUnlockAt = current
            stage = LoginStage.Succeeded
        }
    }

    Scaffold(
        topBar = {
            SmallTopAppBar(
                title = "PawLocker 登录",
                subtitle = PlatformInfo.deviceModel,
                actions = {
                    TextButton(text = "关闭", onClick = onClose)
                },
            )
        },
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(top = innerPadding.calculateTopPadding())
                .padding(horizontal = 24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {
            Icon(
                imageVector = when (stage) {
                    LoginStage.WaitingForPhone -> MiuixIcons.ScreenMirroring
                    LoginStage.Succeeded -> MiuixIcons.Unlock
                    LoginStage.Failed -> MiuixIcons.Lock
                },
                contentDescription = null,
                tint = when (stage) {
                    LoginStage.WaitingForPhone -> MiuixTheme.colorScheme.primary
                    LoginStage.Succeeded -> MiuixTheme.colorScheme.primary
                    LoginStage.Failed -> MiuixTheme.colorScheme.error
                },
                modifier = Modifier.size(64.dp),
            )

            Spacer(Modifier.height(20.dp))

            Text(
                text = when (stage) {
                    LoginStage.WaitingForPhone -> "请在手机上确认"
                    LoginStage.Succeeded -> "已解锁"
                    LoginStage.Failed -> "解锁未完成"
                },
                style = MiuixTheme.textStyles.title2,
                color = MiuixTheme.colorScheme.onBackground,
                textAlign = TextAlign.Center,
            )

            Spacer(Modifier.height(10.dp))

            Text(
                text = when (stage) {
                    LoginStage.WaitingForPhone ->
                        "打开手机上的 PawLocker，在设备列表里点「解锁」，然后完成指纹或 PIN 验证。"

                    LoginStage.Succeeded ->
                        "手机指令已通过校验，Windows 会话可以正常使用。"

                    LoginStage.Failed ->
                        detail ?: "请稍后重试，或在电脑上查看运行日志。"
                },
                style = MiuixTheme.textStyles.body2,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                textAlign = TextAlign.Center,
            )

            Spacer(Modifier.height(24.dp))

            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.fillMaxWidth().padding(16.dp)) {
                    InfoLine(
                        label = "服务状态",
                        value = if (controller.isServiceRunning) {
                            "运行中 · ${controller.config.bindAddress}:${controller.boundPort}"
                        } else {
                            "未启动"
                        },
                        tone = if (controller.isServiceRunning) StatusTone.Active else StatusTone.Error,
                    )
                    Spacer(Modifier.height(10.dp))
                    InfoLine(
                        label = "解锁方式",
                        value = controller.unlockStrategy.displayName,
                        tone = StatusTone.Neutral,
                    )
                    Spacer(Modifier.height(10.dp))
                    InfoLine(
                        label = "信任手机",
                        value = "${controller.trustedPhones.size} 台",
                        tone = StatusTone.Neutral,
                    )
                }
            }

            Spacer(Modifier.height(20.dp))

            when (stage) {
                LoginStage.WaitingForPhone -> {
                    TextButton(
                        text = "取消",
                        onClick = onClose,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }

                LoginStage.Succeeded -> {
                    Button(
                        onClick = onClose,
                        colors = ButtonDefaults.buttonColorsPrimary(),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text("完成")
                    }
                }

                LoginStage.Failed -> {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        TextButton(
                            text = "关闭",
                            onClick = onClose,
                            modifier = Modifier.weight(1f),
                        )
                        TextButton(
                            text = "重试",
                            onClick = {
                                detail = null
                                stage = LoginStage.WaitingForPhone
                            },
                            modifier = Modifier.weight(1f),
                            colors = ButtonDefaults.textButtonColorsPrimary(),
                        )
                    }
                }
            }

            Spacer(Modifier.height(16.dp))

            Text(
                text = "提示：手机端到电脑端全程 AES-256-GCM 端到端加密，" +
                    "且每条指令都带一次性计数器，重放无效。",
                style = MiuixTheme.textStyles.footnote2,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                textAlign = TextAlign.Center,
            )
        }
    }
}

@Composable
private fun InfoLine(label: String, value: String, tone: StatusTone) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = label,
            style = MiuixTheme.textStyles.body2,
            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            modifier = Modifier.width(88.dp),
        )
        StatusPill(text = value, tone = tone)
    }
}

private enum class LoginStage {
    WaitingForPhone,
    Succeeded,
    Failed,
}
