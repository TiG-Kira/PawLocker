package com.kira.pawlocker.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.kira.pawlocker.core.crypto.Base64Url
import com.kira.pawlocker.core.crypto.DeviceIds
import com.kira.pawlocker.core.platform.PlatformEnv
import com.kira.pawlocker.core.protocol.Protocol
import com.kira.pawlocker.ui.components.GroupCard
import com.kira.pawlocker.ui.components.LabeledValue
import com.kira.pawlocker.ui.components.StatusPill
import com.kira.pawlocker.ui.components.StatusTone
import com.kira.pawlocker.ui.platform.PlatformInfo
import com.kira.pawlocker.ui.platform.rememberBiometricGate
import com.kira.pawlocker.ui.state.DeviceSideController
import com.kira.pawlocker.ui.state.UiMessage
import top.yukonga.miuix.kmp.basic.Button
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.basic.SmallTopAppBar
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.extended.Back
import top.yukonga.miuix.kmp.overlay.OverlayDialog
import top.yukonga.miuix.kmp.theme.MiuixTheme

/**
 * Android 端「设置与关于」。
 *
 * 手机端没有太多可配的东西 —— 端口、穿透、解锁方式全在电脑那边。
 * 这里主要回答两个问题：**我是谁**（身份指纹）和 **本机安全吗**（生物识别状态）。
 */
@Composable
fun AndroidSettingsScreen(
    controller: DeviceSideController,
    message: UiMessage?,
    onDismissMessage: () -> Unit,
    onBack: () -> Unit,
) {
    val gate = rememberBiometricGate()
    var confirmReset by remember { mutableStateOf(false) }

    val identity = controller.identity
    val deviceId = remember(identity) { DeviceIds.fromPublicKey(identity.publicKey) }

    Scaffold(
        topBar = {
            SmallTopAppBar(
                title = "设置与关于",
                subtitle = PlatformInfo.deviceModel,
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            imageVector = MiuixIcons.Back,
                            contentDescription = "返回",
                            tint = MiuixTheme.colorScheme.onBackground,
                        )
                    }
                },
            )
        },
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(top = innerPadding.calculateTopPadding())
                .verticalScroll(rememberScrollState()),
        ) {
            GroupCard(title = "本机身份") {
                LabeledValue("设备名称", PlatformInfo.deviceModel.ifBlank { "Android 手机" })
                LabeledValue("系统", PlatformInfo.systemDescription)
                LabeledValue("应用版本", PlatformInfo.version)
                LabeledValue("设备指纹", deviceId)
                Row(
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
                ) {
                    Text(
                        text = "密钥保护",
                        style = MiuixTheme.textStyles.body2,
                        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                        modifier = Modifier.weight(1f),
                    )
                    StatusPill(
                        text = if (identity.hardwareBacked) "硬件密钥库" else "软件密钥（已加密）",
                        tone = if (identity.hardwareBacked) StatusTone.Active else StatusTone.Warning,
                    )
                }
                Text(
                    text = if (identity.hardwareBacked) {
                        "身份私钥保存在 AndroidKeyStore 中，由 TEE / StrongBox 保护，不可导出 —— " +
                            "即使拿到 root 权限也读不出私钥本体。"
                    } else {
                        "本机系统版本较低，身份私钥以软件方式生成后由 AndroidKeyStore 包裹存放。" +
                            "安全性依然远高于明文存储，但不如硬件密钥。"
                    },
                    style = MiuixTheme.textStyles.footnote2,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
                )
            }

            GroupCard(title = "安全") {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
                ) {
                    Text(
                        text = "解锁验证方式",
                        style = MiuixTheme.textStyles.body2,
                        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                        modifier = Modifier.weight(1f),
                    )
                    StatusPill(
                        text = if (gate.isAvailable) gate.description else "不可用",
                        tone = if (gate.isAvailable) StatusTone.Active else StatusTone.Error,
                    )
                }
                LabeledValue("已匹配电脑", "${controller.devices.size} 台")
                LabeledValue("协议版本", "v${Protocol.VERSION}")

                Text(
                    text = "每次解锁前都会要求本机验证。这不是可选项 —— " +
                        "手机丢了但过不了生物识别，就签不出有效的解锁指令。",
                    style = MiuixTheme.textStyles.footnote2,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
                )

                Row(
                    modifier = Modifier.fillMaxWidth().padding(16.dp),
                    horizontalArrangement = Arrangement.End,
                ) {
                    TextButton(
                        text = "清除本机全部配对",
                        onClick = { confirmReset = true },
                        enabled = controller.devices.isNotEmpty(),
                    )
                }
            }

            GroupCard(title = "数据位置") {
                LabeledValue("应用数据", PlatformEnv.dataDir)
                LabeledValue("配对记录", "trust-store.json")
                Text(
                    text = "配对密钥与信任列表都存在应用私有目录里，其它应用读不到。" +
                        "不想留痕就直接清除配对，或在系统里清空应用数据。",
                    style = MiuixTheme.textStyles.footnote2,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
                )
            }

            Spacer(Modifier.height(24.dp))
        }
    }

    if (confirmReset) {
        OverlayDialog(
            title = "清除全部配对？",
            summary = "本机将删除所有电脑的配对密钥，之后无法再解锁任何一台电脑，" +
                "需要在电脑端重新配对。此操作不可撤销。",
            show = true,
            onDismissRequest = { confirmReset = false },
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                TextButton(
                    text = "取消",
                    onClick = { confirmReset = false },
                    modifier = Modifier.weight(1f),
                )
                TextButton(
                    text = "清除",
                    onClick = {
                        controller.forgetAll()
                        confirmReset = false
                    },
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.textButtonColorsPrimary(),
                )
            }
        }
    }

    if (message != null) {
        OverlayDialog(
            title = message.title,
            summary = message.detail,
            show = true,
            onDismissRequest = onDismissMessage,
        ) {
            Button(
                onClick = onDismissMessage,
                colors = ButtonDefaults.buttonColorsPrimary(),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("知道了")
            }
        }
    }
}
