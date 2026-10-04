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
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.kira.pawlocker.core.protocol.TransportKind
import com.kira.pawlocker.ui.components.GroupCard
import com.kira.pawlocker.ui.components.StatusPill
import com.kira.pawlocker.ui.components.StatusTone
import com.kira.pawlocker.ui.platform.QrScanView
import com.kira.pawlocker.ui.state.DeviceSideController
import com.kira.pawlocker.ui.state.PairingStage
import top.yukonga.miuix.kmp.basic.Button
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.basic.SmallTopAppBar
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.basic.TextField
import top.yukonga.miuix.kmp.basic.TextFieldDefaults
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.extended.Back
import top.yukonga.miuix.kmp.icon.extended.Rename
import top.yukonga.miuix.kmp.icon.extended.Scan
import top.yukonga.miuix.kmp.overlay.OverlayDialog
import top.yukonga.miuix.kmp.theme.MiuixTheme

/**
 * Android 端「匹配新电脑」页。
 *
 * 两条路径并列，而不是把扫码藏在主路径后面：
 *  - **扫一扫**：电脑屏幕上有二维码时用，一步到位拿到 host/port/公钥/会话 ID
 *  - **手动输入**：摄像头不可用、或需要经虚拟组网/自定义地址时用
 *
 * 两条路径的安全性完全等价 —— 信任锚始终是电脑屏幕上那 6 位配对码。
 */
@Composable
fun PairingScreen(
    controller: DeviceSideController,
    onBack: () -> Unit,
) {
    var mode by remember { mutableStateOf(PairingMode.Scan) }
    val busy = controller.pairingStage == PairingStage.InProgress

    Scaffold(
        topBar = {
            SmallTopAppBar(
                title = "匹配新电脑",
                subtitle = "需要在电脑上先开启配对窗口",
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
        Box(modifier = Modifier.fillMaxSize().padding(top = innerPadding.calculateTopPadding())) {
            Column(modifier = Modifier.fillMaxSize()) {

                MethodSwitcher(
                    current = mode,
                    onSelect = { mode = it },
                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                )

                when (mode) {
                    PairingMode.Scan -> ScanPane(
                        enabled = !busy,
                        onDecoded = { raw -> controller.pairFromDeepLink(raw) },
                    )

                    PairingMode.Manual -> ManualPane(controller = controller, enabled = !busy)
                }
            }

            if (busy) {
                PairingBusyOverlay()
            }
        }
    }
}

private enum class PairingMode(val label: String) {
    Scan("扫一扫"),
    Manual("手动输入"),
}

@Composable
private fun MethodSwitcher(
    current: PairingMode,
    onSelect: (PairingMode) -> Unit,
    modifier: Modifier = Modifier,
) {
    Row(
        modifier = modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        PairingMode.entries.forEach { entry ->
            TextButton(
                text = entry.label,
                onClick = { onSelect(entry) },
                modifier = Modifier.weight(1f),
                colors = if (entry == current) {
                    ButtonDefaults.textButtonColorsPrimary()
                } else {
                    ButtonDefaults.textButtonColors()
                },
            )
        }
    }
}

@Composable
private fun ScanPane(
    enabled: Boolean,
    onDecoded: (String) -> Unit,
) {
    Column(modifier = Modifier.fillMaxSize()) {
        if (enabled) {
            QrScanView(
                onDecoded = onDecoded,
                modifier = Modifier.fillMaxWidth().height(320.dp),
            )
        } else {
            Box(
                modifier = Modifier.fillMaxWidth().height(320.dp),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    text = "正在配对，请稍候…",
                    style = MiuixTheme.textStyles.body2,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                )
            }
        }

        GroupCard(title = "操作步骤") {
            StepRow("1", "在电脑上打开 PawLocker，进入「配对」页")
            StepRow("2", "点击「添加手机」，电脑会显示二维码和 6 位配对码")
            StepRow("3", "用本机扫描二维码")
            StepRow("4", "核对手机与电脑上显示的校验图案是否一致")
        }
    }
}

@Composable
private fun StepRow(index: String, text: String) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        StatusPill(text = index, tone = StatusTone.Neutral)
        Spacer(Modifier.width(12.dp))
        Text(
            text = text,
            style = MiuixTheme.textStyles.body2,
            color = MiuixTheme.colorScheme.onSurface,
            modifier = Modifier.weight(1f),
        )
    }
}

@Composable
private fun ManualPane(
    controller: DeviceSideController,
    enabled: Boolean,
) {
    val draft = controller.manualPairing
    val codeError = draft.code.isNotEmpty() && (draft.code.length != 6 || draft.code.any { !it.isDigit() })

    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()),
    ) {
        GroupCard(title = "电脑地址") {
            Column(modifier = Modifier.padding(16.dp)) {
                TextField(
                    value = draft.host,
                    onValueChange = { value -> controller.updateManualPairing { it.copy(host = value.trim()) } },
                    label = "主机地址",
                    useLabelAsPlaceholder = true,
                    singleLine = true,
                    enabled = enabled,
                    keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                        keyboardType = androidx.compose.ui.text.input.KeyboardType.Uri,
                    ),
                )
                Spacer(Modifier.height(12.dp))
                TextField(
                    value = draft.port,
                    onValueChange = { value ->
                        controller.updateManualPairing { it.copy(port = value.filter(Char::isDigit).take(5)) }
                    },
                    label = "端口",
                    useLabelAsPlaceholder = true,
                    singleLine = true,
                    enabled = enabled,
                    keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                        keyboardType = androidx.compose.ui.text.input.KeyboardType.Number,
                    ),
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    text = "电脑端「配对」页会直接显示这两个值，" +
                        "例如 192.168.1.10:9898（局域网）或 frp.example.com:19898（内网穿透）。",
                    style = MiuixTheme.textStyles.footnote2,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                )
            }
        }

        GroupCard(title = "配对码") {
            Column(modifier = Modifier.padding(16.dp)) {
                TextField(
                    value = draft.code,
                    onValueChange = { value ->
                        controller.updateManualPairing { it.copy(code = value.filter(Char::isDigit).take(6)) }
                    },
                    label = "6 位数字",
                    useLabelAsPlaceholder = true,
                    singleLine = true,
                    enabled = enabled,
                    keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                        keyboardType = androidx.compose.ui.text.input.KeyboardType.NumberPassword,
                    ),
                    colors = if (codeError) {
                        TextFieldDefaults.textFieldColors(borderColor = MiuixTheme.colorScheme.error)
                    } else {
                        TextFieldDefaults.textFieldColors()
                    },
                )
                if (codeError) {
                    Spacer(Modifier.height(6.dp))
                    Text(
                        text = "配对码是电脑屏幕上显示的 6 位数字",
                        style = MiuixTheme.textStyles.footnote2,
                        color = MiuixTheme.colorScheme.error,
                    )
                }
            }
        }

        // 连接方式只影响「这条记录被标成什么」，不影响协议本身 ——
        // 加解密与配对校验跟走哪条链路无关，所以这里选错也不会出安全问题，
        // 最多个列表里显示得不够准确。
        GroupCard(title = "连接方式（仅用于标记）") {
            TransportKind.entries.forEach { kind ->
                Row(
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    StatusPill(
                        text = kind.displayName,
                        tone = if (kind == draft.transportKind) StatusTone.Active else StatusTone.Neutral,
                    )
                    Spacer(Modifier.width(12.dp))
                    Text(
                        text = when (kind) {
                            TransportKind.LAN -> "手机与电脑在同一 Wi-Fi / 交换机下"
                            TransportKind.OVERLAY -> "通过 Tailscale / ZeroTier 等虚拟组网"
                            TransportKind.TUNNEL -> "通过 frp 等公网反向代理"
                            TransportKind.MANUAL -> "其它自定义地址"
                        },
                        style = MiuixTheme.textStyles.footnote1,
                        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                        modifier = Modifier.weight(1f),
                    )
                    if (kind != draft.transportKind) {
                        TextButton(
                            text = "选择",
                            onClick = {
                                controller.updateManualPairing { it.copy(transportKind = kind) }
                            },
                        )
                    }
                }
            }
        }

        Card(modifier = Modifier.fillMaxWidth().padding(12.dp)) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    text = "开始之前，请确认电脑端已经点了「添加手机」。" +
                        "配对窗口只开 2 分钟，过期后需要重新生成。",
                    style = MiuixTheme.textStyles.footnote1,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                )
                Spacer(Modifier.height(12.dp))
                Button(
                    onClick = { controller.pairManually() },
                    enabled = enabled && draft.host.isNotBlank() && draft.code.length == 6,
                    colors = ButtonDefaults.buttonColorsPrimary(),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text("开始配对")
                }
            }
        }

        Spacer(Modifier.height(24.dp))
    }
}

/**
 * 配对进行中的遮罩。
 * 不做成阻塞式对话框 —— 用户可能需要在这几秒里看一眼电脑屏幕上的提示。
 */
@Composable
private fun PairingBusyOverlay() {
    OverlayDialog(
        title = "正在配对",
        summary = "已向电脑发送配对请求。如果电脑上弹出了确认框，请在电脑上点「允许」。",
        show = true,
        onDismissRequest = null,
    ) {
        Text(
            text = "这一步最长等待 60 秒",
            style = MiuixTheme.textStyles.footnote2,
            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            textAlign = TextAlign.Center,
            modifier = Modifier.fillMaxWidth(),
        )
    }
}
