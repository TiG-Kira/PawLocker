package com.kira.pawlocker.ui.screens

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
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
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
import com.kira.pawlocker.core.crypto.Sas
import com.kira.pawlocker.core.platform.PlatformEnv
import com.kira.pawlocker.core.protocol.TransportKind
import com.kira.pawlocker.core.trust.TrustRecord
import com.kira.pawlocker.ui.components.EmptyState
import com.kira.pawlocker.ui.components.GroupCard
import com.kira.pawlocker.ui.components.LabeledValue
import com.kira.pawlocker.ui.components.SasStrip
import com.kira.pawlocker.ui.components.StatusPill
import com.kira.pawlocker.ui.components.StatusTone
import com.kira.pawlocker.ui.state.DeviceSideController
import com.kira.pawlocker.ui.state.UnlockStage
import com.kira.pawlocker.ui.state.UiMessage
import top.yukonga.miuix.kmp.basic.Button
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.basic.SmallTitle
import top.yukonga.miuix.kmp.basic.SmallTopAppBar
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.extended.Add
import top.yukonga.miuix.kmp.icon.extended.Back
import top.yukonga.miuix.kmp.icon.extended.Delete
import top.yukonga.miuix.kmp.icon.extended.Info
import top.yukonga.miuix.kmp.icon.extended.Refresh
import top.yukonga.miuix.kmp.icon.extended.ScreenMirroring
import top.yukonga.miuix.kmp.icon.extended.Unlock
import top.yukonga.miuix.kmp.overlay.OverlayDialog
import top.yukonga.miuix.kmp.theme.MiuixTheme

/**
 * Android 端默认页 —— 设备页。
 *
 * 结构：
 *  - 顶部：应用名 + 本机状态
 *  - 中部：已匹配的电脑列表，每台一个卡片，卡片上有【解锁】
 *  - 底部：把「匹配新电脑」做成主操作入口
 *
 * 「解锁」是每台设备一个动作，「匹配」是全局动作 —— 这个区分很重要：
 * 匹配是把新电脑加进列表，解锁是对列表里已有的一台发指令。
 */
@Composable
fun DeviceListScreen(
    controller: DeviceSideController,
    message: UiMessage?,
    onDismissMessage: () -> Unit,
    onAddComputer: () -> Unit,
    onOpenDevice: (TrustRecord) -> Unit,
    onOpenSettings: () -> Unit,
) {
    var pendingForget by remember { mutableStateOf<TrustRecord?>(null) }
    val sasTarget = controller.pendingSasVerification

    Scaffold(
        topBar = {
            SmallTopAppBar(
                title = "设备",
                subtitle = if (controller.devices.isEmpty()) {
                    "还没有匹配任何电脑"
                } else {
                    "已匹配 ${controller.devices.size} 台电脑"
                },
                actions = {
                    IconButton(onClick = { controller.refresh() }) {
                        Icon(
                            imageVector = MiuixIcons.Refresh,
                            contentDescription = "刷新列表",
                            tint = MiuixTheme.colorScheme.onBackground,
                        )
                    }
                    IconButton(onClick = onOpenSettings) {
                        Icon(
                            imageVector = MiuixIcons.Info,
                            contentDescription = "设置与关于",
                            tint = MiuixTheme.colorScheme.onBackground,
                        )
                    }
                },
            )
        },
    ) { innerPadding ->
        Box(modifier = Modifier.fillMaxSize().padding(top = innerPadding.calculateTopPadding())) {
            if (controller.devices.isEmpty()) {
                EmptyState(
                    icon = MiuixIcons.ScreenMirroring,
                    title = "还没有匹配的电脑",
                    description = "在电脑上打开 PawLocker，进入「配对」页生成二维码，" +
                        "然后用本机扫描即可完成匹配。",
                    actionLabel = "匹配新电脑",
                    onAction = onAddComputer,
                )
            } else {
                LazyColumn(
                    modifier = Modifier.fillMaxSize(),
                    contentPadding = PaddingValues(
                        top = 4.dp,
                        bottom = innerPadding.calculateBottomPadding() + 24.dp,
                    ),
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    item {
                        SmallTitle(text = "已匹配的电脑")
                    }

                    items(controller.devices, key = { it.deviceId }) { record ->
                        ComputerCard(
                            record = record,
                            isUnlocking = controller.unlockingDeviceId == record.deviceId,
                            unlockingStage = controller.unlockingStage,
                            onUnlock = { controller.unlock(record) },
                            onDetails = { onOpenDevice(record) },
                            onForget = { pendingForget = record },
                        )
                    }

                    item {
                        Spacer(Modifier.height(8.dp))
                        Card(
                            modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp),
                            onClick = onAddComputer,
                        ) {
                            Row(
                                modifier = Modifier.fillMaxWidth().padding(16.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Icon(
                                    imageVector = MiuixIcons.Add,
                                    contentDescription = null,
                                    tint = MiuixTheme.colorScheme.primary,
                                )
                                Spacer(Modifier.width(12.dp))
                                Text(
                                    text = "匹配新电脑",
                                    style = MiuixTheme.textStyles.main,
                                    color = MiuixTheme.colorScheme.primary,
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    // ———— 配对成功后的 SAS 比对 ————
    if (sasTarget != null) {
        OverlayDialog(
            title = "确认配对",
            show = true,
            onDismissRequest = { controller.dismissSasVerification() },
        ) {
            Text(
                text = "「${sasTarget.displayName}」配对完成。请确认电脑屏幕上显示的图案与下面一致 —— " +
                    "不一致说明通信被中间人介入，请立即删除该设备并重新配对。",
                style = MiuixTheme.textStyles.body2,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            Spacer(Modifier.height(12.dp))
            SasStrip(emoji = sasOf(sasTarget))
            Spacer(Modifier.height(12.dp))
            Button(
                onClick = { controller.dismissSasVerification() },
                colors = ButtonDefaults.buttonColorsPrimary(),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("图案一致，完成")
            }
        }
    }

    // ———— 删除设备二次确认 ————
    val forgetTarget = pendingForget
    if (forgetTarget != null) {
        OverlayDialog(
            title = "删除「${forgetTarget.displayName}」？",
            summary = "删除后本机将无法再解锁这台电脑，需要到电脑端重新配对。",
            show = true,
            onDismissRequest = { pendingForget = null },
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                TextButton(
                    text = "取消",
                    onClick = { pendingForget = null },
                    modifier = Modifier.weight(1f),
                )
                TextButton(
                    text = "删除",
                    onClick = {
                        controller.forget(forgetTarget)
                        pendingForget = null
                    },
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.textButtonColorsPrimary(),
                )
            }
        }
    }

    // ———— 操作结果提示 ————
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

@Composable
private fun ComputerCard(
    record: TrustRecord,
    isUnlocking: Boolean,
    unlockingStage: UnlockStage,
    onUnlock: () -> Unit,
    onDetails: () -> Unit,
    onForget: () -> Unit,
) {
    val lastSeen = record.lastSeenAt
    val subtitle = buildString {
        append(record.model.ifBlank { "Windows 电脑" })
        if (lastSeen > 0) {
            append(" · 最近使用 ")
            append(relativeTime(lastSeen))
        } else {
            append(" · 尚未使用过")
        }
    }

    Card(modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp)) {
        Column(modifier = Modifier.fillMaxWidth().padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = MiuixIcons.ScreenMirroring,
                    contentDescription = null,
                    tint = MiuixTheme.colorScheme.primary,
                    modifier = Modifier.size(28.dp),
                )
                Spacer(Modifier.width(12.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = record.displayName,
                        style = MiuixTheme.textStyles.title4,
                        color = MiuixTheme.colorScheme.onSurface,
                    )
                    Spacer(Modifier.height(2.dp))
                    Text(
                        text = subtitle,
                        style = MiuixTheme.textStyles.footnote1,
                        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                    )
                }
            }

            Spacer(Modifier.height(12.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Button(
                    onClick = onUnlock,
                    enabled = !isUnlocking,
                    colors = ButtonDefaults.buttonColorsPrimary(),
                    modifier = Modifier.weight(1f),
                ) {
                    Icon(
                        imageVector = MiuixIcons.Unlock,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp),
                    )
                    Spacer(Modifier.width(6.dp))
                    Text(
                        text = when {
                            !isUnlocking -> "解锁"
                            unlockingStage == UnlockStage.VerifyingIdentity -> "验证身份…"
                            else -> "发送指令…"
                        },
                    )
                }
                TextButton(
                    text = "详情",
                    onClick = onDetails,
                    modifier = Modifier.weight(1f),
                )
                IconButton(onClick = onForget) {
                    Icon(
                        imageVector = MiuixIcons.Delete,
                        contentDescription = "删除该设备",
                        tint = MiuixTheme.colorScheme.error,
                    )
                }
            }
        }
    }
}

/** 设备详情页：地址列表、连通性测试、删除入口。 */
@Composable
fun DeviceDetailScreen(
    record: TrustRecord,
    controller: DeviceSideController,
    onBack: () -> Unit,
) {
    Scaffold(
        topBar = {
            SmallTopAppBar(
                title = record.displayName,
                subtitle = record.model,
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            imageVector = MiuixIcons.Back,
                            contentDescription = "返回",
                            tint = MiuixTheme.colorScheme.onBackground,
                        )
                    }
                },
                actions = {
                    IconButton(onClick = { controller.probe(record) }) {
                        Icon(
                            imageVector = MiuixIcons.Refresh,
                            contentDescription = "测试连接",
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
            GroupCard(title = "设备信息") {
                LabeledValue("名称", record.displayName)
                LabeledValue("型号", record.model)
                LabeledValue("平台", record.platform)
                LabeledValue(
                    "配对时间",
                    absoluteTime(record.pairedAt),
                )
                LabeledValue("指纹", record.deviceId.take(16) + "…")
            }

            GroupCard(title = "可达地址") {
                val endpoints = record.endpoints
                if (endpoints.isEmpty()) {
                    LabeledValue("—", "这台电脑还没有上报过可用地址")
                } else {
                    // 地址按优先级排列：局域网 → 虚拟组网 → 内网穿透
                    endpoints.sortedWith(com.kira.pawlocker.core.protocol.Endpoint.preferredOrder)
                        .forEach { endpoint ->
                            EndpointRow(endpoint.kind, endpoint.display, endpoint.label)
                        }
                }
            }

            GroupCard(title = "连通性") {
                val attempts = controller.lastAttempt
                if (attempts.isEmpty()) {
                    LabeledValue("—", "点右上角刷新按钮开始测试")
                } else {
                    attempts.forEach { attempt ->
                        Row(
                            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            StatusPill(
                                text = if (attempt.success) "可用" else "不可用",
                                tone = if (attempt.success) StatusTone.Active else StatusTone.Error,
                            )
                            Spacer(Modifier.width(12.dp))
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = attempt.endpoint.display,
                                    style = MiuixTheme.textStyles.body2,
                                    color = MiuixTheme.colorScheme.onSurface,
                                )
                                attempt.detail?.let { detail ->
                                    Text(
                                        text = detail,
                                        style = MiuixTheme.textStyles.footnote2,
                                        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                                    )
                                }
                            }
                        }
                    }
                }
            }

            Spacer(Modifier.height(24.dp))
        }
    }
}

@Composable
private fun EndpointRow(kind: TransportKind, display: String, label: String) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        StatusPill(
            text = kind.displayName,
            tone = when (kind) {
                TransportKind.LAN -> StatusTone.Active
                TransportKind.OVERLAY -> StatusTone.Neutral
                TransportKind.TUNNEL -> StatusTone.Warning
                TransportKind.MANUAL -> StatusTone.Neutral
            },
        )
        Spacer(Modifier.width(12.dp))
        Text(
            text = display,
            style = MiuixTheme.textStyles.body2,
            color = MiuixTheme.colorScheme.onSurface,
        )
        Spacer(Modifier.weight(1f))
        if (label.isNotBlank()) {
            Text(
                text = label,
                style = MiuixTheme.textStyles.footnote2,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
        }
    }
}

// ——————————————————————————————————————————————————————————————
// 小工具
// ——————————————————————————————————————————————————————————————

/**
 * SAS 从配对密钥确定性推出来，所以不需要在信任记录里另存一份。
 * 这样即使记录被篡改，也无法伪造出一组「看起来对」的图案。
 */
internal fun sasOf(record: TrustRecord): List<String> =
    runCatching { Sas.fromKey(record.resolveSecret().encKey) }.getOrDefault(listOf("❔"))

internal fun relativeTime(epochMillis: Long): String {
    val delta = PlatformEnv.currentTimeMillis() - epochMillis
    return when {
        delta < 60_000 -> "刚刚"
        delta < 3_600_000 -> "${delta / 60_000} 分钟前"
        delta < 86_400_000 -> "${delta / 3_600_000} 小时前"
        delta < 30L * 86_400_000 -> "${delta / 86_400_000} 天前"
        else -> absoluteTime(epochMillis)
    }
}

internal fun absoluteTime(epochMillis: Long): String {
    if (epochMillis <= 0) return "—"
    // 不引入 kotlinx-datetime，用平台无关的手工换算即可满足展示需求
    val totalSeconds = epochMillis / 1000
    val days = totalSeconds / 86_400
    val secondsOfDay = totalSeconds % 86_400
    // 显式转 Int：pad2() 定义在 Int 上，而上面的运算在 Long 域里
    val hour = (secondsOfDay / 3600).toInt()
    val minute = ((secondsOfDay % 3600) / 60).toInt()
    val (year, month, day) = civilFromDays(days)
    return "$year-${month.pad2()}-${day.pad2()} ${hour.pad2()}:${minute.pad2()}"
}

private fun Int.pad2(): String = toString().padStart(2, '0')

/** Howard Hinnant 的 civil_from_days 算法，纯整数运算，无时区依赖。 */
private fun civilFromDays(daysSinceEpoch: Long): Triple<Int, Int, Int> {
    val z = daysSinceEpoch + 719_468
    val era = (if (z >= 0) z else z - 146_096) / 146_097
    val doe = z - era * 146_097
    val yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365
    val y = yoe + era * 400
    val doy = doe - (365 * yoe + yoe / 4 - yoe / 100)
    val mp = (5 * doy + 2) / 153
    val d = doy - (153 * mp + 2) / 5 + 1
    val m = if (mp < 10) mp + 3 else mp - 9
    return Triple((y + if (m <= 2) 1 else 0).toInt(), m.toInt(), d.toInt())
}
