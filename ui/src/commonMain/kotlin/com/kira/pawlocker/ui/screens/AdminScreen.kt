package com.kira.pawlocker.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.kira.pawlocker.core.net.ServerEvent
import com.kira.pawlocker.core.net.ServerEventKind
import com.kira.pawlocker.core.platform.PlatformEnv
import com.kira.pawlocker.core.protocol.PairingOffer
import com.kira.pawlocker.core.trust.TrustRecord
import com.kira.pawlocker.ui.components.EmptyState
import com.kira.pawlocker.ui.components.GroupCard
import com.kira.pawlocker.ui.components.LabeledValue
import com.kira.pawlocker.ui.components.PairingCodeDisplay
import com.kira.pawlocker.ui.components.QrView
import com.kira.pawlocker.ui.components.SasStrip
import com.kira.pawlocker.ui.components.StatusPill
import com.kira.pawlocker.ui.components.StatusTone
import com.kira.pawlocker.ui.state.AdminSideController
import top.yukonga.miuix.kmp.basic.Button
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.CardDefaults
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.basic.SmallTitle
import top.yukonga.miuix.kmp.basic.SmallTopAppBar
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.extended.Phone
import top.yukonga.miuix.kmp.icon.extended.Refresh
import top.yukonga.miuix.kmp.icon.extended.Settings
import top.yukonga.miuix.kmp.icon.extended.ScreenMirroring
import top.yukonga.miuix.kmp.icon.extended.Unlock
import top.yukonga.miuix.kmp.overlay.OverlayDialog
import top.yukonga.miuix.kmp.theme.MiuixTheme

/**
 * Windows 端管理页外壳。
 *
 * 用左侧导航而不是底部导航栏：桌面窗口是横向的，
 * 把导航放在左边既符合桌面习惯，也不会挤占本就不高的内容高度。
 */
@Composable
fun AdminScreen(
    controller: AdminSideController,
    onOpenLoginWindow: () -> Unit,
) {
    var section by remember { mutableStateOf(AdminSection.TrustedPhones) }

    Scaffold(
        topBar = {
            SmallTopAppBar(
                title = "PawLocker",
                subtitle = if (controller.isServiceRunning) {
                    "监听 ${controller.config.bindAddress}:${controller.boundPort} · 已信任 ${controller.trustedPhones.size} 台手机"
                } else {
                    "服务未启动"
                },
                actions = {
                    TextButton(
                        text = if (controller.isServiceRunning) "停止服务" else "启动服务",
                        onClick = {
                            if (controller.isServiceRunning) controller.stopService()
                            else controller.startService()
                        },
                        colors = if (controller.isServiceRunning) {
                            ButtonDefaults.textButtonColors()
                        } else {
                            ButtonDefaults.textButtonColorsPrimary()
                        },
                    )
                    IconButton(onClick = onOpenLoginWindow) {
                        Icon(
                            imageVector = MiuixIcons.Unlock,
                            contentDescription = "打开登录窗口",
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
                .padding(top = innerPadding.calculateTopPadding()),
        ) {
            // 待确认的配对请求以**横幅**形式钉在所有分区顶部，而不是弹窗。
            //
            // 换成内联是被逼出来的：Miuix 的 OverlayDialog 只是往
            // LocalDialogStates 登记渲染记录，真正画它的是 MiuixPopupHost，
            // 而只有 Scaffold 调用 MiuixPopupHost。挂在任何 Scaffold 之外都会
            // 登记成功、永不渲染，且**无异常无日志** —— 手机端只能看到
            // 「等待一会儿就没反应」，协议层那边 await 到 60 秒超时。
            //
            // 内联渲染不依赖那套 CompositionLocal，看到就是真的。
            // 代价是它属于管理页：用户在首次启动向导 / 锁屏登录小窗时看不到。
            // 那两个场景下一律先回管理页（顶部横幅 + 导航红点都会提示），
            // 而不是让手机端干等。
            PendingPairingBanner(
                controller = controller,
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
            )

            Row(modifier = Modifier.fillMaxSize()) {
                AdminNav(
                    controller = controller,
                    current = section,
                    onSelect = { section = it },
                    modifier = Modifier.width(220.dp).fillMaxHeight(),
                )

                Box(modifier = Modifier.weight(1f).fillMaxHeight()) {
                    when (section) {
                        AdminSection.TrustedPhones -> TrustedPhonesSection(controller)
                        AdminSection.Pairing -> PairingSection(controller)
                        AdminSection.Activity -> ActivitySection(controller)
                        AdminSection.Settings -> AdminSettingsSection(controller)
                    }
                }
            }
        }
    }

    // ———— 手机请求配对：电脑端确认 ————
    //
    // 确认入口是 [PendingPairingBanner]（本页顶部横幅），
    // 不用弹窗 —— 原因见横幅上的注释。

    // ———— 服务错误 ————
    val error = controller.lastError
    if (error != null) {
        OverlayDialog(
            title = "服务启动失败",
            summary = error,
            show = true,
            onDismissRequest = { controller.clearError() },
        ) {
            Button(
                onClick = { controller.clearError() },
                colors = ButtonDefaults.buttonColorsPrimary(),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("知道了")
            }
        }
    }
}

/**
 * 「这台手机想配对，允许吗？」——钉在管理页顶部的一条横幅。
 *
 * ## 为什么是内联横幅而不是弹窗
 *
 * 这是被 Miuix 逼出来的。`OverlayDialog` 不自己画对话框，它只往
 * `LocalDialogStates`（`staticCompositionLocalOf`）登记一条渲染记录，
 * 真正把它画出来的是 `MiuixPopupHost` —— 而**只有 `Scaffold` 会调用
 * `MiuixPopupHost`**。所以弹窗放在任何 Scaffold 之外都会
 * **登记成功、永不渲染**，且无异常无日志：手机端只能看到
 * 「扫码后等一会儿就没反应」，协议层那边 await 到 60 秒超时断开。
 *
 * 「登记了但没人画」比「没创建」更难查 —— 前者日志里连一条线索都不留。
 *
 * 内联渲染不依赖那套 CompositionLocal，看到就是真的。
 *
 * ## 代价与补救
 *
 * 代价：它属于管理页，用户停在首次启动向导 / 锁屏登录小窗时看不到。
 * 补救：两处。导航里「配对」项带红点；本页顶部横幅在**所有分区**都显示，
 * 所以只要用户人在管理页，视线扫到顶部就知道。
 * 那两个场景下服务端仍然照常接受连接 —— 横幅一出现立刻生效，
 * 而协议层的超时是 60 秒，从生成配对码到扫码通常远小于这个窗口。
 */
@Composable
private fun PendingPairingBanner(
    controller: AdminSideController,
    modifier: Modifier = Modifier,
) {
    val pending = controller.pendingApproval ?: return

    Card(
        modifier = modifier.fillMaxWidth(),
        colors = CardDefaults.defaultColors(
            color = MiuixTheme.colorScheme.secondaryContainer,
        ),
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                StatusPill(text = "等待确认", tone = StatusTone.Warning)
                Spacer(Modifier.width(12.dp))
                Text(
                    text = "这台手机正在请求配对",
                    style = MiuixTheme.textStyles.title3,
                    color = MiuixTheme.colorScheme.onSecondaryContainer,
                    modifier = Modifier.weight(1f),
                )
            }

            Spacer(Modifier.height(10.dp))
            LabeledValue("设备名称", pending.phoneDisplayName)
            LabeledValue("型号", pending.phoneModel)
            LabeledValue("设备 ID", pending.phoneDeviceId.take(26) + "…")

            Spacer(Modifier.height(8.dp))
            Text(
                text = "确认这台手机是你本人的操作再点「允许」。允许后它将可以解锁这台电脑。",
                style = MiuixTheme.textStyles.footnote2,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )

            Spacer(Modifier.height(14.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                TextButton(
                    text = "拒绝",
                    onClick = { controller.resolveApproval(false) },
                    modifier = Modifier.weight(1f),
                )
                TextButton(
                    text = "允许配对",
                    onClick = { controller.resolveApproval(true) },
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.textButtonColorsPrimary(),
                )
            }
        }
    }
}

private enum class AdminSection(val label: String) {
    TrustedPhones("信任手机"),
    Pairing("配对"),
    Activity("运行日志"),
    Settings("设置"),
}

@Composable
private fun AdminNav(
    controller: AdminSideController,
    current: AdminSection,
    onSelect: (AdminSection) -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier.padding(horizontal = 12.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        AdminSection.entries.forEach { entry ->
            val selected = entry == current
            Card(
                modifier = Modifier.fillMaxWidth(),
                onClick = { onSelect(entry) },
                colors = if (selected) {
                    CardDefaults.defaultColors(color = MiuixTheme.colorScheme.secondaryContainer)
                } else {
                    CardDefaults.defaultColors()
                },
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Icon(
                        imageVector = when (entry) {
                            AdminSection.TrustedPhones -> MiuixIcons.Phone
                            AdminSection.Pairing -> MiuixIcons.ScreenMirroring
                            AdminSection.Activity -> MiuixIcons.Refresh
                            AdminSection.Settings -> MiuixIcons.Settings
                        },
                        contentDescription = null,
                        tint = if (selected) {
                            MiuixTheme.colorScheme.onSecondaryContainer
                        } else {
                            MiuixTheme.colorScheme.onSurfaceVariantSummary
                        },
                        modifier = Modifier.size(22.dp),
                    )
                    Spacer(Modifier.width(12.dp))
                    Text(
                        text = entry.label,
                        style = MiuixTheme.textStyles.main,
                        color = if (selected) {
                            MiuixTheme.colorScheme.onSecondaryContainer
                        } else {
                            MiuixTheme.colorScheme.onSurface
                        },
                        modifier = Modifier.weight(1f),
                    )
                    // 有手机在等确认时给导航项标红点。
                    // 顶部横幅已经够显眼，但用户此刻可能正停在「运行日志」
                    // 那一屏滚动 —— 横幅会被 viewport 边缘切掉一半。
                    if (entry == AdminSection.Pairing && controller.pendingApproval != null) {
                        StatusPill(text = "待确认", tone = StatusTone.Warning)
                    }
                }
            }
        }

        Spacer(Modifier.height(16.dp))

        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    text = "解锁方式",
                    style = MiuixTheme.textStyles.footnote2,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    text = controller.unlockStrategy.displayName,
                    style = MiuixTheme.textStyles.body2,
                    color = MiuixTheme.colorScheme.onSurface,
                )
                Spacer(Modifier.height(8.dp))
                StatusPill(
                    text = if (controller.isServiceRunning) "服务运行中" else "服务已停止",
                    tone = if (controller.isServiceRunning) StatusTone.Active else StatusTone.Error,
                )
            }
        }
    }
}

// ——————————————————————————————————————————————————————————————
// 信任手机
// ——————————————————————————————————————————————————————————————

@Composable
private fun TrustedPhonesSection(controller: AdminSideController) {
    var pendingRevoke by remember { mutableStateOf<TrustRecord?>(null) }
    var sasTarget by remember { mutableStateOf<TrustRecord?>(null) }

    if (controller.trustedPhones.isEmpty()) {
        EmptyState(
            icon = MiuixIcons.Phone,
            title = "还没有信任的手机",
            description = "切到「配对」页生成二维码，用手机扫一下就能把手机加进来。",
        )
    } else {
        LazyColumn(contentPadding = PaddingValues(bottom = 24.dp)) {
            item { SmallTitle(text = "已信任的手机") }

            items(controller.trustedPhones, key = { it.deviceId }) { record ->
                Card(modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 4.dp)) {
                    Column(modifier = Modifier.fillMaxWidth()) {
                        Row(
                            modifier = Modifier.fillMaxWidth().padding(16.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Icon(
                                imageVector = MiuixIcons.Phone,
                                contentDescription = null,
                                tint = MiuixTheme.colorScheme.primary,
                                modifier = Modifier.size(26.dp),
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
                                    text = buildString {
                                        append(record.model)
                                        append(" · 配对于 ")
                                        append(absoluteTime(record.pairedAt))
                                        if (record.lastSeenAt > 0) {
                                            append(" · 最近使用 ")
                                            append(relativeTime(record.lastSeenAt))
                                        }
                                    },
                                    style = MiuixTheme.textStyles.footnote1,
                                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                                )
                            }
                            StatusPill(
                                text = if (record.sasVerified) "已核对" else "待核对",
                                tone = if (record.sasVerified) StatusTone.Active else StatusTone.Warning,
                            )
                        }

                        Row(
                            modifier = Modifier.fillMaxWidth().padding(start = 16.dp, end = 8.dp, bottom = 8.dp),
                            horizontalArrangement = Arrangement.End,
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            TextButton(
                                text = "查看校验图案",
                                onClick = { sasTarget = record },
                            )
                            Spacer(Modifier.width(8.dp))
                            TextButton(
                                text = "移除信任",
                                onClick = { pendingRevoke = record },
                                colors = ButtonDefaults.textButtonColorsPrimary(),
                            )
                        }
                    }
                }
            }
        }
    }

    val revokeTarget = pendingRevoke
    if (revokeTarget != null) {
        OverlayDialog(
            title = "移除「${revokeTarget.displayName}」？",
            summary = "移除后这台手机将立即失去解锁能力，不需要在手机上做任何操作。",
            show = true,
            onDismissRequest = { pendingRevoke = null },
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                TextButton(
                    text = "取消",
                    onClick = { pendingRevoke = null },
                    modifier = Modifier.weight(1f),
                )
                TextButton(
                    text = "移除",
                    onClick = {
                        controller.revoke(revokeTarget)
                        pendingRevoke = null
                    },
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.textButtonColorsPrimary(),
                )
            }
        }
    }

    val sasRecord = sasTarget
    if (sasRecord != null) {
        OverlayDialog(
            title = "校验图案",
            show = true,
            onDismissRequest = { sasTarget = null },
        ) {
            Text(
                text = "「${sasRecord.displayName}」在配对时看到的就是下面这组图案。" +
                    "如果手机上显示的不是它，说明存在中间人，请立即移除该设备并重新配对。",
                style = MiuixTheme.textStyles.footnote1,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            Spacer(Modifier.height(12.dp))
            SasStrip(emoji = sasOf(sasRecord))
            Spacer(Modifier.height(12.dp))
            Button(
                onClick = { sasTarget = null },
                colors = ButtonDefaults.buttonColorsPrimary(),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("知道了")
            }
        }
    }
}

// ——————————————————————————————————————————————————————————————
// 配对
// ——————————————————————————————————————————————————————————————

@Composable
private fun PairingSection(controller: AdminSideController) {
    val offer = controller.pairingOffer

    // 顶部横幅已经显示过一次，这里只在配对区再显示一份 ——
    // 用户点开「配对」就是要处理这件事，这一屏必须是自足的，
    // 不能让人先滚回顶部才知道有请求在等。
    val pending = controller.pendingApproval

    if (offer == null) {
        Column(modifier = Modifier.fillMaxSize()) {
            if (pending != null) {
                PendingPairingCard(controller)
            }
            EmptyState(
                icon = MiuixIcons.ScreenMirroring,
                title = "尚未开启配对",
                description = "点击下方按钮生成一次性配对码与二维码，然后用手机扫描。" +
                    "配对码 2 分钟内有效，且只能被一台手机使用。",
                actionLabel = if (controller.isServiceRunning) "添加手机" else null,
                onAction = { controller.openPairingWindow() },
            )
            if (!controller.isServiceRunning) {
                Card(modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp)) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text(
                            text = "服务还没启动，先把上面的「启动服务」点一下。",
                            style = MiuixTheme.textStyles.body2,
                            color = MiuixTheme.colorScheme.error,
                        )
                    }
                }
            }
        }
        return
    }

    Column(modifier = Modifier.fillMaxSize()) {
        if (pending != null) {
            PendingPairingCard(controller)
        }
        PairingOfferView(
            offer = offer,
            onClose = { controller.closePairingWindow() },
            advertisedAddresses = controller.advertisedEndpoints()
                .map { it.display to it.kind.displayName },
        )
    }
}

/**
 * 待确认的配对请求卡片。与 [PendingPairingBanner] 共用同一份状态与动作，
 * 只是外层留白不同 —— 两处都要有是因为用户可能停在任何分区。
 */
@Composable
private fun PendingPairingCard(controller: AdminSideController) {
    val pending = controller.pendingApproval ?: return

    Card(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp),
        colors = CardDefaults.defaultColors(color = MiuixTheme.colorScheme.secondaryContainer),
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                StatusPill(text = "等待确认", tone = StatusTone.Warning)
                Spacer(Modifier.width(12.dp))
                Text(
                    text = "这台手机正在请求配对",
                    style = MiuixTheme.textStyles.title3,
                    color = MiuixTheme.colorScheme.onSecondaryContainer,
                    modifier = Modifier.weight(1f),
                )
            }

            Spacer(Modifier.height(10.dp))
            LabeledValue("设备名称", pending.phoneDisplayName)
            LabeledValue("型号", pending.phoneModel)
            LabeledValue("设备 ID", pending.phoneDeviceId.take(26) + "…")

            Spacer(Modifier.height(8.dp))
            Text(
                text = "确认这台手机是你本人的操作再点「允许」。允许后它将可以解锁这台电脑。",
                style = MiuixTheme.textStyles.footnote2,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )

            Spacer(Modifier.height(14.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                TextButton(
                    text = "拒绝",
                    onClick = { controller.resolveApproval(false) },
                    modifier = Modifier.weight(1f),
                )
                TextButton(
                    text = "允许配对",
                    onClick = { controller.resolveApproval(true) },
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.textButtonColorsPrimary(),
                )
            }
        }
    }
}

@Composable
private fun PairingOfferView(
    offer: PairingOffer,
    onClose: () -> Unit,
    advertisedAddresses: List<Pair<String, String>>,
) {
    var remaining by remember(offer.pairingId) {
        mutableStateOf((offer.expiresAt - PlatformEnv.currentTimeMillis()).coerceAtLeast(0))
    }

    // 每秒刷新倒计时；用 LaunchedEffect 而不是轮询，页面离开时自动取消
    androidx.compose.runtime.LaunchedEffect(offer.pairingId) {
        while (remaining > 0) {
            kotlinx.coroutines.delay(1000)
            remaining = (offer.expiresAt - PlatformEnv.currentTimeMillis()).coerceAtLeast(0)
        }
    }

    LazyColumn(contentPadding = PaddingValues(bottom = 24.dp)) {
        item {
            Row(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = if (remaining > 0) "配对窗口已开启" else "配对码已过期",
                    style = MiuixTheme.textStyles.title3,
                    color = MiuixTheme.colorScheme.onBackground,
                    modifier = Modifier.weight(1f),
                )
                StatusPill(
                    text = if (remaining > 0) "剩余 ${remaining / 1000} 秒" else "已过期",
                    tone = if (remaining > 0) StatusTone.Active else StatusTone.Error,
                )
            }
        }

        item { PairingCodeDisplay(code = offer.code, modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp)) }

        item { Spacer(Modifier.height(12.dp)) }

        item { QrView(content = offer.toDeepLink(), modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp)) }

        item {
            Spacer(Modifier.height(12.dp))
            GroupCard(title = "手机可用的地址") {
                if (advertisedAddresses.isEmpty()) {
                    LabeledValue("—", "当前没有可对外宣告的地址，手机将无法连接")
                } else {
                    advertisedAddresses.forEach { (address, kind) ->
                        LabeledValue(kind, address)
                    }
                }
            }
        }

        item {
            GroupCard(title = "接下来会发生什么") {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "1. 手机扫码后，本机会弹出确认框，点「允许」\n" +
                            "2. 手机上会显示一组校验图案，与本机显示的一致才说明配对安全\n" +
                            "3. 配对完成后本机会把可达地址下发给手机，无需再手动配置",
                        style = MiuixTheme.textStyles.body2,
                        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                    )
                }
            }
        }

        item {
            Spacer(Modifier.height(12.dp))
            Button(
                onClick = onClose,
                colors = ButtonDefaults.buttonColors(),
                modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp),
            ) {
                Text("关闭配对窗口")
            }
        }
    }
}

// ——————————————————————————————————————————————————————————————
// 运行日志
// ——————————————————————————————————————————————————————————————

@Composable
private fun ActivitySection(controller: AdminSideController) {
    val events = controller.events

    if (events.isEmpty()) {
        EmptyState(
            icon = MiuixIcons.Refresh,
            title = "暂无记录",
            description = "服务启动、手机连接、配对、解锁等事件都会出现在这里。",
        )
        return
    }

    LazyColumn(contentPadding = PaddingValues(bottom = 24.dp)) {
        item { SmallTitle(text = "最近 ${events.size} 条事件") }
        items(events) { event -> EventRow(event) }
    }
}

@Composable
private fun EventRow(event: ServerEvent) {
    val tone = when (event.kind) {
        ServerEventKind.UNLOCK_SUCCEEDED, ServerEventKind.DEVICE_PAIRED,
        ServerEventKind.STARTED, ServerEventKind.PAIRING_OPENED,
        -> StatusTone.Active

        ServerEventKind.UNLOCK_FAILED, ServerEventKind.ERROR,
        ServerEventKind.PAIRING_REJECTED, ServerEventKind.DEVICE_REVOKED,
        -> StatusTone.Error

        else -> StatusTone.Neutral
    }

    Row(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
        verticalAlignment = Alignment.Top,
    ) {
        Box(modifier = Modifier.width(64.dp)) {
            Text(
                text = timeOfDay(event.at),
                style = MiuixTheme.textStyles.footnote2,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
        }
        Spacer(Modifier.width(8.dp))
        StatusPill(
            text = eventLabel(event.kind),
            tone = tone,
        )
        Spacer(Modifier.width(12.dp))
        Text(
            text = event.message,
            style = MiuixTheme.textStyles.body2,
            color = MiuixTheme.colorScheme.onSurface,
            modifier = Modifier.weight(1f),
        )
    }
}

private fun eventLabel(kind: ServerEventKind): String = when (kind) {
    ServerEventKind.STARTED -> "启动"
    ServerEventKind.STOPPED -> "停止"
    ServerEventKind.CLIENT_CONNECTED -> "连接"
    ServerEventKind.PAIRING_OPENED -> "开配对"
    ServerEventKind.PAIRING_CLOSED -> "关配对"
    ServerEventKind.DEVICE_PAIRED -> "已配对"
    ServerEventKind.DEVICE_REVOKED -> "已移除"
    ServerEventKind.PAIRING_REJECTED -> "已拒绝"
    ServerEventKind.UNLOCK_SUCCEEDED -> "解锁成功"
    ServerEventKind.UNLOCK_FAILED -> "解锁失败"
    ServerEventKind.ERROR -> "错误"
}

private fun timeOfDay(epochMillis: Long): String {
    val secondsOfDay = (epochMillis / 1000) % 86_400
    val hour = secondsOfDay / 3600
    val minute = (secondsOfDay % 3600) / 60
    val second = secondsOfDay % 60
    return "${hour.toString().padStart(2, '0')}:${minute.toString().padStart(2, '0')}:" +
        second.toString().padStart(2, '0')
}
