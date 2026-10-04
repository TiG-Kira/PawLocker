package com.kira.pawlocker.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.kira.pawlocker.ui.state.AdminSideController
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.overlay.OverlayDialog
import top.yukonga.miuix.kmp.theme.MiuixTheme

/**
 * 「允许这台手机配对？」确认框。**每个带 Scaffold 的页面都要自己调一次**。
 *
 * ## 为什么是「每页一份」而不是「全局挂一份」
 *
 * 上一轮的教训是两层的，缺一不可：
 *
 * 1. 弹窗只挂在 `AdminScreen` 里 → 用户停在首次启动向导 / 锁屏登录小窗时，
 *    组件根本不被创建，协议层 `await()` 静默挂到 60 秒超时。
 *    对策：状态提到 controller（全局唯一），每个页面都渲染它。
 *
 * 2. 弹窗提到 `ComputerApp` 顶层（仍不在任何 Scaffold 里）→ Miuix 的
 *    `OverlayDialog` 只是往 `LocalDialogStates` 这个 CompositionLocal 登记渲染记录，
 *    真正把它画出来的是 `MiuixPopupHost`，而**只有 `Scaffold` 会调用 MiuixPopupHost**。
 *    于是登记成功、永不渲染：没有异常、没有日志、手机端照常超时。
 *    `MiuixPopupHost` 本身是 Miuix 的 internal 函数，外部调不到。
 *    对策：只能回到「每个 Scaffold 内部」渲染。
 *
 * 两层的症状一模一样（都表现为「PC 端收不到允许窗口」），
 * 所以第 1 层修好后第 2 层才暴露出来 —— 这类 bug 只靠读代码很难一次看全，
 * 必须真机跑一遍。
 *
 * ## 为什么状态放全局、组件可以有多份
 *
 * 「需要人点头」的挂起操作在协议层是**唯一一个** [AdminSideController.pendingApproval]，
 * 而它对应 `LockerServer` 里一个挂起的 `CompletableDeferred`。多渲染几份组件不��
 * 产生多个待确认请求 —— 都读同一个状态，点「允许」都走同一个 `resolveApproval`，
 * 而它已经把 `approvalDeferred` 置空了（幂等）。
 */
@Composable
fun PairingApprovalDialog(controller: AdminSideController) {
    val pending = controller.pendingApproval ?: return

    OverlayDialog(
        title = "允许这台手机配对？",
        show = true,
        // 60 秒是上限，点掉对话框等价于拒绝 —— 让协议层立刻拿到结果，
        // 而不是继续干等把用户和手机都吊着
        onDismissRequest = { controller.resolveApproval(false) },
    ) {
        Column {
            Text(
                text = "设备名称：${pending.phoneDisplayName}",
                style = MiuixTheme.textStyles.body2,
                color = MiuixTheme.colorScheme.onSurface,
            )
            Text(
                text = "型号：${pending.phoneModel}",
                style = MiuixTheme.textStyles.body2,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            Spacer(Modifier.height(12.dp))
            Text(
                text = "如果这不是你本人操作，请点「拒绝」。允许后该手机将可以解锁这台电脑。",
                style = MiuixTheme.textStyles.footnote1,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
        }
        Spacer(Modifier.height(16.dp))
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
                text = "允许",
                onClick = { controller.resolveApproval(true) },
                modifier = Modifier.weight(1f),
                colors = ButtonDefaults.textButtonColorsPrimary(),
            )
        }
    }
}
