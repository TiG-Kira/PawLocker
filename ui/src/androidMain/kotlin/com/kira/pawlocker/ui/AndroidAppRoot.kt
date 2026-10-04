package com.kira.pawlocker.ui

import androidx.activity.compose.BackHandler
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import com.kira.pawlocker.ui.screens.AndroidSettingsScreen
import com.kira.pawlocker.ui.screens.DeviceDetailScreen
import com.kira.pawlocker.ui.screens.DeviceListScreen
import com.kira.pawlocker.ui.screens.PairingScreen
import com.kira.pawlocker.ui.state.DeviceSideController
import com.kira.pawlocker.ui.state.PairingStage

/**
 * Android 端的界面根节点。
 *
 * 主题与生物识别闸门由外层 [PhoneApp] 负责 —— 这里拿到的控制器上
 * 已经挂好了闸门，不再重复创建 `BiometricPrompt`。
 *
 * 导航刻意不用 Navigation 库：整个应用只有 4 个目的地，
 * 而且「配对结束自动回设备页」这种逻辑用状态机表达比用路由栈更直白。
 * 少一个依赖，少一层 back stack 语义要跟系统对齐。
 */
@Composable
fun AndroidAppRoot(
    controller: DeviceSideController,
    deepLink: String?,
    onDeepLinkHandled: () -> Unit,
) {
    // 冷启动时读一次信任列表
    LaunchedEffect(Unit) { controller.refresh() }

    var route: AppRoute by remember { mutableStateOf(AppRoute.Devices) }
    var pairingStarted by remember { mutableStateOf(false) }

    // 配对一旦开始就记住，等它结束时回到设备页 ——
    // SAS 比对弹窗与失败原因都在设备页上展示，用户不需要留在配对页看结果
    LaunchedEffect(controller.pairingStage) {
        when (controller.pairingStage) {
            PairingStage.InProgress -> pairingStarted = true
            PairingStage.Idle -> if (pairingStarted) {
                pairingStarted = false
                if (route is AppRoute.Pairing) route = AppRoute.Devices
            }
        }
    }

    // 深链：pawlocker://pair?d=...
    // 扫一扫之外的路径 —— 从浏览器/短信里点开链接也能直接进入配对
    LaunchedEffect(deepLink) {
        val raw = deepLink ?: return@LaunchedEffect
        route = AppRoute.Pairing
        controller.pairFromDeepLink(raw)
        onDeepLinkHandled()
    }

    BackHandler(enabled = route !is AppRoute.Devices) {
        route = AppRoute.Devices
    }

    when (val current = route) {
        AppRoute.Devices -> DeviceListScreen(
            controller = controller,
            message = controller.lastMessage,
            onDismissMessage = { controller.clearMessage() },
            onAddComputer = { route = AppRoute.Pairing },
            onOpenDevice = { record -> route = AppRoute.Detail(record.deviceId) },
            onOpenSettings = { route = AppRoute.Settings },
        )

        AppRoute.Pairing -> PairingScreen(
            controller = controller,
            onBack = { route = AppRoute.Devices },
        )

        AppRoute.Settings -> AndroidSettingsScreen(
            controller = controller,
            message = controller.lastMessage,
            onDismissMessage = { controller.clearMessage() },
            onBack = { route = AppRoute.Devices },
        )

        is AppRoute.Detail -> {
            // 记录可能刚被删除或在别处刷新过，所以按 id 重新取一次
            val record = controller.devices.firstOrNull { it.deviceId == current.deviceId }
            if (record == null) {
                LaunchedEffect(current.deviceId) { route = AppRoute.Devices }
            } else {
                DeviceDetailScreen(
                    record = record,
                    controller = controller,
                    onBack = { route = AppRoute.Devices },
                )
            }
        }
    }
}

private sealed interface AppRoute {

    /** 默认页：已匹配的电脑列表。 */
    data object Devices : AppRoute

    /** 匹配新电脑。 */
    data object Pairing : AppRoute

    /** 单台电脑的详情与连通性测试。 */
    data class Detail(val deviceId: String) : AppRoute

    /** 设置与关于。 */
    data object Settings : AppRoute
}
