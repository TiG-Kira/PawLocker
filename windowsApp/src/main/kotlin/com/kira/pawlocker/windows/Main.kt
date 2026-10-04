package com.kira.pawlocker.windows

import androidx.compose.ui.unit.DpSize
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import androidx.compose.ui.window.rememberWindowState
import com.kira.pawlocker.core.crypto.DeviceProfile
import com.kira.pawlocker.core.platform.PlatformEnv
import com.kira.pawlocker.core.platform.WindowsUnlockExecutor
import com.kira.pawlocker.ui.ComputerApp
import com.kira.pawlocker.ui.platform.PlatformInfo

/**
 * Windows 端入口。
 *
 * 同一个可执行文件承担两种形态，由命令行参数决定：
 *
 * | 参数 | 形态 | 用途 |
 * |---|---|---|
 * | （无） | 管理主窗口 | 日常使用：看设备、配对、改设置 |
 * | `--login-window` | 精简登录窗口 | 从锁屏界面 / 托盘单独唤起的小窗 |
 *
 * 做成同一个二进制而不是两个程序，是因为两者共享同一份配置、同一个数据目录、
 * 同一套身份密钥。分成两个 exe 会在「谁持有 9898 端口」上立刻打架。
 *
 * 注意：进程自身**不**常驻监听 —— 监听由 `LockerServer` 在管理窗口存活期间完成。
 * 若要做到「窗口关掉也继续服务」，正确做法是把 [LockerServer] 挪进一个
 * Windows 服务（SYSTEM 权限），由它持有端口，UI 通过本地 IPC 控制它。
 * 这条演进路径在 `docs/01-architecture.md` 里说明。
 */
fun main(args: Array<String>) = application {
    PlatformEnv.init(null)

    val loginWindowOnly = args.any { it == "--login-window" || it == "-l" }

    val profile = DeviceProfile(
        displayName = PlatformInfo.deviceModel,
        model = PlatformInfo.systemDescription,
        platform = "Windows",
    )

    PlatformEnv.log(
        "Main",
        "启动形态=${if (loginWindowOnly) "登录窗口" else "管理窗口"}，数据目录=${PlatformEnv.dataDir}",
    )

    Window(
        onCloseRequest = ::exitApplication,
        title = if (loginWindowOnly) "PawLocker 登录" else "PawLocker",
        state = rememberWindowState(
            size = if (loginWindowOnly) DpSize(420.dp, 620.dp) else DpSize(1080.dp, 760.dp),
        ),
        // 登录窗口要置顶：它的使用场景是「用户在锁屏界面等手机确认」，
        // 被别的窗口盖住就失去了存在意义
        alwaysOnTop = loginWindowOnly,
        resizable = !loginWindowOnly,
    ) {
        ComputerApp(
            profile = profile,
            loginWindowOnly = loginWindowOnly,
            createUnlockExecutor = { config ->
                WindowsUnlockExecutor(
                    strategy = config.unlockStrategy,
                    customCommand = config.customUnlockCommand,
                )
            },
        )
    }
}
