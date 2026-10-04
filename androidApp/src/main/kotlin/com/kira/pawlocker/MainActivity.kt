package com.kira.pawlocker

import android.content.Intent
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.fragment.app.FragmentActivity
import com.kira.pawlocker.core.crypto.DeviceProfile
import com.kira.pawlocker.core.platform.PlatformEnv
import com.kira.pawlocker.ui.AndroidAppRoot
import com.kira.pawlocker.ui.PhoneApp
import com.kira.pawlocker.ui.platform.PlatformInfo

/**
 * 唯一的 Activity。
 *
 * 继承 [FragmentActivity] 而不是 `ComponentActivity` 是硬性要求：
 * `BiometricPrompt` 需要一个 `FragmentActivity` 宿主，用 `ComponentActivity`
 * 会在构造时直接抛异常。
 *
 * 界面外壳交给 [AndroidAppRoot] —— 它负责返回键与配对深链；
 * 主题、身份密钥初始化、生物识别闸门注入由 [PhoneApp] 统一处理。
 */
class MainActivity : FragmentActivity() {

    /**
     * 待处理的配对深链。
     *
     * 用 `mutableStateOf` 而不是普通字段：`onNewIntent` 可能在任意时刻被调用
     * （应用已在前台时点开链接），需要它一写入就触发重组。
     * 由 `AndroidAppRoot` 消费后置空，避免热重载/重组时重复配对。
     */
    private var pendingDeepLink by mutableStateOf<String?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 冷启动时可能还没走过 Application.onCreate（例如被系统恢复进程），兜底一次
        PlatformEnv.init(applicationContext)

        pendingDeepLink = intent?.data?.toString()
        pendingDeepLink?.let { PlatformEnv.log("MainActivity", "收到配对深链: $it") }

        setContent {
            PhoneApp(
                profile = DeviceProfile(
                    displayName = android.os.Build.MODEL ?: "Android 手机",
                    model = PlatformInfo.deviceModel,
                    platform = "Android",
                ),
                shell = { controller ->
                    AndroidAppRoot(
                        controller = controller,
                        deepLink = pendingDeepLink,
                        onDeepLinkHandled = { pendingDeepLink = null },
                    )
                },
            )
        }
    }

    /**
     * 单 Activity 应用，深链走 [onNewIntent]。
     * 配对深链的消费逻辑在 `DeviceSideController.pairFromDeepLink`，
     * 这里只负责把新意图转成一次调用。
     */
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        // 必须调 setIntent，否则 getIntent() 一直返回冷启动时那一份
        setIntent(intent)

        intent.data?.toString()?.let { raw ->
            PlatformEnv.log("MainActivity", "收到新的配对深链: $raw")
            pendingDeepLink = raw
        }
    }
}
