package com.kira.pawlocker

import android.app.Application
import com.kira.pawlocker.core.platform.PlatformEnv

/**
 * 应用入口。
 *
 * **必须在进程启动的最早期**把 `Application` 交给 [PlatformEnv] ——
 * 数据目录、静态加密文件、日志都依赖它。晚一步就会在密钥初始化时拿到 null。
 */
class PawLockerApplication : Application() {

    override fun onCreate() {
        super.onCreate()
        PlatformEnv.init(this)
        PlatformEnv.log("Application", "PawLocker 启动，数据目录 ${PlatformEnv.dataDir}")
    }
}
