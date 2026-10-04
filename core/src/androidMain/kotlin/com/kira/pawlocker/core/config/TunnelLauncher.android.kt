package com.kira.pawlocker.core.config

/**
 * Android 端不做内网穿透的**服务端** —— 手机是连接方，不是被连接方。
 * 但 `core` 是共享模块，所以这里给一个空实现，保持 `expect/actual` 对称。
 * 实现本体 [UnsupportedTunnelLauncher] 在 commonMain。
 */
actual fun createTunnelLauncher(): TunnelLauncher = UnsupportedTunnelLauncher()
