package com.kira.pawlocker.core.platform

/**
 * Android 侧不存在「向 Windows 注册」这回事 —— 手机是发起解锁的一方，
 * 需要注册凭据提供程序、写防火墙规则、挂开机启动项的是被解锁的那台电脑。
 *
 * 这里保留一个 [UnsupportedWindowsRegistrar] 是为了让共享 UI 层
 * （`AdminScreen` / 设置页）能无条件调用 `createWindowsRegistrar()` 而不必到处判平台。
 * 所有写操作都会返回带原因的失败，界面上会显示「当前平台不支持」，
 * 不会出现「点了没反应」这种最糟糕的交互。
 */
actual fun createWindowsRegistrar(): WindowsRegistrar = UnsupportedWindowsRegistrar()
