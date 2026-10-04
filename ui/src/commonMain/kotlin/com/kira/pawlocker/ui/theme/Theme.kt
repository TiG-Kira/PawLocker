package com.kira.pawlocker.ui.theme

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import top.yukonga.miuix.kmp.theme.ColorSchemeMode
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.theme.ThemeController

/**
 * 应用根主题。
 *
 * 只有一处 `MiuixTheme` —— 两端的所有页面都在这棵子树下面，
 * 页面内部不要再套一层，否则颜色 token 会分裂成两套。
 *
 * 用 `ColorSchemeMode.System` 跟随系统深浅色：Windows 端跟随系统主题，
 * Android 端跟随系统深色模式。Miuix 会据此在 light/dark 两套 Colors 之间切换。
 */
@Composable
fun PawLockerTheme(content: @Composable () -> Unit) {
    val controller = remember { ThemeController(ColorSchemeMode.System) }
    MiuixTheme(controller = controller) {
        content()
    }
}
