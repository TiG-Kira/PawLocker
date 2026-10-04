@file:Suppress("UnstableApiUsage")

rootProject.name = "PawLocker"

pluginManagement {
    repositories {
        google {
            mavenContent {
                includeGroupAndSubgroups("androidx")
                includeGroupAndSubgroups("com.android")
                includeGroupAndSubgroups("com.google")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositories {
        google {
            mavenContent {
                includeGroupAndSubgroups("androidx")
                includeGroupAndSubgroups("com.android")
                includeGroupAndSubgroups("com.google")
            }
        }
        mavenCentral()
    }
}

// 核心协议 / 密码学 / 传输层（纯 Kotlin，可单测）
include(":core")

// Miuix UI 层（Compose Multiplatform，Android + Desktop 共用）
include(":ui")

// 两个端
include(":androidApp")
include(":windowsApp")
