import org.jetbrains.compose.desktop.application.dsl.TargetFormat

plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.compose.multiplatform)
    alias(libs.plugins.compose.compiler)
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

// Kotlin 侧产出 17 字节码，Java 任务也必须是 17 —— 否则 Gradle 会以
// 「Inconsistent JVM-target compatibility」直接 fail。
// 本机没有 JDK 17，所以这里让 JDK 21 以 --release 17 编译，产出仍可运行在 JRE 17+。
java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

dependencies {
    implementation(project(":ui"))
    implementation(compose.desktop.currentOs)
    implementation(libs.kotlinx.coroutines.swing)
    implementation(libs.jna.core)
    implementation(libs.jna.platform)
}

compose.desktop {
    application {
        mainClass = "com.kira.pawlocker.windows.MainKt"

        nativeDistributions {
            // Windows 端交付物：MSI 安装包
            targetFormats(TargetFormat.Msi)
            packageName = "PawLocker"
            packageVersion = "1.0.0"
            description = "PawLocker —— 手机远程解锁 Windows"
            vendor = "TiG-Kira"

            windows {
                // 需要 UIAccess 才能在锁屏界面弹出应用窗口（正式发布需代码签名证书）
                menuGroup = "PawLocker"
                dirChooser = true
                perUserInstall = false
                shortcut = true
            }
        }
    }
}
