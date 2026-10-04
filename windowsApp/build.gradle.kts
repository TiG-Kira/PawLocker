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
                // 不指定 iconFile 的话，成品会套上 Java 的默认图标（一只咖啡杯）。
                // 图标由 tools/generate-icons.py 生成，改形状改颜色都在那个脚本里。
                iconFile.set(project.file("icons/pawlocker.ico"))

                // MSI 的升级标识。**这个值一旦发布就不能改**：
                // Windows Installer 靠它判断「装的是同一产品的新版本」而不是「另一个产品」。
                // 改了它，旧版本不会被视为可升级，用户会看到两个 PawLocker 并存，
                // 而且没有卸载旧版就装新版会直接失败。
                upgradeUuid = "c569f376-d7a6-4075-9643-02493e343eee"

                // 需要 UIAccess 才能在锁屏界面弹出应用窗口（正式发布需代码签名证书）
                menuGroup = "PawLocker"
                dirChooser = true
                // perMachine 安装：装到 Program Files，装一次全机可用。
                // 这也是 UIAccess 与凭据提供程序能正常工作的前提——
                // 它们都要求可执行文件位于受信任的位置。
                perUserInstall = false
                shortcut = true
            }
        }
    }
}
