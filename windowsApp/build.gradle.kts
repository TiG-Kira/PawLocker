import org.jetbrains.compose.desktop.application.dsl.TargetFormat

plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.compose.multiplatform)
    alias(libs.plugins.compose.compiler)
}

// ——————————————————————————————————————————————————————————————
// 凭据提供程序 DLL
// ——————————————————————————————————————————————————————————————
//
// 这个 DLL 必须跟着 MSI 一起装到 `C:\Program Files\PawLocker\`，原因是
// 注册向导建议的路径就是那儿（`WindowsRegistrar.suggestedCredentialProviderPath`），
// 而凭据提供程序又要求 DLL 位于受信任的位置 —— Program Files 正合适。
//
// 但 DLL 是**原生构建产物**（MSVC 编出来的），不能进版本库：
// 二进制入库会让「仓库里的文件」和「源码 + 签名」脱节，
// 谁改了什么、签没签名，从 diff 里完全看不出来。
//
// 所以做法是：从 credential-provider 的构建目录**取**（而不是复制一份存起来），
// 通过 Compose 的 `appResourcesRootDir` 机制交给打包流程。
// 放进 `resources/windows/` 的文件只会被 Windows 产物收录，不会污染其他平台。
val credentialProviderDll: File = rootProject.file("credential-provider/build/PawLockerProvider.dll")

/**
 * 把已构建的 DLL 放进打包资源目录。
 *
 * 用 `Sync` 而不是 `Copy`：DLL 被删除或改名后，残留的旧文件会让安装包里
 * 混进一个**上一版**的 DLL —— 那东西照样能注册成功，出问题时要查很久才想得到。
 *
 * `into` 会自动建目录，所以仓库里不需要保留空目录占位
 * （空目录 Git 也存不下来，靠占位文件反而会和 `prepareAppResources` 的
 * 重名检查打架 —— `.gitkeep` 在 common/ 与 windows/ 各一份会撞车）。
 */
val stageCredentialProviderDll = tasks.register<Sync>("stageCredentialProviderDll") {
    description = "把已构建的凭据提供程序 DLL 放进打包资源目录"
    from(credentialProviderDll)
    into(layout.projectDirectory.dir("resources/windows"))
}

/**
 * `prepareAppResources` 是 Compose 插件里真正把 `resources/` 收集起来交给 jpackage 的任务。
 *
 * ## 为什么必须挂在它上面，而不是挂在 `packageMsi` 上
 *
 * 挂 `packageMsi` 是错的 —— 那样两个任务之间**没有声明依赖**：
 * Gradle 只看得到「`prepareAppResources` 读了 `resources/windows`」，
 * 而那个目录是 `stageCredentialProviderDll` 的产物。谁先跑取决于调度顺序，
 * 结果是**偶发**的打进一个旧 DLL 或空目录。
 * Gradle 会直接以「implicit dependency」报错拦住这种情况，这个报错是对的。
 *
 * ## 为什么用 `matching` 而不是 `named`
 *
 * `prepareAppResources` 由 Compose 插件在 `afterEvaluate` 阶段注册。
 * 在脚本主体的顶层直接 `tasks.named(...)` 会因「任务还不存在」而失败 ——
 * 这也是为什么一开始那句 `tasks.named("prepareAppResources")` 报 not found。
 * `matching {}` 是惰性的，配置时任务还没注册也没关系。
 */
tasks.matching { it.name == "prepareAppResources" }.configureEach {
    dependsOn(stageCredentialProviderDll)
}

// DLL 不在位就直接报错，**刻意不留「找不到就跳过」的后路**：
// 那样会产出一个装完之后锁屏上什么都没有的安装包，
// 而这个问题只有在用户登录那一刻才会暴露 —— 排查成本极高。
//
// 校验放在 `packageMsi` 的 doFirst 而不是配置阶段：配置阶段抛异常会让
// IDE 同步 / `gradlew tasks` 这类完全不相关的操作也一起失败。
tasks.matching { it.name == "packageMsi" }.configureEach {
    doFirst {
        require(credentialProviderDll.isFile) {
            """
            找不到凭据提供程序 DLL：$credentialProviderDll

            它由 credential-provider 目录下的原生构建脚本产出，先执行：

                cd credential-provider
                build.bat            REM 用 MSVC 编译
                sign.bat devcert     REM 首次：创建开发证书
                sign.bat sign        REM 给 DLL 签名
            """.trimIndent()
        }
    }
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

            // 额外随包分发的文件。Compose 按 `common/`（全平台）
            // 与 `windows/`（仅 Windows）两个子目录选入，其余平台目录会被忽略。
            // 目前里面只有凭据提供程序 DLL —— 见文件顶部那段说明。
            appResourcesRootDir.set(project.layout.projectDirectory.dir("resources"))

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
