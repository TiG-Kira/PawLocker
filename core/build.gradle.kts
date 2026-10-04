plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.android.kmp.library)
    alias(libs.plugins.kotlin.serialization)
}

kotlin {
    // expect/actual 的 class 形态仍标记为 Beta，但我们确实要用
    // expect object（PlatformEnv / IdentityKeyFactory 等），这里显式认可该警告
    compilerOptions {
        freeCompilerArgs.add("-Xexpect-actual-classes")
    }

    android {
        namespace = "com.kira.pawlocker.core"
        compileSdk { version = release(37) }
        minSdk = 26
        compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) }
    }

    jvm("desktop") {
        compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) }
    }

    sourceSets {
        commonMain.dependencies {
            implementation(libs.kotlinx.coroutines.core)
            api(libs.kotlinx.serialization.json)
        }
        androidMain.dependencies {
            implementation(libs.kotlinx.coroutines.android)
        }
        // 自定义命名的 target 不生成 `desktopMain` 访问器，得按名字取
        getByName("desktopMain").dependencies {
            implementation(libs.kotlinx.coroutines.swing)
            // jna 必须显式声明：jna-platform 只把它作为 runtime 依赖传递进来，
            // 编译期拿不到 WinDef.DWORD 这类继承自 jna 基础包的成员
            implementation(libs.jna.core)
            implementation(libs.jna.platform)
        }
        commonTest.dependencies {
            // 断言与注解用 kotlin-test（target 无关）；JVM 上的运行器绑定在 desktopTest 里
            implementation(libs.kotlin.test.core)
        }
        // 同上：自定义命名的 target 不生成 `desktopTest` 访问器
        getByName("desktopTest").dependencies {
            implementation(libs.kotlin.test.junit)
        }
    }
}
