import java.io.File
import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.compose.compiler)
}

// ——————————————————————————————————————————————————————————————
// 发布签名
// ——————————————————————————————————————————————————————————————
//
// 凭据从仓库外的 `keystore.properties` 读，而不是写在这个文件里。
//
// 理由很直接：build.gradle.kts 是**会被提交**的文件，签名密钥的密码写进去
// 就等于公开。密码只应存在于一个 gitignore 掉的本地文件里。
//
// 三条行为约定：
//  1. 没有 keystore.properties → 不配置签名，release 产物保持未签名。
//     这样 clone 下来的人、以及没配密钥的 CI 仍然构建得出来，只是需要自己补签。
//  2. 有 keystore.properties 但密钥库文件不在 → **配置阶段直接报错**。
//     刻意不做「找不到就跳过」的静默降级：那会产出一个看似正常、实则未签名的
//     release 包，而这类包只有在用户安装时才会暴露问题。
//  3. storeFile 支持绝对路径，也支持「相对 keystore.properties 所在目录」的写法。
val keystorePropertiesFile: File? = listOf(
    // 推荐位置，与 keystore.properties.example 同目录
    file("keystore.properties"),
    // 兼容放在仓库根目录的写法
    rootProject.file("keystore.properties"),
).firstOrNull { it.isFile }

val keystoreProperties = Properties().apply {
    keystorePropertiesFile?.inputStream()?.use { load(it) }
}

/** 解析后的密钥库文件；没有配置文件时为 null。 */
val releaseKeystore: File? = keystorePropertiesFile?.let { propertiesFile ->
    val raw = keystoreProperties.getProperty("storeFile").orEmpty().trim()
    val candidate = File(raw)
    val resolved = if (candidate.isAbsolute) {
        candidate
    } else {
        // 相对路径按 keystore.properties 所在目录解析，这样「把 .jks 和
        // properties 一起放进 androidApp/」这种最常见的用法直接可用
        File(propertiesFile.parentFile, raw)
    }
    require(resolved.isFile) {
        "keystore.properties 指向的密钥库不存在：$resolved\n" +
            "改掉 storeFile，或把那个文件放回去。"
    }
    resolved
}

android {
    namespace = "com.kira.pawlocker"
    compileSdk { version = release(37) }

    defaultConfig {
        applicationId = "com.kira.pawlocker"
        minSdk = 26
        targetSdk = 37
        versionCode = 1
        versionName = "0.1.0"
    }

    signingConfigs {
        if (releaseKeystore != null) {
            create("release") {
                storeFile = releaseKeystore
                storePassword = keystoreProperties.getProperty("storePassword")
                keyAlias = keystoreProperties.getProperty("keyAlias")
                keyPassword = keystoreProperties.getProperty("keyPassword")

                // 签名方案的选择不是随便开的：
                //  v1（JAR 签名）对 minSdk 26 是多余的 —— v2 从 Android 7.0 起就支持，
                //     而且 v1 只覆盖部分文件、校验也更弱。关掉能少一个攻击面。
                //  v3 必须开：它带密钥轮换信息，是将来万一要换签名密钥时唯一的退路。
                //     现在不开，以后想换 key 就只能换包名重发。
                enableV1Signing = false
                enableV2Signing = true
                enableV3Signing = true
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
            // 只在真的读到了凭据时才挂上签名配置
            signingConfigs.findByName("release")?.let { signingConfig = it }
        }
        debug {
            applicationIdSuffix = ".debug"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
    }
}

dependencies {
    implementation(project(":ui"))
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.fragment.ktx)
    implementation(libs.androidx.biometric)
    implementation(libs.kotlinx.coroutines.android)
}
