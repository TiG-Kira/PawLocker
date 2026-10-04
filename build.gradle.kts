// 注意：Gradle 的版本目录访问器把别名里的 `-` 转成 `.`。
// 在 `plugins {}` 块里**必须**写点号形式（libs.plugins.android.application），
// 写成 libs.plugins.android-application 会被解析成减号运算而编译失败。
plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.android.kmp.library) apply false
    alias(libs.plugins.kotlin.multiplatform) apply false
    alias(libs.plugins.kotlin.jvm) apply false
    alias(libs.plugins.kotlin.serialization) apply false
    alias(libs.plugins.compose.compiler) apply false
    alias(libs.plugins.compose.multiplatform) apply false
}
