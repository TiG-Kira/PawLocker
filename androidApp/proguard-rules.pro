# PawLocker release 的 R8 规则。
#
# 这个文件之前是缺的，而 `isMinifyEnabled = true` 一直开着 —— 也就是说
# release 包一直在跑 R8，只是没人告诉它哪些东西不能裁。
# 最容易中招的是 kotlinx.serialization：序列化器由编译器插件生成，
# R8 静态分析看不到「谁在用」，一旦判为无用就会裁掉。
# 症状是 debug 包一切正常、release 包一碰序列化就抛
# SerializerNotFoundException 或字段全丢 —— 只有装到真机上才暴露。

# ——————————————————————————————————————————————————————————————
# kotlinx.serialization
# ——————————————————————————————————————————————————————————————

# 序列化器是靠注解与生成类发现的，注解属性必须保留
-keepattributes *Annotation*, InnerClasses, Signature, RuntimeVisibleAnnotations, RuntimeInvisibleAnnotations, RuntimeVisibleParameterAnnotations

# 每个 @Serializable 类都会生成一个 <类名>$$serializer，实例挂在 Companion 上
-keepclassmembers class **$$serializer {
    *;
}
-keepclasseswithmembers class * {
    kotlinx.serialization.KSerializer serializer(...);
}
-keepclassmembers class * {
    *** Companion;
}

# 多态类型（sealed interface WireMessage）靠 SerializersModule 反射查表
-keep class kotlinx.serialization.** { *; }
-dontwarn kotlinx.serialization.**

# ——————————————————————————————————————————————————————————————
# 数据模型：字段名就是 JSON key
# ——————————————————————————————————————————————————————————————
#
# 这几层的类名与字段名会**落到磁盘上**（信任列表）或**发到线路上**（协议报文）。
# 混淆掉字段名就等于同时废掉两件事：
#   - 已经配对过的设备反序列化不出旧记录
#   - 手机与电脑之间的报文互相看不懂
# 代价是这些包不做混淆。协议本身在 docs/ 里是公开的，
# 靠的是密码学而不是「别人看不懂类名」，所以这个代价可以接受。

-keep class com.kira.pawlocker.core.protocol.** { *; }
-keep class com.kira.pawlocker.core.trust.** { *; }
-keep class com.kira.pawlocker.core.config.** { *; }

# crypto / platform 的字段名不进任何序列化格式，允许混淆；
# 但它们的 Companion 上也可能挂着序列化器，所以保留成员名
-keepclassmembers class com.kira.pawlocker.core.crypto.** {
    <fields>;
}
-keepclassmembers class com.kira.pawlocker.core.platform.** {
    <fields>;
}

# ——————————————————————————————————————————————————————————————
# kotlinx.coroutines
# ——————————————————————————————————————————————————————————————

# 协程内部会通过反射访问 Job / CoroutineContext 的 volatile 字段做调试探针
-keepclassmembers class kotlinx.coroutines.** {
    volatile <fields>;
}
-dontwarn kotlinx.coroutines.**

# ——————————————————————————————————————————————————————————————
# AndroidX / Compose
# ——————————————————————————————————————————————————————————————

# Compose 的运行时已经带了 consumer rules，这里只补一条：
# Composable 函数在调试工具之外不需要可读名，但 @Composable 注解要留住
-keep @androidx.compose.runtime.Composable class * { *; }

# 生物识别回调通过反射实例化
-keep class androidx.biometric.** { *; }

# ——————————————————————————————————————————————————————————————
# 诊断
# ——————————————————————————————————————————————————————————————

# 行号是排查线上崩溃的唯一线索，混淆掉等于放弃可诊断性
-keepattributes SourceFile, LineNumberTable
-renamesourcefileattribute SourceFile
