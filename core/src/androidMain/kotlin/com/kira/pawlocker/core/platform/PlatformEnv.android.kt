package com.kira.pawlocker.core.platform

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
private const val WRAP_KEY_ALIAS = "pawlocker.storage.wrap"

/**
 * Android 平台环境。
 *
 * ## 静态加密方案
 *
 * 没有用 `EncryptedSharedPreferences`，而是自己用 AndroidKeyStore 里的一把
 * AES-256-GCM「包裹密钥」来加密落盘内容。原因：
 *  - 包裹密钥本身由 TEE（或 StrongBox）保护，私钥材料不可导出
 *  - 支持 API 26 起全部版本，不依赖 androidx.security 的额外版本分歧
 *  - 加解密逻辑完全自持，出问题容易定位
 *
 * 落盘格式：`[1 字节版本][12 字节 IV][GCM 密文 + 16 字节 tag]`
 */
actual object PlatformEnv {

    private var appContext: Context? = null

    actual val platformName: String = "Android"

    actual fun init(handle: Any?) {
        val context = handle as? Context ?: return
        appContext = context.applicationContext
    }

    actual val dataDir: String
        get() = File(requireContext().filesDir, "pawlocker").apply { mkdirs() }.absolutePath

    actual val hasHardwareKeyStore: Boolean = true

    actual fun currentTimeMillis(): Long = System.currentTimeMillis()

    actual fun localIpv4Addresses(): List<String> = try {
        java.net.NetworkInterface.getNetworkInterfaces().toList()
            .filter { it.isUp && !it.isLoopback && !it.isVirtual }
            .flatMap { nic -> nic.inetAddresses.toList().map { nic.name to it } }
            .filter { (_, address) -> address is java.net.Inet4Address && !address.isLoopbackAddress }
            .map { (_, address) -> address.hostAddress.orEmpty().substringBefore('%') }
            .filter { it.isNotBlank() }
            .distinct()
    } catch (error: Throwable) {
        emptyList()
    }

    actual fun log(tag: String, message: String) {
        android.util.Log.i("PawLocker/$tag", message)
    }

    actual fun writeSecure(name: String, data: ByteArray) {
        val sealed = seal(data)
        fileFor(name).writeBytes(sealed)
    }

    actual fun readSecure(name: String): ByteArray? {
        val file = fileFor(name)
        if (!file.exists()) return null
        return runCatching { open(file.readBytes()) }.getOrElse { error ->
            log("PlatformEnv", "读取 $name 失败：${error.message}")
            null
        }
    }

    actual fun deleteSecure(name: String) {
        fileFor(name).delete()
    }

    // ——————————————————————————————————————————————————————————
    // 内部
    // ——————————————————————————————————————————————————————————

    /** 子目录名，避免和 keys/ 之类的专用目录混在一起。 */
    private const val SECURE_DIR = "secure"

    private fun requireContext(): Context =
        appContext ?: error("PlatformEnv.init(context) 尚未调用，请在 Application.onCreate 中初始化")

    private fun fileFor(name: String): File =
        File(File(dataDir, SECURE_DIR).apply { mkdirs() }, name)

    private fun wrapKey(): SecretKey {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        (keyStore.getEntry(WRAP_KEY_ALIAS, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)

        fun spec(strongBox: Boolean): KeyGenParameterSpec {
            val builder = KeyGenParameterSpec.Builder(
                WRAP_KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                // 平台不要求用户生物验证即可解密：解锁动作本身的二次确认在业务层做，
                // 这里如果强制验证，会导致后台服务无法读取信任列表
                .setUserAuthenticationRequired(false)
            if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                builder.setIsStrongBoxBacked(true)
            }
            return builder.build()
        }

        // 优先尝试 StrongBox，不可用时退回 TEE
        runCatching { generator.init(spec(strongBox = true)) }
            .onFailure { generator.init(spec(strongBox = false)) }

        return generator.generateKey()
    }

    private fun seal(plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, wrapKey())
        // AndroidKeyStore 的 GCM 由系统生成 IV，必须回读，不能自己塞
        val iv = cipher.iv
        val body = cipher.doFinal(plaintext)
        return byteArrayOf(FORMAT_VERSION) + iv + body
    }

    private fun open(sealed: ByteArray): ByteArray {
        require(sealed.size > 1 + IV_SIZE) { "加密文件格式错误" }
        require(sealed[0] == FORMAT_VERSION) { "加密文件版本不支持: ${sealed[0]}" }
        val iv = sealed.copyOfRange(1, 1 + IV_SIZE)
        val body = sealed.copyOfRange(1 + IV_SIZE, sealed.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, wrapKey(), GCMParameterSpec(128, iv))
        return cipher.doFinal(body)
    }

    private const val FORMAT_VERSION: Byte = 1
    private const val IV_SIZE = 12
}

/**
 * 手机端没有 Windows 账户概念，因此恒返回 [UserIdentity.Unknown]。
 *
 * 这不是遗漏：三元绑定链里的「Windows 账户」属于**电脑**，
 * 手机只是在配对时把它记下来、在发解锁指令时原样回传。
 * 手机自身的身份是设备身份密钥（AndroidKeyStore 里的那把）。
 *
 * 注意 [UserIdentity.Unknown] 的 `bindingKey` 是 `"name:"` 而不是空串 ——
 * 电脑侧会拿自己解析出的账户去比对，不匹配就拒绝，不会因为「两边都空」而误判通过。
 */
actual fun currentUserIdentity(): UserIdentity = UserIdentity.Unknown
