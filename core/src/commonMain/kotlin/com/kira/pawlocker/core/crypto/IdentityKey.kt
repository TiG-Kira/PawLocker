package com.kira.pawlocker.core.crypto

/**
 * 设备身份密钥（长期密钥，随设备安装存活）。每个端各有一把：
 *  - Windows 端别名 `pawlocker.windows.identity`
 *  - Android 端别名 `pawlocker.android.identity`
 *
 * 私钥**永不离开**安全存储：
 *  - Android：AndroidKeyStore，优先 StrongBox / TEE 硬件后端，`setUserAuthenticationRequired(false)`
 *  - Windows：JCE 生成的 PKCS#8，落盘前用 DPAPI（当前用户作用域）封装
 *
 * 公钥（65 字节未压缩点）会被广播给对方，并作为配对记录的主键
 * （`deviceId = SHA-256(pubKey)` 前 16 字节的 Base64Url），
 * 因此双方都不能伪造对方的身份。
 */
interface IdentityKey {

    val alias: String

    /** 65 字节未压缩点：0x04 || X(32) || Y(32) */
    val publicKey: ByteArray

    /** 私钥是否由硬件（TEE / StrongBox / TPM）保护。 */
    val hardwareBacked: Boolean

    /** ECDSA-P256-SHA256 签名，返回 DER 编码。 */
    fun sign(data: ByteArray): ByteArray

    /** ECDH P-256 密钥协商，返回 32 字节共享秘密。 */
    fun agree(peerPublicKey: ByteArray): ByteArray
}

expect object IdentityKeyFactory {

    /**
     * 加载指定别名的身份密钥；不存在则生成一把。
     * 该方法是幂等的，重复调用返回同一把密钥。
     */
    fun loadOrCreate(alias: String): IdentityKey

    /** 移除身份密钥（用户「重置本机身份」时调用，会导致全部配对失效）。 */
    fun delete(alias: String)
}

/** 配对场景下用来描述「我是谁」的最小信息集。 */
data class DeviceProfile(
    val displayName: String,
    val model: String,
    val platform: String,
)

object DeviceIds {

    /** 由公钥派生稳定设备 ID，避免两端各自维护一套 ID 映射。 */
    fun fromPublicKey(publicKey: ByteArray): String =
        Base64Url.encode(PlatformCrypto.sha256(publicKey).copyOf(16))
}
