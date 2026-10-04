package com.kira.pawlocker.core.crypto

/**
 * 平台密码学原语。Android 与 Windows 都跑在 JVM 上，但密钥的**存放方式**完全不同，
 * 所以这里只下沉「不需要持有私钥」的运算；需要私钥的 ECDSA / ECDH 走 [IdentityKey]。
 */
expect object PlatformCrypto {

    /** 底层实现标识，用于设置页展示与排障。 */
    val backendName: String

    fun randomBytes(size: Int): ByteArray

    fun sha256(data: ByteArray): ByteArray

    fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray

    /**
     * 校验 ECDSA-P256-SHA256 签名。
     * @param publicKeyUncompressed 65 字节未压缩点
     * @param signatureDer DER 编码签名（JCE 默认输出格式）
     */
    fun verifyEcdsa(
        publicKeyUncompressed: ByteArray,
        data: ByteArray,
        signatureDer: ByteArray,
    ): Boolean

    /**
     * AES-256-GCM 加密。
     * @return 密文 || 16 字节认证标签
     */
    fun aesGcmSeal(
        key: ByteArray,
        nonce: ByteArray,
        plaintext: ByteArray,
        aad: ByteArray,
    ): ByteArray

    /** AES-256-GCM 解密；认证失败抛 [AeadFailure]。 */
    fun aesGcmOpen(
        key: ByteArray,
        nonce: ByteArray,
        sealed: ByteArray,
        aad: ByteArray,
    ): ByteArray

    /** 尽力而为地擦除内存中的密钥材料。 */
    fun wipe(bytes: ByteArray)
}

/** AEAD 认证失败。对外统一成这一种异常，避免把底层异常信息泄露给攻击者。 */
class AeadFailure(message: String = "认证失败：密文被篡改或密钥不匹配") : Exception(message)
