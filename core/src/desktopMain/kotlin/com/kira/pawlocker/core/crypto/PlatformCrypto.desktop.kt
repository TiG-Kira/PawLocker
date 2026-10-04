package com.kira.pawlocker.core.crypto

import java.security.KeyFactory
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Windows 侧的密码学原语。全部走 JDK 内置 provider，不引入 BouncyCastle ——
 * 少一个依赖就少一处供应链风险，而 P-256 / AES-GCM / SHA-256 这些 JDK 早就够了。
 */
actual object PlatformCrypto {

    private val secureRandom = SecureRandom()

    actual val backendName: String = "JDK SunEC / SunJCE (AES-GCM / ECDSA P-256)"

    actual fun randomBytes(size: Int): ByteArray =
        ByteArray(size).also { secureRandom.nextBytes(it) }

    actual fun sha256(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(data)

    actual fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256")
            .apply { init(SecretKeySpec(key, "HmacSHA256")) }
            .doFinal(data)

    actual fun verifyEcdsa(
        publicKeyUncompressed: ByteArray,
        data: ByteArray,
        signatureDer: ByteArray,
    ): Boolean = runCatching {
        val publicKey = KeyFactory.getInstance("EC")
            .generatePublic(X509EncodedKeySpec(EcKeys.rawToSpki(publicKeyUncompressed)))
        Signature.getInstance("SHA256withECDSA").run {
            initVerify(publicKey)
            update(data)
            verify(signatureDer)
        }
    }.getOrDefault(false)

    actual fun aesGcmSeal(
        key: ByteArray,
        nonce: ByteArray,
        plaintext: ByteArray,
        aad: ByteArray,
    ): ByteArray = Cipher.getInstance("AES/GCM/NoPadding").run {
        init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, nonce))
        if (aad.isNotEmpty()) updateAAD(aad)
        doFinal(plaintext)
    }

    actual fun aesGcmOpen(
        key: ByteArray,
        nonce: ByteArray,
        sealed: ByteArray,
        aad: ByteArray,
    ): ByteArray = try {
        Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, nonce))
            if (aad.isNotEmpty()) updateAAD(aad)
            doFinal(sealed)
        }
    } catch (error: Throwable) {
        throw AeadFailure()
    }

    actual fun wipe(bytes: ByteArray) {
        bytes.fill(0)
    }

    private const val TAG_BITS = 128
}
