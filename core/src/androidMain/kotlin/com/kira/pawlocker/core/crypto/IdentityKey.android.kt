package com.kira.pawlocker.core.crypto

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import com.kira.pawlocker.core.platform.PlatformEnv
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.PKCS8EncodedKeySpec
import javax.crypto.KeyAgreement

private const val PROVIDER = "AndroidKeyStore"
private const val CURVE = "secp256r1"

/**
 * Android 侧的身份密钥。
 *
 * ## 分级策略（按系统能力自动选择，对上层透明）
 *
 * | 条件 | 实现 | 私钥保护 |
 * |---|---|---|
 * | API 31+ | [KeystoreIdentityKey] | 原生 AndroidKeyStore，**私钥完全不可导出**，TEE / StrongBox 内完成签名与 ECDH |
 * | API 26–30 | [WrappedSoftwareIdentityKey] | 软件 P-256 私钥，但落盘前由 AndroidKeyStore 里一把 TEE 保护的 AES-256-GCM 密钥包裹 |
 *
 * 之所以要分两级：AndroidKeyStore 直到 API 31 才支持 `PURPOSE_AGREE_KEY`（ECDH 密钥协商）
 * 与 `PURPOSE_SIGN` 共用一把 EC 密钥。低于 31 时强行用原生密钥会导致配对直接失败，
 * 所以退化方案是「软件密钥 + 硬件包裹」，安全性依然显著高于明文落盘。
 *
 * 两种实现的 [IdentityKey.publicKey] 都是 P-256 未压缩点，协议层无感知差异。
 */
actual object IdentityKeyFactory {

    actual fun loadOrCreate(alias: String): IdentityKey {
        // ① 原生 AndroidKeyStore 密钥（API 31+ 创建）
        if (hasKeystoreEntry(alias)) return KeystoreIdentityKey(alias)

        // ② 软件密钥 + 硬件包裹（低版本创建，或用户从旧系统升级上来）
        val stored = PlatformEnv.readSecure("key-$alias")
        if (stored != null) return WrappedSoftwareIdentityKey(alias, stored)

        // ③ 全新生成
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            createKeystoreKey(alias)
        } else {
            createSoftwareKey(alias)
        }
    }

    actual fun delete(alias: String) {
        runCatching {
            KeyStore.getInstance(PROVIDER).apply { load(null) }.deleteEntry(alias)
        }
        PlatformEnv.deleteSecure("key-$alias")
    }

    private fun hasKeystoreEntry(alias: String): Boolean =
        runCatching {
            KeyStore.getInstance(PROVIDER).apply { load(null) }.containsAlias(alias)
        }.getOrDefault(false)

    private fun createKeystoreKey(alias: String): IdentityKey {
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, PROVIDER)

        fun spec(strongBox: Boolean): KeyGenParameterSpec {
            val builder = KeyGenParameterSpec.Builder(
                alias,
                // ECDH 的用途位叫 PURPOSE_AGREE_KEY（API 31 起才存在），
                // 这条路径本身也只在 API 31+ 走，见类注释里的分级策略
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_AGREE_KEY,
            )
                .setAlgorithmParameterSpec(ECGenParameterSpec(CURVE))
                .setDigests(KeyProperties.DIGEST_SHA256)
                // 解锁场景下不能要求用户先做一次系统生物验证 ——
                // 手机侧的生物验证由业务层在发指令前完成
                .setUserAuthenticationRequired(false)
            if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                builder.setIsStrongBoxBacked(true)
            }
            return builder.build()
        }

        runCatching { generator.initialize(spec(strongBox = true)) }
            .onFailure { generator.initialize(spec(strongBox = false)) }
        generator.generateKeyPair()

        return KeystoreIdentityKey(alias)
    }

    private fun createSoftwareKey(alias: String): IdentityKey {
        val generator = KeyPairGenerator.getInstance("EC")
        generator.initialize(ECGenParameterSpec(CURVE))
        val keyPair = generator.generateKeyPair()

        val publicKey = EcJce.encodePoint(keyPair.public as ECPublicKey)
        val encoded = EcJce.packSoftwareKey(keyPair.private.encoded, publicKey)
        PlatformEnv.writeSecure("key-$alias", encoded)

        return WrappedSoftwareIdentityKey(alias, encoded)
    }
}

/** API 31+：密钥材料全程留在 TEE / StrongBox 内。 */
private class KeystoreIdentityKey(override val alias: String) : IdentityKey {

    private val privateKey: PrivateKey = run {
        val entry = KeyStore.getInstance(PROVIDER).apply { load(null) }.getEntry(alias, null)
        (entry as? KeyStore.PrivateKeyEntry)?.privateKey
            ?: error("AndroidKeyStore 中找不到别名 $alias")
    }

    override val publicKey: ByteArray = run {
        val entry = KeyStore.getInstance(PROVIDER).apply { load(null) }.getEntry(alias, null)
        val certificate = (entry as? KeyStore.PrivateKeyEntry)?.certificate
            ?: error("AndroidKeyStore 中找不到别名 $alias 的证书")
        EcKeys.spkiToRaw(certificate.publicKey.encoded)
    }

    override val hardwareBacked: Boolean = runCatching {
        @Suppress("DEPRECATION")
        KeyFactory.getInstance(privateKey.algorithm, PROVIDER)
            .getKeySpec(privateKey, KeyInfo::class.java)
            .isInsideSecureHardware
    }.getOrDefault(false)

    override fun sign(data: ByteArray): ByteArray =
        Signature.getInstance("SHA256withECDSA").run {
            initSign(privateKey)
            update(data)
            sign()
        }

    override fun agree(peerPublicKey: ByteArray): ByteArray =
        KeyAgreement.getInstance("ECDH").run {
            init(privateKey)
            doPhase(EcJce.toPublicKey(peerPublicKey), true)
            generateSecret()
        }
}

/** API 26–30：软件密钥 + AndroidKeyStore 硬件包裹。 */
private class WrappedSoftwareIdentityKey(
    override val alias: String,
    packed: ByteArray,
) : IdentityKey {

    private val privateKey: ECPrivateKey

    override val publicKey: ByteArray

    init {
        val (pkcs8, rawPublic) = EcJce.unpackSoftwareKey(packed)
        val key = KeyFactory.getInstance("EC")
            .generatePrivate(PKCS8EncodedKeySpec(pkcs8))
        privateKey = key as? ECPrivateKey ?: error("存储的私钥不是 EC 私钥")
        publicKey = rawPublic
    }

    /** 私钥本身是软件生成，但静态加密由 TEE 保护的包裹密钥完成。 */
    override val hardwareBacked: Boolean = false

    override fun sign(data: ByteArray): ByteArray =
        Signature.getInstance("SHA256withECDSA").run {
            initSign(privateKey)
            update(data)
            sign()
        }

    override fun agree(peerPublicKey: ByteArray): ByteArray =
        KeyAgreement.getInstance("ECDH").run {
            init(privateKey)
            doPhase(EcJce.toPublicKey(peerPublicKey), true)
            generateSecret()
        }
}

/**
 * P-256 的 JCE 互转工具。
 * Android 与 Windows 端各有一份，内容一致 —— 平台代码保持自包含，便于单独审计。
 */
internal object EcJce {

    fun p256Parameters(): ECParameterSpec =
        AlgorithmParameters.getInstance("EC")
            .apply { init(ECGenParameterSpec(CURVE)) }
            .getParameterSpec(ECParameterSpec::class.java)

    /** 未压缩点 -> JCE 公钥 */
    fun toPublicKey(raw: ByteArray): ECPublicKey {
        require(EcKeys.isValidRawPoint(raw)) { "非法的 P-256 公钥点" }
        val x = BigInteger(1, raw.copyOfRange(1, 33))
        val y = BigInteger(1, raw.copyOfRange(33, 65))
        val generated = KeyFactory.getInstance("EC")
            .generatePublic(ECPublicKeySpec(ECPoint(x, y), p256Parameters()))
        return generated as? ECPublicKey
            ?: error("JCE 没有返回 EC 公钥：${generated.javaClass.name}")
    }

    /** JCE 公钥 -> 未压缩点。坐标要通过 `w`（ECPoint）取，`ECPublicKey` 上没有 affineX。 */
    fun encodePoint(publicKey: ECPublicKey): ByteArray =
        byteArrayOf(0x04) + publicKey.w.affineX.toFixed32() + publicKey.w.affineY.toFixed32()

    // ——————————————————————————————————————————————————————————
    // 软件密钥的持久化容器
    //
    // `[4 字节大端 pkcs8 长度][pkcs8][65 字节未压缩点]`
    //
    // 为什么要连公钥一起存：纯 JCE 无法从 EC 私钥反推公钥
    // （`ECPrivateKey` 只给 s，不给基点标量乘的结果）。
    // 早期版本想靠运行时缓存绕过去，结果是重启即失效 —— 直接持久化最省事也最可靠。
    // ——————————————————————————————————————————————————————————

    fun packSoftwareKey(pkcs8: ByteArray, rawPublicKey: ByteArray): ByteArray =
        byteArrayOf(
            (pkcs8.size ushr 24).toByte(),
            (pkcs8.size ushr 16).toByte(),
            (pkcs8.size ushr 8).toByte(),
            pkcs8.size.toByte(),
        ) + pkcs8 + rawPublicKey

    fun unpackSoftwareKey(packed: ByteArray): Pair<ByteArray, ByteArray> {
        require(packed.size > 4 + EcKeys.RAW_PUBLIC_KEY_SIZE) { "软件密钥文件损坏" }
        val length = ((packed[0].toInt() and 0xFF) shl 24) or
            ((packed[1].toInt() and 0xFF) shl 16) or
            ((packed[2].toInt() and 0xFF) shl 8) or
            (packed[3].toInt() and 0xFF)
        require(length > 0 && 4 + length + EcKeys.RAW_PUBLIC_KEY_SIZE == packed.size) {
            "软件密钥文件长度不自洽"
        }
        val pkcs8 = packed.copyOfRange(4, 4 + length)
        val rawPublicKey = packed.copyOfRange(4 + length, packed.size)
        require(EcKeys.isValidRawPoint(rawPublicKey)) { "软件密钥中的公钥不是合法 P-256 点" }
        return pkcs8 to rawPublicKey
    }

    private fun BigInteger.toFixed32(): ByteArray {
        val bytes = toByteArray()
        return when {
            bytes.size == 32 -> bytes
            bytes.size == 33 && bytes[0] == 0.toByte() -> bytes.copyOfRange(1, 33)
            bytes.size < 32 -> ByteArray(32 - bytes.size) + bytes
            else -> bytes.copyOfRange(bytes.size - 32, bytes.size)
        }
    }
}
