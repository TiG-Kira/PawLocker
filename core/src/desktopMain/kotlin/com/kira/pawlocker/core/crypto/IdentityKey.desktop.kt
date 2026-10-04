package com.kira.pawlocker.core.crypto

import com.kira.pawlocker.core.platform.PlatformEnv
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.PKCS8EncodedKeySpec
import javax.crypto.KeyAgreement

private const val CURVE = "secp256r1"

/**
 * Windows 侧的身份密钥。
 *
 * 用纯软件 P-256 密钥对，但 PKCS#8 落盘前经 DPAPI 封装，
 * 存在 `%APPDATA%\PawLocker\secure\key-<alias>`。
 *
 * ## 为什么不用 Windows CNG / TPM
 *
 * 理论上可以把私钥放进 TPM 并用 NCrypt 做不可导出签名，但那需要引入
 * 原生 JNI/JNA 层调用 `NCryptOpenStorageProvider` / `NCryptCreatePersistedKey`，
 * 代码量翻几倍，还得处理各种 TPM 固件差异。
 * 对「解锁家里电脑」这个威胁模型来说，DPAPI 提供的「跨用户不可解密」
 * 已经覆盖了主要风险（同机其他账户、把文件拷走的攻击者）。
 * 如果部署环境有更高要求，[IdentityKey] 接口本身就是为此预留的替换点。
 */
actual object IdentityKeyFactory {

    actual fun loadOrCreate(alias: String): IdentityKey {
        val stored = PlatformEnv.readSecure("key-$alias")
        if (stored != null) return runCatching { DesktopIdentityKey(alias, stored) }
            .getOrElse { error ->
                PlatformEnv.log("IdentityKeyFactory", "身份密钥损坏，将重新生成：${error.message}")
                generate(alias)
            }
        return generate(alias)
    }

    actual fun delete(alias: String) {
        PlatformEnv.deleteSecure("key-$alias")
    }

    private fun generate(alias: String): IdentityKey {
        val generator = KeyPairGenerator.getInstance("EC")
        generator.initialize(ECGenParameterSpec(CURVE))
        val keyPair = generator.generateKeyPair()

        val publicKey = EcJceDesktop.encodePoint(keyPair.public as ECPublicKey)
        val packed = EcJceDesktop.pack(keyPair.private.encoded, publicKey)
        PlatformEnv.writeSecure("key-$alias", packed)

        return DesktopIdentityKey(alias, packed)
    }
}

private class DesktopIdentityKey(
    override val alias: String,
    packed: ByteArray,
) : IdentityKey {

    private val privateKey: ECPrivateKey

    override val publicKey: ByteArray

    init {
        val (pkcs8, rawPublic) = EcJceDesktop.unpack(packed)
        val key = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(pkcs8))
        privateKey = key as? ECPrivateKey ?: error("存储的私钥不是 EC 私钥")
        publicKey = rawPublic
    }

    /** 私钥材料在软件中运算，静态保护由 DPAPI 提供。 */
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
            doPhase(EcJceDesktop.toPublicKey(peerPublicKey), true)
            generateSecret()
        }
}

/** P-256 的 JCE 互转工具（与 Android 侧实现一致，各自自包含便于审计）。 */
internal object EcJceDesktop {

    fun p256Parameters(): ECParameterSpec =
        AlgorithmParameters.getInstance("EC")
            .apply { init(ECGenParameterSpec(CURVE)) }
            .getParameterSpec(ECParameterSpec::class.java)

    fun toPublicKey(raw: ByteArray): ECPublicKey {
        require(EcKeys.isValidRawPoint(raw)) { "非法的 P-256 公钥点" }
        val x = BigInteger(1, raw.copyOfRange(1, 33))
        val y = BigInteger(1, raw.copyOfRange(33, 65))
        val generated = KeyFactory.getInstance("EC")
            .generatePublic(ECPublicKeySpec(ECPoint(x, y), p256Parameters()))
        return generated as? ECPublicKey
            ?: error("JCE 没有返回 EC 公钥：${generated.javaClass.name}")
    }

    /** 坐标在 [ECPublicKey] 上要通过 `w`（ECPoint）取，别写成 `publicKey.affineX`。 */
    fun encodePoint(publicKey: ECPublicKey): ByteArray =
        byteArrayOf(0x04) + publicKey.w.affineX.toFixed32() + publicKey.w.affineY.toFixed32()

    /** 容器格式：`[4 字节大端 pkcs8 长度][pkcs8][65 字节未压缩点]` */
    fun pack(pkcs8: ByteArray, rawPublicKey: ByteArray): ByteArray =
        byteArrayOf(
            (pkcs8.size ushr 24).toByte(),
            (pkcs8.size ushr 16).toByte(),
            (pkcs8.size ushr 8).toByte(),
            pkcs8.size.toByte(),
        ) + pkcs8 + rawPublicKey

    fun unpack(packed: ByteArray): Pair<ByteArray, ByteArray> {
        require(packed.size > 4 + EcKeys.RAW_PUBLIC_KEY_SIZE) { "身份密钥文件损坏" }
        val length = ((packed[0].toInt() and 0xFF) shl 24) or
            ((packed[1].toInt() and 0xFF) shl 16) or
            ((packed[2].toInt() and 0xFF) shl 8) or
            (packed[3].toInt() and 0xFF)
        require(length > 0 && 4 + length + EcKeys.RAW_PUBLIC_KEY_SIZE == packed.size) {
            "身份密钥文件长度不自洽"
        }
        val pkcs8 = packed.copyOfRange(4, 4 + length)
        val rawPublicKey = packed.copyOfRange(4 + length, packed.size)
        require(EcKeys.isValidRawPoint(rawPublicKey)) { "身份密钥中的公钥不是合法 P-256 点" }
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
