package com.kira.pawlocker.core.crypto

import com.kira.pawlocker.core.hexToBytes
import com.kira.pawlocker.core.toHex
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class EcKeysTest {

    /** P-256 曲线的基点 G（SEC 2 / NIST 标准值）。 */
    private val generator = (
        "04" +
            "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296" +
            "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
        ).hexToBytes()

    @Test
    fun `基点常量本身符合未压缩点格式`() {
        // 先确认测试数据没抄错，否则后面所有断言都失去意义
        assertEquals(65, generator.size)
        assertEquals(0x04, generator[0].toInt())
        assertTrue(EcKeys.isValidRawPoint(generator))
    }

    @Test
    fun `raw 到 SPKI 的固定前缀与长度`() {
        val spki = EcKeys.rawToSpki(generator)

        assertEquals(91, spki.size, "26 字节 DER 前缀 + 65 字节点")
        assertEquals(
            "3059301306072a8648ce3d020106082a8648ce3d030107034200",
            spki.copyOfRange(0, 26).toHex(),
            "DER 前缀必须是 ecPublicKey + prime256v1 + BIT STRING",
        )
        assertContentEquals(generator, spki.copyOfRange(26, 91))
    }

    @Test
    fun `SPKI 与 raw 互为逆运算`() {
        assertContentEquals(generator, EcKeys.spkiToRaw(EcKeys.rawToSpki(generator)))
    }

    @Test
    fun `SPKI 长度不符时拒绝解析`() {
        assertFailsWith<IllegalArgumentException> { EcKeys.spkiToRaw(ByteArray(90)) }
        assertFailsWith<IllegalArgumentException> { EcKeys.spkiToRaw(ByteArray(92)) }
        assertFailsWith<IllegalArgumentException> { EcKeys.spkiToRaw(ByteArray(0)) }
    }

    @Test
    fun `非法点被 isValidRawPoint 拒绝`() {
        // 长度不对
        assertFalse(EcKeys.isValidRawPoint(ByteArray(64)))
        assertFalse(EcKeys.isValidRawPoint(ByteArray(66)))
        assertFalse(EcKeys.isValidRawPoint(ByteArray(0)))

        // 未压缩标记不对
        assertFalse(EcKeys.isValidRawPoint(ByteArray(65).also { it[0] = 0x02 }))
        assertFalse(EcKeys.isValidRawPoint(ByteArray(65).also { it[0] = 0x00 }))

        // X 或 Y 全零（无穷远点或未初始化数据）
        val zeroX = generator.copyOf().also { it.fill(0, 1, 33) }
        assertFalse(EcKeys.isValidRawPoint(zeroX), "X 全零必须拒绝")

        val zeroY = generator.copyOf().also { it.fill(0, 33, 65) }
        assertFalse(EcKeys.isValidRawPoint(zeroY), "Y 全零必须拒绝")
    }

    @Test
    fun `非法点无法包装成 SPKI`() {
        assertFailsWith<IllegalArgumentException> { EcKeys.rawToSpki(ByteArray(65)) }
    }

    @Test
    fun `长度常量与实现一致`() {
        assertEquals(65, EcKeys.RAW_PUBLIC_KEY_SIZE)
        assertEquals(32, EcKeys.SCALAR_SIZE)
        assertEquals(
            EcKeys.RAW_PUBLIC_KEY_SIZE,
            EcKeys.spkiToRaw(EcKeys.rawToSpki(generator)).size,
        )
    }
}
