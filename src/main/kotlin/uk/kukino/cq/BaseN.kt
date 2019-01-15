package uk.kukino.cq

import java.math.BigInteger
import java.util.*

class BaseN(private val alphabet: CharArray) {

    private val base = BigInteger.valueOf(alphabet.size.toLong())

    companion object {
        val B16 = BaseN("0123456789abcdef".toCharArray())
        val B58 = BaseN("0123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".toCharArray())
        val B85 = BaseN("0123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz!@£$%^&*()_+-=[]{};':|,.<>?".toCharArray())

        fun toUnsigned(value: BigInteger): ByteArray {
            val signedValue = value.toByteArray()
            if (signedValue[0].toInt() != 0x00 || signedValue.size == 1) {
                return signedValue
            }
            return Arrays.copyOfRange(signedValue, 1, signedValue.size)
        }

        fun fromUnsigned(value: ByteArray): BigInteger {
            val signedValue = ByteArray(value.size + 1)
            System.arraycopy(value, 0, signedValue, 1, value.size)
            return BigInteger(signedValue)
        }
    }

    fun encode(source: BigInteger): String {
        var work = BigInteger(1, source.toByteArray())
        var qr: Array<BigInteger>
        val sb = StringBuilder()
        if (work == BigInteger.ZERO) sb.append(alphabet[0])
        while (work > BigInteger.ZERO) {
            qr = work.divideAndRemainder(base)
            val base58DigitVal = qr[1].intValueExact()
            sb.append(alphabet[base58DigitVal])
            work = qr[0]
        }
        return sb.reverse().toString()
    }

    fun decode(source: String): BigInteger {
        var value = BigInteger.ZERO
        source.forEach {
            value = value.multiply(base).add(alphabet.indexOf(it).toBigInteger())
        }
        return value
    }


}

