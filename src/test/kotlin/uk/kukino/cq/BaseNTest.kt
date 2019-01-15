package uk.kukino.cq

import org.junit.Test
import java.math.BigInteger
import kotlin.random.Random

class BaseNTest {

    @Test
    fun it_handles_zero() {
        val bytes = byteArrayOf(0)
        val encoded = BaseN.B16.encode(BigInteger(bytes))
        val decoded = BaseN.B16.decode(encoded)
        assert(bytes.contentEquals(BaseN.toUnsigned(decoded)))
    }

    @Test
    fun it_handles_ones() {
        val bytes = byteArrayOf(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1)
        val encoded = BaseN.B58.encode(BigInteger(bytes))
        val decoded = BaseN.B58.decode(encoded)
        assert(bytes.contentEquals(BaseN.toUnsigned(decoded)))
    }

    @Test
    fun it_round_trips_B58() {
        val bytes = Random.nextBytes(100)
        val encoded = BaseN.B58.encode(BigInteger(bytes))
        val decoded = BaseN.B58.decode(encoded)
        assert(bytes.contentEquals(BaseN.toUnsigned(decoded)))
    }

    @Test
    fun it_round_trips_B16() {
        val bytes = Random.nextBytes(100)
        val encoded = BaseN.B16.encode(BigInteger(bytes))
        val decoded = BaseN.B16.decode(encoded)
        assert(bytes.contentEquals(BaseN.toUnsigned(decoded)))
    }

    @Test
    fun it_round_trips_B85() {
        val bytes = Random.nextBytes(100)
        val encoded = BaseN.B85.encode(BigInteger(bytes))
        val decoded = BaseN.B85.decode(encoded)
        assert(bytes.contentEquals(BaseN.toUnsigned(decoded)))
    }

}