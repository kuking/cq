package uk.kukino.cq

import org.junit.Test
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import kotlin.random.Random

class ECHTtest {

    val underTest = ECH()

    @Test
    fun it_creates_key_pairs_with_correct_specs() {
        val kp = underTest.createKeyPair()
        assert(kp.private is ECPrivateKey)
        assert(kp.public is ECPublicKey)
        assert(kp.private.algorithm == "ECDSA")
        assert(kp.public.algorithm == "ECDSA")
    }

    @Test
    fun it_round_trips_private_b64() {
        val kp = underTest.createKeyPair()
        val serialised = underTest.privateAsB64(kp.private)
        println(serialised)
        val roundtrip = underTest.privateAsB64(underTest.privateFromB64(serialised))
        assert(serialised == roundtrip)
    }

    @Test
    fun it_round_trips_public_b64() {
        val kp = underTest.createKeyPair()
        val serialised = underTest.publicAsB64(kp.public)
        print(serialised)
        val roundtrip = underTest.publicAsB64(underTest.publicFromB64(serialised))
        assert(serialised == roundtrip)
    }

    @Test
    fun it_signs_and_verify() {
        val kp = underTest.createKeyPair()
        val payload = Random(System.currentTimeMillis()).nextBytes(2500)
        val signature = underTest.sign(kp.private, payload)
        assert(underTest.verify(kp.public, payload, signature))
    }

    @Test
    fun it_really_signs_and_verifies() {
        val kp = underTest.createKeyPair()
        val payload = Random(System.currentTimeMillis()).nextBytes(2500)
        val signature = underTest.sign(kp.private, payload)
        payload[0] = 0
        assert(!underTest.verify(kp.public, payload, signature))
    }

}