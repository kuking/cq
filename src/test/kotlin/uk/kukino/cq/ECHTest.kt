package uk.kukino.cq

import org.bouncycastle.util.encoders.Base64
import org.junit.Test
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import javax.crypto.spec.SecretKeySpec
import kotlin.random.Random

class ECHTtest {

    val ech = ECH()

    @Test
    fun it_creates_key_pairs_with_correct_specs() {
        val kp = ech.createKeyPair()
        assert(kp.private is ECPrivateKey)
        assert(kp.public is ECPublicKey)
        assert(kp.private.algorithm == "ECDSA")
        assert(kp.public.algorithm == "ECDSA")
    }

    @Test
    fun it_round_trips_private_b64() {
        val kp = ech.createKeyPair()
        val serialised = ech.privateAsB64(kp.private)
        println(serialised)
        val roundtrip = ech.privateAsB64(ech.privateFromB64(serialised))
        assert(serialised == roundtrip)
    }

    @Test
    fun it_round_trips_public_b64() {
        val kp = ech.createKeyPair()
        val serialised = ech.publicAsB64(kp.public)
        print(serialised)
        val roundtrip = ech.publicAsB64(ech.publicFromB64(serialised))
        assert(serialised == roundtrip)
    }

    @Test
    fun it_round_trips_public_b58() {
        val kp = ech.createKeyPair()
        val serialised = ech.publicAsB58(kp.public)
        print(serialised)
        val roundtrip = ech.publicAsB58(ech.publicFromB58(serialised))
        assert(serialised == roundtrip)
    }

    @Test
    fun it_signs_and_verify() {
        val kp = ech.createKeyPair()
        val payload = Random.nextBytes(2500)
        val signature = ech.sign(kp.private, payload)
        assert(ech.verify(kp.public, payload, signature))
    }

    @Test
    fun it_really_signs_and_verifies() {
        val kp = ech.createKeyPair()
        val payload = Random.nextBytes(2500)
        val signature = ech.sign(kp.private, payload)
        payload[0] = 0
        assert(!ech.verify(kp.public, payload, signature))
    }

    @Test
    fun it_encrypts_decrypts_symmetric() {
        val keyBits = Random.nextBytes(256 / 8)
        val key = SecretKeySpec(keyBits, "AES")
        val iv = Random.nextBytes(128 / 8)
        val payload = Random.nextBytes(3500)

        val enc = ech.encryptS(key, iv, payload)
        val dec = ech.decryptS(key, iv, enc)

        assert(payload.contentEquals(dec))
    }

    @Test
    fun it_derives_common_key() {
        val kpa = ech.createKeyPair()
        val kpb = ech.createKeyPair()

        val keyAB = ech.diffieHellman(kpa.private, kpb.public)
        val keyBA = ech.diffieHellman(kpb.private, kpa.public)

        val keyABb64 = Base64.toBase64String(keyAB.encoded)
        val keyBAb64 = Base64.toBase64String(keyBA.encoded)

        assert(keyAB == keyBA)
        assert(keyABb64 == keyBAb64)
    }

}