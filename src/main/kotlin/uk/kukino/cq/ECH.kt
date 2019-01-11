package uk.kukino.cq

import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECNamedCurveSpec
import org.bouncycastle.util.encoders.Base64
import java.math.BigInteger
import java.security.*
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec


class ECH(val curve: String = "secp256k1",
          val signAlgo: String = "SHA512withECDSA",
          val rand: SecureRandom = SecureRandom()) {

    val keySpec: ECNamedCurveSpec
    var provider = "BC"

    init {
        Security.addProvider(BouncyCastleProvider())
        val parameterSpec = ECNamedCurveTable.getParameterSpec(this.curve)
        keySpec = ECNamedCurveSpec(this.curve, parameterSpec.curve, parameterSpec.g, parameterSpec.n, parameterSpec.h, parameterSpec.seed)
    }

    private fun keyFactory() = KeyFactory.getInstance("EC")

    @Throws(NoSuchAlgorithmException::class, NoSuchProviderException::class, InvalidAlgorithmParameterException::class)
    fun createKeyPair(): KeyPair {
        val keyGen = KeyPairGenerator.getInstance("ECDSA", provider)
        val ecSpec = ECGenParameterSpec(this.curve)
        keyGen.initialize(ecSpec, this.rand)
        return keyGen.generateKeyPair()
    }

    fun privateAsB64(pvtKey: PrivateKey): String {
        val ecPvt = pvtKey as ECPrivateKey
        return Base64.toBase64String(ecPvt.s.toByteArray())
    }

    fun privateFromB64(b64: String): PrivateKey {
        return keyFactory().generatePrivate(ECPrivateKeySpec(BigInteger(Base64.decode(b64)), keySpec)) as ECPrivateKey
    }

    fun publicAsB64(pubKey: PublicKey): String {
        val pub = pubKey as ECPublicKey
        return Base64.toBase64String(pub.w.affineX.toByteArray()) + "|" + Base64.toBase64String(pub.w.affineY.toByteArray())
    }

    fun publicFromB64(b64: String): PublicKey {
        val (x, y) = b64.split("|").map { BigInteger(Base64.decode(it)) }
        val point = ECPoint(x, y)
        return keyFactory().generatePublic(ECPublicKeySpec(point, keySpec)) as ECPublicKey
    }

    fun sign(pvt: PrivateKey, payload: ByteArray): ByteArray {
        val signature = Signature.getInstance(signAlgo)
        signature.initSign(pvt)
        signature.update(payload)
        return signature.sign()
    }

    fun verify(pub: PublicKey, payload: ByteArray, sign: ByteArray): Boolean {
        val signature = Signature.getInstance(signAlgo)
        signature.initVerify(pub)
        signature.update(payload)
        return signature.verify(sign)
    }

    fun encrypt(key: SecretKey, iv: ByteArray, payload: ByteArray): ByteArray {
        val ivSpec = IvParameterSpec(iv)
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", provider)
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec, rand)
        return cipher.doFinal(payload)
    }

    fun decrypt(key: SecretKey, iv: ByteArray, payload: ByteArray): ByteArray {
        val ivSpec = IvParameterSpec(iv)
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", provider)
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec, rand)
        return cipher.doFinal(payload)
    }

    fun diffieHellman(pvt: PrivateKey, pub: PublicKey): SecretKey {
        val agreement = KeyAgreement.getInstance("ECCDH", provider)
        agreement.init(pvt)
        agreement.doPhase(pub, true)
        return agreement.generateSecret("SHA256")
    }

}