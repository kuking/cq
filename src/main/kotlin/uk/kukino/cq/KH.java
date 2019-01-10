package uk.kukino.cq;


import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class KH {

    public static void init() {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static KeyPair getKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDsA", "BC");
        // secp256k1 - secp384r1 - secp521r1 - sect571r1
//        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256k1");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("sect571r1");
        keyGen.initialize(ecSpec, new SecureRandom());
        return keyGen.generateKeyPair();
    }

    public static byte[] sign(KeyPair keyPair, byte[] payload) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
//        Signature signature = Signature.getInstance("SHA512withECDsA");
        Signature signature = Signature.getInstance("SHA256withECDsA");
        signature.initSign(keyPair.getPrivate());
        signature.update(payload);
        return signature.sign();
    }

    public static boolean verify(ECPublicKey publicKey, byte[] payload, byte[] sign) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withECDsA");
        signature.initVerify(publicKey);
        signature.update(payload);
        return signature.verify(sign);
    }

    public static ECPrivateKey asECPrivateKey(PrivateKey pk) {
        return (ECPrivateKey) pk;
    }

    public static ECPublicKey asECPublicKey(PublicKey pk) {
        return (ECPublicKey) pk;
    }

    public static PrivateKey base64ToPrivateKey(String encodedKey) throws Exception {
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
        return bytesToPrivateKey(decodedKey);
    }

    public static PrivateKey bytesToPrivateKey(byte[] pkcs8key) throws GeneralSecurityException {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pkcs8key);
        KeyFactory factory = KeyFactory.getInstance("EC");
        PrivateKey privateKey = factory.generatePrivate(spec);
        return privateKey;
    }

    public static PublicKey base64ToPublicKey(String encodedKey) throws Exception {
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
        return bytesToPublicKey(decodedKey);
    }

    public static PublicKey bytesToPublicKey(byte[] x509key) throws GeneralSecurityException {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(x509key);
        KeyFactory factory = KeyFactory.getInstance("EC");
        PublicKey publicKey = factory.generatePublic(spec);
        return publicKey;
    }


}
