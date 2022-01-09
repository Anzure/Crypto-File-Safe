package no.odit.crypto.util;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class RSA {

    public static KeyPair generateKeys() {
        try {
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(4096, random);
            KeyPair keys = keyGen.generateKeyPair();
            System.out.println("Public Key: " + savePublicKey(keys.getPublic()));
            System.out.println("Private Key: " + savePrivateKey(keys.getPrivate()));
            return keys;

        } catch (Exception e) {
            e.printStackTrace();
            throw new Error(e);
        }
    }

    public static byte[] encrypt(byte[] bytes, PublicKey key) {
        try {
            Cipher rsa = Cipher.getInstance("RSA");
            rsa.init(1, key);
            return rsa.doFinal(bytes);

        } catch (Exception e) {
            e.printStackTrace();
            throw new Error(e);
        }
    }

    public static byte[] decrypt(byte[] bytes, PrivateKey key) {
        try {
            Cipher rsa = Cipher.getInstance("RSA");
            rsa.init(2, key);
            return rsa.doFinal(bytes);

        } catch (Exception e) {
            e.printStackTrace();
            throw new Error(e);
        }
    }

    public static PrivateKey loadPrivateKey(String key64) throws Exception {
        byte[] clear = Base64.decodeBase64(key64.getBytes());
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(clear);
        KeyFactory fact = KeyFactory.getInstance("RSA");
        PrivateKey priv = fact.generatePrivate(keySpec);
        Arrays.fill(clear, (byte) 0);
        return priv;
    }

    public static PublicKey loadPublicKey(String stored) throws Exception {
        byte[] data = Base64.decodeBase64(stored);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
        KeyFactory fact = KeyFactory.getInstance("RSA");
        return fact.generatePublic(spec);
    }

    public static String savePrivateKey(PrivateKey priv) throws Exception {
        KeyFactory fact = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec spec = (PKCS8EncodedKeySpec) fact.getKeySpec(priv, PKCS8EncodedKeySpec.class);
        byte[] packed = spec.getEncoded();
        String key64 = Base64.encodeBase64String(packed);
        Arrays.fill(packed, (byte) 0);
        return key64;
    }

    public static String savePublicKey(PublicKey publ) throws Exception {
        KeyFactory fact = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec spec = (X509EncodedKeySpec) fact.getKeySpec(publ, X509EncodedKeySpec.class);
        return Base64.encodeBase64String(spec.getEncoded());
    }

}
