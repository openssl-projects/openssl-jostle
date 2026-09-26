/*
 *
 *   Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *   Licensed under the Apache License 2.0 (the "License"). You may not use
 *   this file except in compliance with the License.  You can obtain a copy
 *   in the file LICENSE in the source distribution or at
 *   https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */
package jostle.examples.fips;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.spec.HKDFParameterSpec;
import org.openssl.jostle.jcajce.spec.KBKDFParameterSpec;
import org.openssl.jostle.jcajce.spec.SSHKDFParameterSpec;
import org.openssl.jostle.jcajce.spec.SSKDFParameterSpec;
import org.openssl.jostle.util.encoders.Hex;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Key derivation functions in the FIPS module, served as `SecretKeyFactory`: PBKDF2, HKDF, the SP 800-108 and
 * SP 800-56C KDFs and the SSH KDF. The 3.5.8 module serves no scrypt or Argon2. Whether it refuses key inputs
 * shorter than 112 bits depends on fipsinstall configuration.
 */
public class FipsSecretKeyFactoryExamplesTest
        extends FipsExamples
{
    /**
     * PBKDF2 with HMAC-SHA256. JSLFIPS refuses a salt shorter than 16 bytes or fewer than 1000 iterations
     * with `InvalidKeySpecException`; the key length in `PBEKeySpec` is in bits.
     */
    @Test
    public void pbkdf2WithHmacSha256()
            throws Exception
    {
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256", "JSLFIPS");
        byte[] salt = "sixteen byte slt".getBytes(StandardCharsets.US_ASCII);
        byte[] k1 = f.generateSecret(new PBEKeySpec("correct horse".toCharArray(), salt, 10000, 256)).getEncoded();
        byte[] k2 = f.generateSecret(new PBEKeySpec("correct horse".toCharArray(), salt, 10000, 256)).getEncoded();
        Assertions.assertArrayEquals(k1, k2);
        Assertions.assertEquals(32, k1.length);
        Assertions.assertThrows(java.security.spec.InvalidKeySpecException.class, () -> f.generateSecret(
                new PBEKeySpec("correct horse".toCharArray(), "salt".getBytes(StandardCharsets.US_ASCII), 10000, 256)));
    }

    /**
     * Every PBKDF2 variant: the same inputs derive the same key, and a different salt a different key. The
     * password is UTF-8 encoded, except under `PBKDF2WithASCII`, which keeps the low 8 bits of each char.
     */
    @Test
    public void everyPbkdf2()
            throws Exception
    {
        String[] names = {"PBKDF2", "PBKDF2WithASCII", "PBKDF2WithHmacSHA1", "PBKDF2WithHmacSHA224",
                "PBKDF2WithHmacSHA384", "PBKDF2WithHmacSHA512", "PBKDF2WithHmacSHA512-224",
                "PBKDF2WithHmacSHA512-256", "PBKDF2WithHmacSHA3-224", "PBKDF2WithHmacSHA3-256",
                "PBKDF2WithHmacSHA3-384", "PBKDF2WithHmacSHA3-512"};
        char[] password = "correct horse".toCharArray();
        byte[] salt = "sixteen byte slt".getBytes(StandardCharsets.US_ASCII);
        byte[] salt2 = "sixteen byte sl2".getBytes(StandardCharsets.US_ASCII);
        for (String name : names)
        {
            SecretKeyFactory f = SecretKeyFactory.getInstance(name, "JSLFIPS");
            byte[] k1 = f.generateSecret(new PBEKeySpec(password, salt, 1000, 256)).getEncoded();
            byte[] k2 = f.generateSecret(new PBEKeySpec(password, salt, 1000, 256)).getEncoded();
            byte[] k3 = f.generateSecret(new PBEKeySpec(password, salt2, 1000, 256)).getEncoded();
            Assertions.assertEquals(32, k1.length, name);
            Assertions.assertArrayEquals(k1, k2, name);
            Assertions.assertFalse(Arrays.equals(k1, k3), name);
        }
    }

    /**
     * HKDF extract-and-expand with `HKDFParameterSpec(ikm, salt, info, lengthInBytes)`. The inputs are
     * RFC 5869 test case 1.
     */
    @Test
    public void hkdfSha256()
            throws Exception
    {
        byte[] ikm = Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] salt = Hex.decode("000102030405060708090a0b0c");
        byte[] info = Hex.decode("f0f1f2f3f4f5f6f7f8f9");
        SecretKeyFactory f = SecretKeyFactory.getInstance("HKDF-SHA256", "JSLFIPS");
        byte[] okm = f.generateSecret(new HKDFParameterSpec(ikm, salt, info, 42)).getEncoded();
        Assertions.assertEquals("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                + "34007208d5b887185865", Hex.toHexString(okm));
    }

    /**
     * HKDF over the other digests, and the single-step (SP 800-56C) KDF, which takes a shared secret and
     * the other info. Output lengths are in bytes; different info gives a different key.
     */
    @Test
    public void hkdfAndSingleStepKdf()
            throws Exception
    {
        byte[] secret = "a shared secret from a key agreement".getBytes(StandardCharsets.US_ASCII);
        byte[] info = "context A".getBytes(StandardCharsets.US_ASCII);
        byte[] info2 = "context B".getBytes(StandardCharsets.US_ASCII);
        String[] hkdfNames = {"HKDF-SHA384", "HKDF-SHA512"};
        for (String name : hkdfNames)
        {
            SecretKeyFactory f = SecretKeyFactory.getInstance(name, "JSLFIPS");
            byte[] k1 = f.generateSecret(new HKDFParameterSpec(secret, null, info, 48)).getEncoded();
            byte[] k2 = f.generateSecret(new HKDFParameterSpec(secret, null, info2, 48)).getEncoded();
            Assertions.assertEquals(48, k1.length, name);
            Assertions.assertFalse(Arrays.equals(k1, k2), name);
        }
        String[] ssNames = {"SSKDF-SHA1", "SSKDF-SHA224", "SSKDF-SHA256", "SSKDF-SHA384", "SSKDF-SHA512"};
        for (String name : ssNames)
        {
            SecretKeyFactory f = SecretKeyFactory.getInstance(name, "JSLFIPS");
            byte[] k1 = f.generateSecret(new SSKDFParameterSpec(secret, info, 32)).getEncoded();
            byte[] k2 = f.generateSecret(new SSKDFParameterSpec(secret, info2, 32)).getEncoded();
            Assertions.assertEquals(32, k1.length, name);
            Assertions.assertFalse(Arrays.equals(k1, k2), name);
        }
    }

    /**
     * SP 800-108 key-based KDF in counter mode: a key-derivation key, a label and a context. The HMAC
     * variants take any key length; the CMAC variants take an AES key of the size in their name.
     */
    @Test
    public void kbkdfCounterMode()
            throws Exception
    {
        byte[] label = "encryption".getBytes(StandardCharsets.US_ASCII);
        byte[] context = "session 42".getBytes(StandardCharsets.US_ASCII);
        String[] names = {"KBKDF-HMAC-SHA1", "KBKDF-HMAC-SHA224", "KBKDF-HMAC-SHA256", "KBKDF-HMAC-SHA384",
                "KBKDF-HMAC-SHA512", "KBKDF-CMAC-AES128", "KBKDF-CMAC-AES192", "KBKDF-CMAC-AES256"};
        int[] keyBytes = {32, 32, 32, 32, 32, 16, 24, 32};
        for (int i = 0; i < names.length; i++)
        {
            SecretKeyFactory f = SecretKeyFactory.getInstance(names[i], "JSLFIPS");
            byte[] ki = new byte[keyBytes[i]];
            byte[] k1 = f.generateSecret(new KBKDFParameterSpec(ki, label, context, 32)).getEncoded();
            byte[] k2 = f.generateSecret(new KBKDFParameterSpec(ki, label, null, 32)).getEncoded();
            Assertions.assertEquals(32, k1.length, names[i]);
            Assertions.assertFalse(Arrays.equals(k1, k2), names[i]);
        }
    }

    /**
     * The SSH key derivation of RFC 4253 section 7.2: the shared secret K, exchange hash H and session id
     * derive each of the six keys, chosen by the key type.
     */
    @Test
    public void sshKdf()
            throws Exception
    {
        byte[] k = Hex.decode("0000002100a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90");
        byte[] h = "exchange hash, one per key exchange".getBytes(StandardCharsets.US_ASCII);
        byte[] sessionId = h;
        String[] names = {"SSHKDF-SHA1", "SSHKDF-SHA224", "SSHKDF-SHA256", "SSHKDF-SHA384", "SSHKDF-SHA512"};
        for (String name : names)
        {
            SecretKeyFactory f = SecretKeyFactory.getInstance(name, "JSLFIPS");
            byte[] enc = f.generateSecret(new SSHKDFParameterSpec(k, h, sessionId,
                    SSHKDFParameterSpec.KeyType.ENCRYPTION_KEY_CLIENT_TO_SERVER, 32)).getEncoded();
            byte[] mac = f.generateSecret(new SSHKDFParameterSpec(k, h, sessionId,
                    SSHKDFParameterSpec.KeyType.INTEGRITY_KEY_CLIENT_TO_SERVER, 32)).getEncoded();
            Assertions.assertEquals(32, enc.length, name);
            Assertions.assertFalse(Arrays.equals(enc, mac), name);
        }
    }
}
