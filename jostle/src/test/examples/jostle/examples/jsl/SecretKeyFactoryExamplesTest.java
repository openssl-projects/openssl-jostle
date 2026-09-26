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
package jostle.examples.jsl;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.spec.Argon2KeySpec;
import org.openssl.jostle.jcajce.spec.HKDFParameterSpec;
import org.openssl.jostle.jcajce.spec.KBKDFParameterSpec;
import org.openssl.jostle.jcajce.spec.SSHKDFParameterSpec;
import org.openssl.jostle.jcajce.spec.SSKDFParameterSpec;
import org.openssl.jostle.jcajce.spec.ScryptKeySpec;
import org.openssl.jostle.util.encoders.Hex;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Key derivation functions, all served as `SecretKeyFactory`: pass the inputs as a key spec to
 * `generateSecret` and read the derived bytes with `getEncoded()`. Password-based KDFs take the JDK's
 * `PBEKeySpec` or a Jostle spec; the others take a Jostle parameter spec.
 */
public class SecretKeyFactoryExamplesTest
        extends JslExamples
{
    /**
     * PBKDF2 with HMAC-SHA256. The key length in `PBEKeySpec` is in bits. The inputs are the published
     * PBKDF2-HMAC-SHA256 vector ("password", "salt", one iteration); use far more iterations in practice.
     */
    @Test
    public void pbkdf2WithHmacSha256()
            throws Exception
    {
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256", "JSL");
        PBEKeySpec spec = new PBEKeySpec("password".toCharArray(),
                "salt".getBytes(StandardCharsets.US_ASCII), 1, 256);
        byte[] key = f.generateSecret(spec).getEncoded();
        Assertions.assertEquals("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
                Hex.toHexString(key));
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
                "PBKDF2WithHmacSHA3-384", "PBKDF2WithHmacSHA3-512", "PBKDF2WithHmacMD5",
                "PBKDF2WithHmacMD5-SHA1", "PBKDF2WithHmacRIPEMD160", "PBKDF2WithHmacSM3",
                "PBKDF2WithHmacBLAKE2B-512", "PBKDF2WithHmacBLAKE2S-256"};
        char[] password = "correct horse".toCharArray();
        byte[] salt = "sixteen byte slt".getBytes(StandardCharsets.US_ASCII);
        byte[] salt2 = "sixteen byte sl2".getBytes(StandardCharsets.US_ASCII);
        for (String name : names)
        {
            SecretKeyFactory f = SecretKeyFactory.getInstance(name, "JSL");
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
        SecretKeyFactory f = SecretKeyFactory.getInstance("HKDF-SHA256", "JSL");
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
            SecretKeyFactory f = SecretKeyFactory.getInstance(name, "JSL");
            byte[] k1 = f.generateSecret(new HKDFParameterSpec(secret, null, info, 48)).getEncoded();
            byte[] k2 = f.generateSecret(new HKDFParameterSpec(secret, null, info2, 48)).getEncoded();
            Assertions.assertEquals(48, k1.length, name);
            Assertions.assertFalse(Arrays.equals(k1, k2), name);
        }
        String[] ssNames = {"SSKDF-SHA1", "SSKDF-SHA224", "SSKDF-SHA256", "SSKDF-SHA384", "SSKDF-SHA512"};
        for (String name : ssNames)
        {
            SecretKeyFactory f = SecretKeyFactory.getInstance(name, "JSL");
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
            SecretKeyFactory f = SecretKeyFactory.getInstance(names[i], "JSL");
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
            SecretKeyFactory f = SecretKeyFactory.getInstance(name, "JSL");
            byte[] enc = f.generateSecret(new SSHKDFParameterSpec(k, h, sessionId,
                    SSHKDFParameterSpec.KeyType.ENCRYPTION_KEY_CLIENT_TO_SERVER, 32)).getEncoded();
            byte[] mac = f.generateSecret(new SSHKDFParameterSpec(k, h, sessionId,
                    SSHKDFParameterSpec.KeyType.INTEGRITY_KEY_CLIENT_TO_SERVER, 32)).getEncoded();
            Assertions.assertEquals(32, enc.length, name);
            Assertions.assertFalse(Arrays.equals(enc, mac), name);
        }
    }

    /**
     * scrypt with `ScryptKeySpec(password, salt, N, r, p, keyLengthInBits)`. The inputs are the RFC 7914
     * vector ("password", "NaCl", N = 1024, r = 8, p = 16).
     */
    @Test
    public void scrypt()
            throws Exception
    {
        SecretKeyFactory f = SecretKeyFactory.getInstance("SCRYPT", "JSL");
        ScryptKeySpec spec = new ScryptKeySpec("password".toCharArray(),
                "NaCl".getBytes(StandardCharsets.US_ASCII), 1024, 8, 16, 512);
        byte[] key = f.generateSecret(spec).getEncoded();
        Assertions.assertEquals("fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162"
                + "2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640", Hex.toHexString(key));
    }

    /**
     * Argon2id, version 1.3, with memory in kibibytes and the key length in bits. The same inputs derive
     * the same key; a different salt, a different key.
     */
    @Test
    public void argon2id()
            throws Exception
    {
        SecretKeyFactory f = SecretKeyFactory.getInstance("ARGON2", "JSL");
        char[] password = "correct horse".toCharArray();
        byte[] salt = "sixteen byte slt".getBytes(StandardCharsets.US_ASCII);
        byte[] k1 = f.generateSecret(new Argon2KeySpec(password, salt, 3, 4096, 1, 256)).getEncoded();
        byte[] k2 = f.generateSecret(new Argon2KeySpec(password, salt, 3, 4096, 1, 256)).getEncoded();
        byte[] k3 = f.generateSecret(new Argon2KeySpec(password, "sixteen byte sl2".getBytes(
                StandardCharsets.US_ASCII), 3, 4096, 1, 256)).getEncoded();
        Assertions.assertEquals(32, k1.length);
        Assertions.assertArrayEquals(k1, k2);
        Assertions.assertFalse(Arrays.equals(k1, k3));
    }
}
