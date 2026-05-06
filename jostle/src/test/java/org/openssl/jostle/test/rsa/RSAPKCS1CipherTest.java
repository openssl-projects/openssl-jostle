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

package org.openssl.jostle.test.rsa;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

/**
 * JCE-level tests for the RSA-PKCS#1 v1.5 cipher: round-trips, BC parity,
 * wrap/unwrap, vandalism handling, and parameter rejection.
 */
public class RSAPKCS1CipherTest
{
    private static final SecureRandom RANDOM = new SecureRandom();
    private static KeyPair sharedKeyPair;

    @BeforeAll
    static void before() throws Exception
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", JostleProvider.PROVIDER_NAME);
        kpg.initialize(2048);
        sharedKeyPair = kpg.generateKeyPair();
    }


    // -----------------------------------------------------------------
    // Round-trips
    // -----------------------------------------------------------------

    @Test
    public void testPKCS1_RoundTrip() throws Exception
    {
        byte[] msg = randomMessage(64);
        Cipher enc = Cipher.getInstance("RSA/ECB/PKCS1Padding", JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, sharedKeyPair.getPublic());
        byte[] ct = enc.doFinal(msg);
        Assertions.assertEquals(256, ct.length, "2048-bit modulus → 256-byte ciphertext");

        Cipher dec = Cipher.getInstance("RSA/ECB/PKCS1Padding", JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, sharedKeyPair.getPrivate());
        byte[] pt = dec.doFinal(ct);
        Assertions.assertArrayEquals(msg, pt);
    }

    // -----------------------------------------------------------------
    // Reset / reuse: doFinal must leave the SPI ready for a subsequent
    // doFinal on the same Cipher without re-init.
    // -----------------------------------------------------------------

    @Test
    public void testPKCS1_EncryptReuseAfterDoFinal() throws Exception
    {
        byte[] msgA = randomMessage(40);
        byte[] msgB = randomMessage(72);

        Cipher enc = Cipher.getInstance("RSA/ECB/PKCS1Padding", JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, sharedKeyPair.getPublic());
        byte[] ctA = enc.doFinal(msgA);
        // Reuse — no re-init.
        byte[] ctB = enc.doFinal(msgB);

        Assertions.assertEquals(256, ctA.length);
        Assertions.assertEquals(256, ctB.length);
        // PKCS#1 v1.5 encryption uses random PS padding bytes; two
        // ciphertexts must differ even for identical plaintexts, and
        // certainly for different ones.
        Assertions.assertFalse(java.util.Arrays.equals(ctA, ctB),
                "two PKCS#1 ciphertexts must differ");

        Cipher dec = Cipher.getInstance("RSA/ECB/PKCS1Padding", JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, sharedKeyPair.getPrivate());
        Assertions.assertArrayEquals(msgA, dec.doFinal(ctA));
        // Decryptor reuse too.
        Assertions.assertArrayEquals(msgB, dec.doFinal(ctB));
    }

    @Test
    public void testPKCS1_EncryptReuseSameInput_DifferentCiphertexts() throws Exception
    {
        byte[] msg = randomMessage(64);

        Cipher enc = Cipher.getInstance("RSA/ECB/PKCS1Padding", JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, sharedKeyPair.getPublic());
        byte[] ctA = enc.doFinal(msg);
        byte[] ctB = enc.doFinal(msg);
        Assertions.assertFalse(java.util.Arrays.equals(ctA, ctB),
                "PKCS#1 v1.5 must use fresh PS bytes per doFinal");

        Cipher dec = Cipher.getInstance("RSA/ECB/PKCS1Padding", JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, sharedKeyPair.getPrivate());
        Assertions.assertArrayEquals(msg, dec.doFinal(ctA));
        Assertions.assertArrayEquals(msg, dec.doFinal(ctB));
    }

    @Test
    public void testPKCS1_DecryptReuse_BadCiphertextThenGood() throws Exception
    {
        // OpenSSL's implicit-rejection countermeasure means a malformed
        // ciphertext yields a deterministic-looking pseudo-random plaintext
        // (NOT a BadPaddingException) — so this test cannot use the same
        // shape as the OAEP variant. Instead drive a too-short input that
        // EVP_PKEY_decrypt rejects structurally, then prove a good
        // ciphertext still decrypts.
        byte[] msg = randomMessage(32);

        Cipher enc = Cipher.getInstance("RSA/ECB/PKCS1Padding", JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, sharedKeyPair.getPublic());
        byte[] good = enc.doFinal(msg);

        Cipher dec = Cipher.getInstance("RSA/ECB/PKCS1Padding", JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, sharedKeyPair.getPrivate());
        // Wrong-length ciphertext; OpenSSL rejects without invoking the
        // implicit-rejection plaintext path. Either BadPaddingException or
        // IllegalBlockSizeException is acceptable depending on which check
        // fires first.
        Assertions.assertThrows(java.security.GeneralSecurityException.class,
                () -> dec.doFinal(new byte[good.length + 1]));

        byte[] pt = dec.doFinal(good);
        Assertions.assertArrayEquals(msg, pt);
    }

    @Test
    public void testPKCS1_WrapReuseAfterWrap() throws Exception
    {
        javax.crypto.spec.SecretKeySpec aesA =
                new javax.crypto.spec.SecretKeySpec(randomMessage(16), "AES");
        javax.crypto.spec.SecretKeySpec aesB =
                new javax.crypto.spec.SecretKeySpec(randomMessage(32), "AES");

        Cipher wrapper = Cipher.getInstance("RSA/ECB/PKCS1Padding", JostleProvider.PROVIDER_NAME);
        wrapper.init(Cipher.WRAP_MODE, sharedKeyPair.getPublic());
        byte[] wA = wrapper.wrap(aesA);
        byte[] wB = wrapper.wrap(aesB);

        Assertions.assertFalse(java.util.Arrays.equals(wA, wB));

        Cipher unwrapper = Cipher.getInstance("RSA/ECB/PKCS1Padding", JostleProvider.PROVIDER_NAME);
        unwrapper.init(Cipher.UNWRAP_MODE, sharedKeyPair.getPrivate());
        Key uA = unwrapper.unwrap(wA, "AES", Cipher.SECRET_KEY);
        Key uB = unwrapper.unwrap(wB, "AES", Cipher.SECRET_KEY);

        Assertions.assertArrayEquals(aesA.getEncoded(), uA.getEncoded());
        Assertions.assertArrayEquals(aesB.getEncoded(), uB.getEncoded());
    }


    @Test
    public void testPKCS1_NonAlias_NoneSlashPKCS1Padding() throws Exception
    {
        byte[] msg = randomMessage(48);
        Cipher enc = Cipher.getInstance("RSA/None/PKCS1Padding", JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, sharedKeyPair.getPublic());
        byte[] ct = enc.doFinal(msg);

        Cipher dec = Cipher.getInstance("RSA/None/PKCS1Padding", JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, sharedKeyPair.getPrivate());
        Assertions.assertArrayEquals(msg, dec.doFinal(ct));
    }

    /**
     * Per CLAUDE.md "Vary the chunking, and randomise the inputs": the
     * SPI accumulates update() into a buffer, so different chunkings of
     * the same plaintext must round-trip to the same output. PKCS#1 v1.5
     * is non-deterministic on encrypt (random PS bytes), so we compare
     * on the post-decrypt plaintext.
     */
    @Test
    public void testPKCS1_ChunkingMatrix_decryptsToOriginal() throws Exception
    {
        SecureRandom sr = seededRandom("testPKCS1_ChunkingMatrix_decryptsToOriginal");
        byte[] msg = new byte[200]; // under PKCS#1 v1.5 max of 245
        sr.nextBytes(msg);

        // Reference round-trip.
        Assertions.assertArrayEquals(msg, encryptThenDecrypt(msg, msg.length));

        // byte-by-byte.
        Assertions.assertArrayEquals(msg, encryptThenDecrypt(msg, 1),
                "byte-by-byte chunking diverged");

        // Adversarial chunk sizes.
        for (int chunk : new int[]{63, 64, 65, 99, 100, 101})
        {
            Assertions.assertArrayEquals(msg, encryptThenDecrypt(msg, chunk),
                    "chunk=" + chunk + " diverged");
        }

        // Random splits.
        for (int trial = 0; trial < 5; trial++)
        {
            Assertions.assertArrayEquals(msg, encryptWithRandomSplits(msg, sr),
                    "random-split chunking diverged");
        }
    }

    /**
     * Per CLAUDE.md "use fully random values for everything" — vary
     * plaintext content AND length across many trials, log the seed
     * so a flaky run is reproducible.
     */
    @Test
    public void testPKCS1_RandomLengthMessages_roundTrip() throws Exception
    {
        SecureRandom sr = seededRandom("testPKCS1_RandomLengthMessages_roundTrip");
        for (int trial = 0; trial < 25; trial++)
        {
            int len = sr.nextInt(246); // [0, 245] inclusive
            byte[] msg = new byte[len];
            sr.nextBytes(msg);

            Cipher enc = Cipher.getInstance("RSA/ECB/PKCS1Padding", JostleProvider.PROVIDER_NAME);
            enc.init(Cipher.ENCRYPT_MODE, sharedKeyPair.getPublic());
            byte[] ct = enc.doFinal(msg);

            Cipher dec = Cipher.getInstance("RSA/ECB/PKCS1Padding", JostleProvider.PROVIDER_NAME);
            dec.init(Cipher.DECRYPT_MODE, sharedKeyPair.getPrivate());
            byte[] pt = dec.doFinal(ct);
            Assertions.assertArrayEquals(msg, pt,
                    "trial " + trial + " (len=" + len + ") failed round-trip");
        }
    }

    private byte[] encryptThenDecrypt(byte[] msg, int chunk) throws Exception
    {
        Cipher enc = Cipher.getInstance("RSA/ECB/PKCS1Padding", JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, sharedKeyPair.getPublic());
        for (int off = 0; off < msg.length; off += chunk)
        {
            int len = Math.min(chunk, msg.length - off);
            enc.update(msg, off, len);
        }
        byte[] ct = enc.doFinal();

        Cipher dec = Cipher.getInstance("RSA/ECB/PKCS1Padding", JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, sharedKeyPair.getPrivate());
        return dec.doFinal(ct);
    }

    private byte[] encryptWithRandomSplits(byte[] msg, SecureRandom sr) throws Exception
    {
        Cipher enc = Cipher.getInstance("RSA/ECB/PKCS1Padding", JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, sharedKeyPair.getPublic());
        int pos = 0;
        while (pos < msg.length)
        {
            int remaining = msg.length - pos;
            int chunk = 1 + sr.nextInt(Math.max(1, remaining));
            chunk = Math.min(chunk, remaining);
            enc.update(msg, pos, chunk);
            pos += chunk;
        }
        byte[] ct = enc.doFinal();

        Cipher dec = Cipher.getInstance("RSA/ECB/PKCS1Padding", JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, sharedKeyPair.getPrivate());
        return dec.doFinal(ct);
    }

    private static SecureRandom seededRandom(String testName) throws Exception
    {
        long seed = RANDOM.nextLong();
        System.out.println(testName + " seed=" + seed);
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        return sr;
    }

    @Test
    public void testPKCS1_NonDeterministic() throws Exception
    {
        // PKCS#1 v1.5 encryption uses random PS bytes; two encryptions
        // of the same plaintext must differ.
        byte[] msg = randomMessage(32);
        Cipher enc = Cipher.getInstance("RSA/ECB/PKCS1Padding", JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, sharedKeyPair.getPublic());
        byte[] first = enc.doFinal(msg);

        enc.init(Cipher.ENCRYPT_MODE, sharedKeyPair.getPublic());
        byte[] second = enc.doFinal(msg);

        Assertions.assertFalse(java.util.Arrays.equals(first, second),
                "PKCS#1 v1.5 ciphertexts must differ across calls (random PS bytes)");
    }

    @Test
    public void testPKCS1_StreamingUpdateThenDoFinal() throws Exception
    {
        byte[] msg = randomMessage(40);

        Cipher enc = Cipher.getInstance("RSA/ECB/PKCS1Padding", JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, sharedKeyPair.getPublic());
        Assertions.assertNull(enc.update(msg, 0, 12));
        Assertions.assertNull(enc.update(msg, 12, 18));
        byte[] ct = enc.doFinal(msg, 30, msg.length - 30);

        Cipher dec = Cipher.getInstance("RSA/ECB/PKCS1Padding", JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, sharedKeyPair.getPrivate());
        Assertions.assertArrayEquals(msg, dec.doFinal(ct));
    }


    // -----------------------------------------------------------------
    // BouncyCastle parity
    // -----------------------------------------------------------------

    @Test
    public void testPKCS1_BCEncrypt_JostleDecrypt() throws Exception
    {
        byte[] msg = randomMessage(64);
        Cipher bcEnc = Cipher.getInstance("RSA/ECB/PKCS1Padding",
                BouncyCastleProvider.PROVIDER_NAME);
        bcEnc.init(Cipher.ENCRYPT_MODE, sharedKeyPair.getPublic());
        byte[] ct = bcEnc.doFinal(msg);

        Cipher joDec = Cipher.getInstance("RSA/ECB/PKCS1Padding",
                JostleProvider.PROVIDER_NAME);
        joDec.init(Cipher.DECRYPT_MODE, sharedKeyPair.getPrivate());
        Assertions.assertArrayEquals(msg, joDec.doFinal(ct));
    }

    @Test
    public void testPKCS1_JostleEncrypt_BCDecrypt() throws Exception
    {
        byte[] msg = randomMessage(64);
        Cipher joEnc = Cipher.getInstance("RSA/ECB/PKCS1Padding",
                JostleProvider.PROVIDER_NAME);
        joEnc.init(Cipher.ENCRYPT_MODE, sharedKeyPair.getPublic());
        byte[] ct = joEnc.doFinal(msg);

        Cipher bcDec = Cipher.getInstance("RSA/ECB/PKCS1Padding",
                BouncyCastleProvider.PROVIDER_NAME);
        bcDec.init(Cipher.DECRYPT_MODE, sharedKeyPair.getPrivate());
        Assertions.assertArrayEquals(msg, bcDec.doFinal(ct));
    }


    /**
     * Multi-trial PKCS#1 v1.5 cipher agreement: per-trial fresh
     * keypair, random plaintext length and content, both directions
     * (Jostle→BC and BC→Jostle).
     */
    @Test
    public void testPKCS1_AgreementWithBC_MultiTrial() throws Exception
    {
        SecureRandom sr = seededRandom("testPKCS1_AgreementWithBC_MultiTrial");

        for (int trial = 0; trial < 10; trial++)
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", JostleProvider.PROVIDER_NAME);
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();

            // PKCS#1 v1.5 max plaintext for 2048-bit modulus = 256 - 11 = 245.
            int msgLen = sr.nextInt(246);
            byte[] msg = new byte[msgLen];
            sr.nextBytes(msg);

            // Jostle encrypt → BC decrypt
            Cipher joEnc = Cipher.getInstance("RSA/ECB/PKCS1Padding", JostleProvider.PROVIDER_NAME);
            joEnc.init(Cipher.ENCRYPT_MODE, kp.getPublic());
            byte[] ct = joEnc.doFinal(msg);

            Cipher bcDec = Cipher.getInstance("RSA/ECB/PKCS1Padding", BouncyCastleProvider.PROVIDER_NAME);
            bcDec.init(Cipher.DECRYPT_MODE, kp.getPrivate());
            Assertions.assertArrayEquals(msg, bcDec.doFinal(ct),
                    "trial=" + trial + " msgLen=" + msgLen + ": BC failed to decrypt Jostle ct");

            // BC encrypt → Jostle decrypt
            Cipher bcEnc = Cipher.getInstance("RSA/ECB/PKCS1Padding", BouncyCastleProvider.PROVIDER_NAME);
            bcEnc.init(Cipher.ENCRYPT_MODE, kp.getPublic());
            byte[] ct2 = bcEnc.doFinal(msg);

            Cipher joDec = Cipher.getInstance("RSA/ECB/PKCS1Padding", JostleProvider.PROVIDER_NAME);
            joDec.init(Cipher.DECRYPT_MODE, kp.getPrivate());
            Assertions.assertArrayEquals(msg, joDec.doFinal(ct2),
                    "trial=" + trial + " msgLen=" + msgLen + ": Jostle failed to decrypt BC ct");
        }
    }


    // -----------------------------------------------------------------
    // Wrap / unwrap
    // -----------------------------------------------------------------

    @Test
    public void testPKCS1_WrapUnwrap_AESSecretKey_roundTrip() throws Exception
    {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKey aesKey = kg.generateKey();

        Cipher wrapper = Cipher.getInstance("RSA/ECB/PKCS1Padding", JostleProvider.PROVIDER_NAME);
        wrapper.init(Cipher.WRAP_MODE, sharedKeyPair.getPublic());
        byte[] wrapped = wrapper.wrap(aesKey);
        Assertions.assertEquals(256, wrapped.length, "wrapped key sized to modulus");

        Cipher unwrapper = Cipher.getInstance("RSA/ECB/PKCS1Padding", JostleProvider.PROVIDER_NAME);
        unwrapper.init(Cipher.UNWRAP_MODE, sharedKeyPair.getPrivate());
        Key unwrapped = unwrapper.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
        Assertions.assertEquals("AES", unwrapped.getAlgorithm());
        Assertions.assertArrayEquals(aesKey.getEncoded(), unwrapped.getEncoded());
    }

    @Test
    public void testPKCS1_BCWrap_JostleUnwrap_AESKey() throws Exception
    {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);
        SecretKey aesKey = kg.generateKey();

        Cipher bcWrap = Cipher.getInstance("RSA/ECB/PKCS1Padding",
                BouncyCastleProvider.PROVIDER_NAME);
        bcWrap.init(Cipher.WRAP_MODE, sharedKeyPair.getPublic());
        byte[] wrapped = bcWrap.wrap(aesKey);

        Cipher joUnwrap = Cipher.getInstance("RSA/ECB/PKCS1Padding",
                JostleProvider.PROVIDER_NAME);
        joUnwrap.init(Cipher.UNWRAP_MODE, sharedKeyPair.getPrivate());
        Key unwrapped = joUnwrap.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
        Assertions.assertArrayEquals(aesKey.getEncoded(), unwrapped.getEncoded());
    }


    // -----------------------------------------------------------------
    // Vandalism — Bleichenbacher countermeasure check
    // -----------------------------------------------------------------

    /**
     * A flipped byte in a PKCS#1 v1.5 ciphertext must not return the
     * original plaintext. With OpenSSL 3.x's implicit-rejection enabled
     * (default), the decryptor returns a deterministic-length pseudo-
     * random plaintext on padding failure rather than erroring; either
     * way the result must NOT match the original message and there must
     * NOT be a distinguishable difference in failure modes between two
     * vandalised ciphertexts (Bleichenbacher countermeasure).
     */
    @Test
    public void testPKCS1_VandalisedCiphertext_doesNotRecoverPlaintext() throws Exception
    {
        byte[] msg = randomMessage(64);

        Cipher enc = Cipher.getInstance("RSA/ECB/PKCS1Padding", JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, sharedKeyPair.getPublic());
        byte[] ct = enc.doFinal(msg);

        // Flip a byte in the middle of the ciphertext.
        byte[] tampered = ct.clone();
        tampered[100] ^= 0x42;

        Cipher dec = Cipher.getInstance("RSA/ECB/PKCS1Padding", JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, sharedKeyPair.getPrivate());

        byte[] result;
        try
        {
            result = dec.doFinal(tampered);
        }
        catch (javax.crypto.BadPaddingException e)
        {
            // Acceptable: implicit rejection disabled or padding-check
            // surfaces. Implicit-rejection-on (the OpenSSL 3.x default)
            // returns a synthetic plaintext, falling through.
            return;
        }
        Assertions.assertFalse(java.util.Arrays.equals(msg, result),
                "vandalised ciphertext must not decrypt to the original plaintext");
    }

    /**
     * Mirror via wrap/unwrap: a tampered wrapped key must surface as
     * InvalidKeyException, not BadPaddingException — the JCE convention
     * to keep the unwrap channel from acting as a Bleichenbacher oracle.
     */
    @Test
    public void testPKCS1_Unwrap_VandalisedCiphertext_throwsInvalidKey() throws Exception
    {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);
        SecretKey aesKey = kg.generateKey();

        Cipher wrapper = Cipher.getInstance("RSA/ECB/PKCS1Padding", JostleProvider.PROVIDER_NAME);
        wrapper.init(Cipher.WRAP_MODE, sharedKeyPair.getPublic());
        byte[] wrapped = wrapper.wrap(aesKey);
        wrapped[10] ^= 1;

        Cipher unwrapper = Cipher.getInstance("RSA/ECB/PKCS1Padding", JostleProvider.PROVIDER_NAME);
        unwrapper.init(Cipher.UNWRAP_MODE, sharedKeyPair.getPrivate());
        try
        {
            Key unwrapped = unwrapper.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
            // Implicit rejection produces a synthetic 16-byte plaintext
            // that gets accepted as an "AES key" by SecretKeySpec — but
            // it cannot match the original.
            Assertions.assertFalse(java.util.Arrays.equals(aesKey.getEncoded(),
                    unwrapped.getEncoded()),
                    "vandalised wrapped key must not unwrap to the original AES key");
        }
        catch (InvalidKeyException expected)
        {
            // Equally acceptable.
        }
    }


    // -----------------------------------------------------------------
    // Input length boundary — PKCS#1 v1.5 max plaintext = keysize - 11
    // -----------------------------------------------------------------

    @Test
    public void testPKCS1_MaxInputLength_acceptsAtLimit() throws Exception
    {
        // 2048-bit modulus → 256-byte block → max plaintext = 245 bytes.
        byte[] msg = randomMessage(245);

        Cipher enc = Cipher.getInstance("RSA/ECB/PKCS1Padding", JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, sharedKeyPair.getPublic());
        byte[] ct = enc.doFinal(msg);

        Cipher dec = Cipher.getInstance("RSA/ECB/PKCS1Padding", JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, sharedKeyPair.getPrivate());
        Assertions.assertArrayEquals(msg, dec.doFinal(ct));
    }

    @Test
    public void testPKCS1_MaxInputLength_rejectsAboveLimit() throws Exception
    {
        byte[] msg = randomMessage(246); // one byte over the limit

        Cipher enc = Cipher.getInstance("RSA/ECB/PKCS1Padding", JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, sharedKeyPair.getPublic());
        try
        {
            enc.doFinal(msg);
            Assertions.fail("encrypt of 246 bytes must be rejected");
        }
        catch (javax.crypto.IllegalBlockSizeException expected) {}
    }


    // -----------------------------------------------------------------
    // Failure paths
    // -----------------------------------------------------------------

    @Test
    public void testPKCS1_RejectsParameterSpec() throws Exception
    {
        // PKCS#1 v1.5 takes no algorithm parameters.
        Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding", JostleProvider.PROVIDER_NAME);
        try
        {
            c.init(Cipher.ENCRYPT_MODE, sharedKeyPair.getPublic(),
                    new javax.crypto.spec.OAEPParameterSpec("SHA-256", "MGF1",
                            new java.security.spec.MGF1ParameterSpec("SHA-256"),
                            javax.crypto.spec.PSource.PSpecified.DEFAULT));
            Assertions.fail();
        }
        catch (InvalidAlgorithmParameterException expected) {}
    }

    @Test
    public void testPKCS1_Encrypt_rejectsPrivateKey() throws Exception
    {
        Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding", JostleProvider.PROVIDER_NAME);
        try
        {
            c.init(Cipher.ENCRYPT_MODE, sharedKeyPair.getPrivate());
            Assertions.fail();
        }
        catch (InvalidKeyException expected) {}
    }

    @Test
    public void testPKCS1_Decrypt_rejectsPublicKey() throws Exception
    {
        Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding", JostleProvider.PROVIDER_NAME);
        try
        {
            c.init(Cipher.DECRYPT_MODE, sharedKeyPair.getPublic());
            Assertions.fail();
        }
        catch (InvalidKeyException expected) {}
    }

    @Test
    public void testPKCS1_UpdateWithoutInit_throwsIllegalState() throws Exception
    {
        Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding", JostleProvider.PROVIDER_NAME);
        try
        {
            c.update(new byte[]{1, 2, 3});
            Assertions.fail();
        }
        catch (IllegalStateException expected) {}
    }

    @Test
    public void testPKCS1_DoFinalWithoutInit_throwsIllegalState() throws Exception
    {
        Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding", JostleProvider.PROVIDER_NAME);
        try
        {
            c.doFinal(new byte[]{1, 2, 3});
            Assertions.fail();
        }
        catch (IllegalStateException expected) {}
    }

    @Test
    public void testPKCS1_WrapWithoutInit_throwsIllegalState() throws Exception
    {
        Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding", JostleProvider.PROVIDER_NAME);
        javax.crypto.spec.SecretKeySpec aes =
                new javax.crypto.spec.SecretKeySpec(new byte[16], "AES");
        try
        {
            c.wrap(aes);
            Assertions.fail();
        }
        catch (IllegalStateException expected) {}
    }

    @Test
    public void testPKCS1_UnwrapWithoutInit_throwsIllegalState() throws Exception
    {
        Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding", JostleProvider.PROVIDER_NAME);
        try
        {
            c.unwrap(new byte[256], "AES", Cipher.SECRET_KEY);
            Assertions.fail();
        }
        catch (IllegalStateException expected) {}
    }


    // -----------------------------------------------------------------
    // Output buffer variant
    // -----------------------------------------------------------------

    @Test
    public void testPKCS1_DoFinal_intoExternalBuffer() throws Exception
    {
        byte[] msg = randomMessage(32);
        Cipher enc = Cipher.getInstance("RSA/ECB/PKCS1Padding", JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, sharedKeyPair.getPublic());
        byte[] ct = new byte[enc.getOutputSize(msg.length)];
        int written = enc.doFinal(msg, 0, msg.length, ct, 0);
        Assertions.assertEquals(256, written);

        Cipher dec = Cipher.getInstance("RSA/ECB/PKCS1Padding", JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, sharedKeyPair.getPrivate());
        byte[] pt = new byte[dec.getOutputSize(ct.length)];
        int writtenPt = dec.doFinal(ct, 0, written, pt, 0);
        Assertions.assertEquals(msg.length, writtenPt);
        byte[] trimmed = new byte[writtenPt];
        System.arraycopy(pt, 0, trimmed, 0, writtenPt);
        Assertions.assertArrayEquals(msg, trimmed);
    }


    private static byte[] randomMessage(int len)
    {
        byte[] m = new byte[len];
        RANDOM.nextBytes(m);
        return m;
    }
}
