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

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;

/**
 * JCE-level tests for the RSA-OAEP cipher: round-trips, BC parity for
 * each supported digest, parameter-spec handling, vandalism rejection,
 * and the various padding-name forms registered in {@code ProvRSA}.
 */
public class RSAOAEPCipherTest
{
    private static final SecureRandom RANDOM = new SecureRandom();
    private static KeyPair sharedKeyPair;

    /**
     * Per-test seeded random, for tests that loop over randomised lengths
     * or content. The seed is logged on failure so a flaky run can be
     * reproduced — call this inside a test, not at the class level, so
     * each test gets its own log line if it fails.
     */
    private static SecureRandom seededRandom(String testName) throws Exception
    {
        long seed = RANDOM.nextLong();
        System.out.println(testName + " seed=" + seed);
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        return sr;
    }

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
    // Basic round-trips
    // -----------------------------------------------------------------

    @Test
    public void testOAEP_DefaultParams_roundTrip() throws Exception
    {
        byte[] msg = randomMessage(64);
        Cipher enc = Cipher.getInstance("RSA/ECB/OAEPPadding", JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, sharedKeyPair.getPublic());
        byte[] ct = enc.doFinal(msg);
        Assertions.assertEquals(256, ct.length, "2048-bit modulus → 256-byte ciphertext");

        Cipher dec = Cipher.getInstance("RSA/ECB/OAEPPadding", JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, sharedKeyPair.getPrivate());
        byte[] pt = dec.doFinal(ct);
        Assertions.assertArrayEquals(msg, pt);
    }

    // -----------------------------------------------------------------
    // Reset / reuse: doFinal must leave the SPI ready for a subsequent
    // doFinal without re-init. The native EVP_PKEY_CTX is reused; the
    // input buffer is cleared. Two doFinal calls must produce two
    // independent ciphertexts that each decrypt back to their plaintext.
    // -----------------------------------------------------------------

    @Test
    public void testOAEP_EncryptReuseAfterDoFinal() throws Exception
    {
        byte[] msgA = randomMessage(40);
        byte[] msgB = randomMessage(72);

        Cipher enc = Cipher.getInstance("RSA/ECB/OAEPPadding", JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, sharedKeyPair.getPublic());
        byte[] ctA = enc.doFinal(msgA);
        // Reuse — no re-init.
        byte[] ctB = enc.doFinal(msgB);

        Assertions.assertEquals(256, ctA.length);
        Assertions.assertEquals(256, ctB.length);
        // OAEP randomises the seed each call; identical inputs produce
        // distinct ciphertexts. Different inputs definitely should.
        Assertions.assertFalse(java.util.Arrays.equals(ctA, ctB),
                "two OAEP ciphertexts must differ");

        Cipher dec = Cipher.getInstance("RSA/ECB/OAEPPadding", JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, sharedKeyPair.getPrivate());
        Assertions.assertArrayEquals(msgA, dec.doFinal(ctA));
        // Decryptor reuse too.
        Assertions.assertArrayEquals(msgB, dec.doFinal(ctB));
    }

    @Test
    public void testOAEP_EncryptReuseSameInput_DifferentCiphertexts() throws Exception
    {
        // Same plaintext through the same encryptor twice. OAEP's seed
        // is fresh per call; ciphertexts must differ. If the SPI's reuse
        // path were caching the EVP_PKEY_CTX in a way that froze the
        // seed, this would surface as ctA.equals(ctB).
        byte[] msg = randomMessage(64);

        Cipher enc = Cipher.getInstance("RSA/ECB/OAEPPadding", JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, sharedKeyPair.getPublic());
        byte[] ctA = enc.doFinal(msg);
        byte[] ctB = enc.doFinal(msg);
        Assertions.assertFalse(java.util.Arrays.equals(ctA, ctB),
                "OAEP must produce a fresh seed per doFinal");

        Cipher dec = Cipher.getInstance("RSA/ECB/OAEPPadding", JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, sharedKeyPair.getPrivate());
        Assertions.assertArrayEquals(msg, dec.doFinal(ctA));
        Assertions.assertArrayEquals(msg, dec.doFinal(ctB));
    }

    @Test
    public void testOAEP_DecryptReuse_BadCiphertextThenGood() throws Exception
    {
        // After a BadPaddingException the SPI must remain usable: a
        // subsequent doFinal on a well-formed ciphertext must succeed.
        // This is exactly the path where a stale buffer or a
        // half-cleaned-up native ctx would surface as a false reject.
        byte[] msg = randomMessage(32);

        Cipher enc = Cipher.getInstance("RSA/ECB/OAEPPadding", JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, sharedKeyPair.getPublic());
        byte[] good = enc.doFinal(msg);

        // Construct a definitively-bad ciphertext (full of zeros decodes
        // to invalid OAEP padding under any digest).
        byte[] bad = new byte[good.length];

        Cipher dec = Cipher.getInstance("RSA/ECB/OAEPPadding", JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, sharedKeyPair.getPrivate());
        Assertions.assertThrows(javax.crypto.BadPaddingException.class,
                () -> dec.doFinal(bad));

        // Decryptor must still work after the failure.
        byte[] pt = dec.doFinal(good);
        Assertions.assertArrayEquals(msg, pt);
    }

    @Test
    public void testOAEP_WrapReuseAfterWrap() throws Exception
    {
        javax.crypto.spec.SecretKeySpec aesA =
                new javax.crypto.spec.SecretKeySpec(randomMessage(16), "AES");
        javax.crypto.spec.SecretKeySpec aesB =
                new javax.crypto.spec.SecretKeySpec(randomMessage(32), "AES");

        Cipher wrapper = Cipher.getInstance("RSA/ECB/OAEPPadding", JostleProvider.PROVIDER_NAME);
        wrapper.init(Cipher.WRAP_MODE, sharedKeyPair.getPublic());
        byte[] wA = wrapper.wrap(aesA);
        byte[] wB = wrapper.wrap(aesB);

        Assertions.assertFalse(java.util.Arrays.equals(wA, wB),
                "wrapping different keys must yield different bytes");

        Cipher unwrapper = Cipher.getInstance("RSA/ECB/OAEPPadding", JostleProvider.PROVIDER_NAME);
        unwrapper.init(Cipher.UNWRAP_MODE, sharedKeyPair.getPrivate());
        Key uA = unwrapper.unwrap(wA, "AES", Cipher.SECRET_KEY);
        // Unwrapper reuse.
        Key uB = unwrapper.unwrap(wB, "AES", Cipher.SECRET_KEY);

        Assertions.assertArrayEquals(aesA.getEncoded(), uA.getEncoded());
        Assertions.assertArrayEquals(aesB.getEncoded(), uB.getEncoded());
    }


    @Test
    public void testOAEP_AllRegisteredDigests_roundTrip() throws Exception
    {
        // Each padding-name digest variant must round-trip against itself.
        String[] aliases = {
                "RSA/ECB/OAEPWithSHA-1AndMGF1Padding",
                "RSA/ECB/OAEPWithSHA-224AndMGF1Padding",
                "RSA/ECB/OAEPWithSHA-256AndMGF1Padding",
                "RSA/ECB/OAEPWithSHA-384AndMGF1Padding",
                "RSA/ECB/OAEPWithSHA-512AndMGF1Padding",
                "RSA/ECB/OAEPWithSHA3-256AndMGF1Padding",
                "RSA/ECB/OAEPWithSHA3-512AndMGF1Padding"
        };
        byte[] msg = randomMessage(48);
        for (String alias : aliases)
        {
            Cipher enc = Cipher.getInstance(alias, JostleProvider.PROVIDER_NAME);
            enc.init(Cipher.ENCRYPT_MODE, sharedKeyPair.getPublic());
            byte[] ct = enc.doFinal(msg);

            Cipher dec = Cipher.getInstance(alias, JostleProvider.PROVIDER_NAME);
            dec.init(Cipher.DECRYPT_MODE, sharedKeyPair.getPrivate());
            byte[] pt = dec.doFinal(ct);
            Assertions.assertArrayEquals(msg, pt, alias + ": round-trip failed");
        }
    }

    @Test
    public void testOAEP_StreamingUpdateThenDoFinal() throws Exception
    {
        // OAEP is one-shot inside our SPI but engineUpdate must still
        // accumulate input correctly.
        byte[] msg = randomMessage(40);

        Cipher enc = Cipher.getInstance("RSA/ECB/OAEPPadding", JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, sharedKeyPair.getPublic());
        Assertions.assertNull(enc.update(msg, 0, 10));
        Assertions.assertNull(enc.update(msg, 10, 15));
        byte[] ct = enc.doFinal(msg, 25, msg.length - 25);

        Cipher dec = Cipher.getInstance("RSA/ECB/OAEPPadding", JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, sharedKeyPair.getPrivate());
        byte[] pt = dec.doFinal(ct);
        Assertions.assertArrayEquals(msg, pt);
    }

    /**
     * Per CLAUDE.md "use fully random values for everything" — vary the
     * plaintext content AND length across many trials to flush out
     * length-specific code paths (an off-by-one in OAEP padding, a
     * boundary bug at the maximum length minus a few). Logs the seed
     * on failure for reproducibility.
     */
    @Test
    public void testOAEP_RandomLengthMessages_roundTrip() throws Exception
    {
        SecureRandom sr = seededRandom("testOAEP_RandomLengthMessages_roundTrip");
        // For 2048 + SHA-256: max plaintext = 190 bytes. Sample across
        // [0, 190] inclusive to cover empty input and the max boundary.
        for (int trial = 0; trial < 25; trial++)
        {
            int len = sr.nextInt(191);
            byte[] msg = new byte[len];
            sr.nextBytes(msg);

            Cipher enc = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding",
                    JostleProvider.PROVIDER_NAME);
            enc.init(Cipher.ENCRYPT_MODE, sharedKeyPair.getPublic());
            byte[] ct = enc.doFinal(msg);

            Cipher dec = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding",
                    JostleProvider.PROVIDER_NAME);
            dec.init(Cipher.DECRYPT_MODE, sharedKeyPair.getPrivate());
            byte[] pt = dec.doFinal(ct);
            Assertions.assertArrayEquals(msg, pt,
                    "trial " + trial + " (len=" + len + ") failed round-trip");
        }
    }

    /**
     * Streaming chunking matrix per CLAUDE.md "Vary the chunking, and
     * randomise the inputs". OAEP is one-shot at the OpenSSL layer but
     * the SPI buffers update() calls — so different chunkings of the
     * same plaintext must accumulate to the same input and decrypt to
     * a byte-identical output. (OAEP ciphertexts can't be compared
     * directly because each encrypt randomises the seed; we compare on
     * the round-tripped plaintext instead.)
     */
    @Test
    public void testOAEP_ChunkingMatrix_decryptsToOriginal() throws Exception
    {
        SecureRandom sr = seededRandom("testOAEP_ChunkingMatrix_decryptsToOriginal");
        byte[] msg = new byte[150]; // well under SHA-256 OAEP max of 190
        sr.nextBytes(msg);

        // Reference: one-shot encrypt + decrypt.
        byte[] reference = encryptThenDecrypt(msg, msg.length);
        Assertions.assertArrayEquals(msg, reference);

        // byte-by-byte
        Assertions.assertArrayEquals(msg, encryptThenDecrypt(msg, 1),
                "byte-by-byte chunking diverged");

        // SHA-256 block-aligned offsets.
        for (int chunk : new int[]{63, 64, 65})
        {
            Assertions.assertArrayEquals(msg, encryptThenDecrypt(msg, chunk),
                    "chunk=" + chunk + " diverged");
        }

        // Random splits.
        for (int trial = 0; trial < 5; trial++)
        {
            byte[] roundTripped = encryptWithRandomSplits(msg, sr);
            Assertions.assertArrayEquals(msg, roundTripped,
                    "random-split round-trip diverged");
        }
    }

    private byte[] encryptThenDecrypt(byte[] msg, int chunk) throws Exception
    {
        Cipher enc = Cipher.getInstance("RSA/ECB/OAEPPadding", JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, sharedKeyPair.getPublic());
        for (int off = 0; off < msg.length; off += chunk)
        {
            int len = Math.min(chunk, msg.length - off);
            enc.update(msg, off, len);
        }
        byte[] ct = enc.doFinal();

        Cipher dec = Cipher.getInstance("RSA/ECB/OAEPPadding", JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, sharedKeyPair.getPrivate());
        return dec.doFinal(ct);
    }

    private byte[] encryptWithRandomSplits(byte[] msg, SecureRandom sr) throws Exception
    {
        Cipher enc = Cipher.getInstance("RSA/ECB/OAEPPadding", JostleProvider.PROVIDER_NAME);
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

        Cipher dec = Cipher.getInstance("RSA/ECB/OAEPPadding", JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, sharedKeyPair.getPrivate());
        return dec.doFinal(ct);
    }

    @Test
    public void testOAEP_NonDeterministic() throws Exception
    {
        // OAEP injects a random seed; two encryptions of the same plaintext
        // must differ.
        byte[] msg = randomMessage(64);
        Cipher enc = Cipher.getInstance("RSA/ECB/OAEPPadding", JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, sharedKeyPair.getPublic());
        byte[] first = enc.doFinal(msg);

        enc.init(Cipher.ENCRYPT_MODE, sharedKeyPair.getPublic());
        byte[] second = enc.doFinal(msg);

        Assertions.assertFalse(java.util.Arrays.equals(first, second),
                "OAEP ciphertexts must differ across calls (random seed)");
    }


    // -----------------------------------------------------------------
    // Parameter handling
    // -----------------------------------------------------------------

    @Test
    public void testOAEP_ExplicitParameterSpec() throws Exception
    {
        OAEPParameterSpec spec = new OAEPParameterSpec(
                "SHA-384", "MGF1", new MGF1ParameterSpec("SHA-256"),
                PSource.PSpecified.DEFAULT);
        byte[] msg = randomMessage(32);

        Cipher enc = Cipher.getInstance("RSA/ECB/OAEPPadding", JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, sharedKeyPair.getPublic(), spec);
        byte[] ct = enc.doFinal(msg);

        Cipher dec = Cipher.getInstance("RSA/ECB/OAEPPadding", JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, sharedKeyPair.getPrivate(), spec);
        byte[] pt = dec.doFinal(ct);
        Assertions.assertArrayEquals(msg, pt);
    }

    @Test
    public void testOAEP_LabelMatters() throws Exception
    {
        // A non-default OAEP label must change the ciphertext, and
        // decryption with a different label must fail.
        byte[] labelA = "label-A".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] labelB = "label-B".getBytes(java.nio.charset.StandardCharsets.UTF_8);

        OAEPParameterSpec specA = new OAEPParameterSpec(
                "SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"),
                new PSource.PSpecified(labelA));
        OAEPParameterSpec specB = new OAEPParameterSpec(
                "SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"),
                new PSource.PSpecified(labelB));

        byte[] msg = randomMessage(32);

        Cipher enc = Cipher.getInstance("RSA/ECB/OAEPPadding", JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, sharedKeyPair.getPublic(), specA);
        byte[] ct = enc.doFinal(msg);

        // Decrypt with the matching label — succeeds.
        Cipher dec = Cipher.getInstance("RSA/ECB/OAEPPadding", JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, sharedKeyPair.getPrivate(), specA);
        byte[] pt = dec.doFinal(ct);
        Assertions.assertArrayEquals(msg, pt);

        // Decrypt with a different label — must reject as bad padding.
        Cipher decBad = Cipher.getInstance("RSA/ECB/OAEPPadding", JostleProvider.PROVIDER_NAME);
        decBad.init(Cipher.DECRYPT_MODE, sharedKeyPair.getPrivate(), specB);
        try
        {
            decBad.doFinal(ct);
            Assertions.fail("decrypt with mismatched label must fail");
        }
        catch (BadPaddingException expected) {}
    }

    @Test
    public void testOAEP_RejectsNonOAEPParameterSpec() throws Exception
    {
        Cipher enc = Cipher.getInstance("RSA/ECB/OAEPPadding", JostleProvider.PROVIDER_NAME);
        try
        {
            enc.init(Cipher.ENCRYPT_MODE, sharedKeyPair.getPublic(),
                    new AlgorithmParameterSpec() {});
            Assertions.fail();
        }
        catch (InvalidAlgorithmParameterException expected) {}
    }

    @Test
    public void testOAEP_RejectsNonMGF1() throws Exception
    {
        // Constructed with an MGF other than MGF1.
        OAEPParameterSpec bad = new OAEPParameterSpec(
                "SHA-256", "MGF2", new MGF1ParameterSpec("SHA-256"),
                PSource.PSpecified.DEFAULT);
        Cipher enc = Cipher.getInstance("RSA/ECB/OAEPPadding", JostleProvider.PROVIDER_NAME);
        try
        {
            enc.init(Cipher.ENCRYPT_MODE, sharedKeyPair.getPublic(), bad);
            Assertions.fail();
        }
        catch (InvalidAlgorithmParameterException e)
        {
            Assertions.assertTrue(e.getMessage().contains("MGF1"),
                    "expected MGF1 rejection, got: " + e.getMessage());
        }
    }


    // -----------------------------------------------------------------
    // Vandalism / failure paths
    // -----------------------------------------------------------------

    @Test
    public void testOAEP_VandalisedCiphertext_rejected() throws Exception
    {
        byte[] msg = randomMessage(32);
        Cipher enc = Cipher.getInstance("RSA/ECB/OAEPPadding", JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, sharedKeyPair.getPublic());
        byte[] ct = enc.doFinal(msg);
        ct[0] ^= 1;

        Cipher dec = Cipher.getInstance("RSA/ECB/OAEPPadding", JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, sharedKeyPair.getPrivate());
        try
        {
            dec.doFinal(ct);
            Assertions.fail("vandalised ciphertext must be rejected");
        }
        catch (BadPaddingException expected) {}
    }

    @Test
    public void testOAEP_WrapUnwrap_AESSecretKey_roundTrip() throws Exception
    {
        // Generate an AES key, wrap with OAEP, unwrap, and confirm the
        // unwrapped key matches.
        javax.crypto.KeyGenerator kg = javax.crypto.KeyGenerator.getInstance("AES");
        kg.init(256);
        javax.crypto.SecretKey aesKey = kg.generateKey();

        Cipher wrapper = Cipher.getInstance("RSA/ECB/OAEPPadding", JostleProvider.PROVIDER_NAME);
        wrapper.init(Cipher.WRAP_MODE, sharedKeyPair.getPublic());
        byte[] wrapped = wrapper.wrap(aesKey);
        Assertions.assertEquals(256, wrapped.length, "wrapped key sized to modulus");

        Cipher unwrapper = Cipher.getInstance("RSA/ECB/OAEPPadding", JostleProvider.PROVIDER_NAME);
        unwrapper.init(Cipher.UNWRAP_MODE, sharedKeyPair.getPrivate());
        Key unwrapped = unwrapper.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
        Assertions.assertEquals("AES", unwrapped.getAlgorithm());
        Assertions.assertArrayEquals(aesKey.getEncoded(), unwrapped.getEncoded(),
                "unwrapped AES key must match original");
    }

    @Test
    public void testOAEP_WrapUnwrap_PublicKey_roundTrip() throws Exception
    {
        // Generate an EC key, wrap its public side, unwrap as PUBLIC_KEY.
        java.security.KeyPairGenerator ec = java.security.KeyPairGenerator.getInstance("EC");
        ec.initialize(256);
        java.security.KeyPair ecKp = ec.generateKeyPair();
        java.security.PublicKey ecPub = ecKp.getPublic();

        Cipher wrapper = Cipher.getInstance("RSA/ECB/OAEPPadding", JostleProvider.PROVIDER_NAME);
        wrapper.init(Cipher.WRAP_MODE, sharedKeyPair.getPublic());
        byte[] wrapped = wrapper.wrap(ecPub);

        Cipher unwrapper = Cipher.getInstance("RSA/ECB/OAEPPadding", JostleProvider.PROVIDER_NAME);
        unwrapper.init(Cipher.UNWRAP_MODE, sharedKeyPair.getPrivate());
        Key unwrapped = unwrapper.unwrap(wrapped, "EC", Cipher.PUBLIC_KEY);
        Assertions.assertEquals("EC", unwrapped.getAlgorithm());
        Assertions.assertArrayEquals(ecPub.getEncoded(), unwrapped.getEncoded());
    }

    @Test
    public void testOAEP_Unwrap_VandalisedCiphertext_throwsInvalidKey() throws Exception
    {
        // Tampered wrapped bytes must surface as InvalidKeyException —
        // not BadPaddingException — to avoid Bleichenbacher-style
        // oracles via the wrap/unwrap channel.
        javax.crypto.KeyGenerator kg = javax.crypto.KeyGenerator.getInstance("AES");
        kg.init(128);
        javax.crypto.SecretKey aesKey = kg.generateKey();

        Cipher wrapper = Cipher.getInstance("RSA/ECB/OAEPPadding", JostleProvider.PROVIDER_NAME);
        wrapper.init(Cipher.WRAP_MODE, sharedKeyPair.getPublic());
        byte[] wrapped = wrapper.wrap(aesKey);
        wrapped[5] ^= 1;

        Cipher unwrapper = Cipher.getInstance("RSA/ECB/OAEPPadding", JostleProvider.PROVIDER_NAME);
        unwrapper.init(Cipher.UNWRAP_MODE, sharedKeyPair.getPrivate());
        try
        {
            unwrapper.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
            Assertions.fail();
        }
        catch (InvalidKeyException expected) {}
    }

    @Test
    public void testOAEP_BCWrap_JostleUnwrap_AESKey() throws Exception
    {
        javax.crypto.KeyGenerator kg = javax.crypto.KeyGenerator.getInstance("AES");
        kg.init(256);
        javax.crypto.SecretKey aesKey = kg.generateKey();

        OAEPParameterSpec spec = new OAEPParameterSpec(
                "SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"),
                PSource.PSpecified.DEFAULT);

        Cipher bcWrap = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding",
                BouncyCastleProvider.PROVIDER_NAME);
        bcWrap.init(Cipher.WRAP_MODE, sharedKeyPair.getPublic(), spec);
        byte[] wrapped = bcWrap.wrap(aesKey);

        Cipher joUnwrap = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding",
                JostleProvider.PROVIDER_NAME);
        joUnwrap.init(Cipher.UNWRAP_MODE, sharedKeyPair.getPrivate(), spec);
        Key unwrapped = joUnwrap.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
        Assertions.assertArrayEquals(aesKey.getEncoded(), unwrapped.getEncoded());
    }

    @Test
    public void testOAEP_UpdateWithoutInit_throwsIllegalState() throws Exception
    {
        Cipher c = Cipher.getInstance("RSA/ECB/OAEPPadding", JostleProvider.PROVIDER_NAME);
        try
        {
            c.update(new byte[]{1, 2, 3});
            Assertions.fail();
        }
        catch (IllegalStateException expected) {}
    }

    @Test
    public void testOAEP_DoFinalWithoutInit_throwsIllegalState() throws Exception
    {
        Cipher c = Cipher.getInstance("RSA/ECB/OAEPPadding", JostleProvider.PROVIDER_NAME);
        try
        {
            c.doFinal(new byte[]{1, 2, 3});
            Assertions.fail();
        }
        catch (IllegalStateException expected) {}
    }

    @Test
    public void testOAEP_WrapWithoutInit_throwsIllegalState() throws Exception
    {
        Cipher c = Cipher.getInstance("RSA/ECB/OAEPPadding", JostleProvider.PROVIDER_NAME);
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
    public void testOAEP_UnwrapWithoutInit_throwsIllegalState() throws Exception
    {
        Cipher c = Cipher.getInstance("RSA/ECB/OAEPPadding", JostleProvider.PROVIDER_NAME);
        try
        {
            c.unwrap(new byte[256], "AES", Cipher.SECRET_KEY);
            Assertions.fail();
        }
        catch (IllegalStateException expected) {}
    }

    @Test
    public void testOAEP_Encrypt_rejectsPrivateKey() throws Exception
    {
        Cipher enc = Cipher.getInstance("RSA/ECB/OAEPPadding", JostleProvider.PROVIDER_NAME);
        try
        {
            enc.init(Cipher.ENCRYPT_MODE, sharedKeyPair.getPrivate());
            Assertions.fail();
        }
        catch (InvalidKeyException expected) {}
    }

    @Test
    public void testOAEP_Decrypt_rejectsPublicKey() throws Exception
    {
        Cipher dec = Cipher.getInstance("RSA/ECB/OAEPPadding", JostleProvider.PROVIDER_NAME);
        try
        {
            dec.init(Cipher.DECRYPT_MODE, sharedKeyPair.getPublic());
            Assertions.fail();
        }
        catch (InvalidKeyException expected) {}
    }


    // -----------------------------------------------------------------
    // Input length boundary — OAEP max plaintext = keysize - 2*hash - 2
    // -----------------------------------------------------------------

    /**
     * Locks in the fix for the OAEP-alias-suppresses-setPadding bug.
     * Each digest variant must be ACTUALLY APPLIED (not silently
     * collapsed to a default): encrypting with digest A and decrypting
     * with digest B must fail. If a transformation alias bug ever
     * recurs (e.g. registering {@code RSA/ECB/OAEPWithSHA-512AndMGF1Padding}
     * as a JCE alias of {@code RSA}), this test will catch it because
     * both ciphers would silently use the SPI's default digest, making
     * the cross-digest decrypt succeed.
     */
    @Test
    public void testOAEP_DigestActuallyApplied_crossDigestFails() throws Exception
    {
        byte[] msg = randomMessage(60);

        Cipher enc = Cipher.getInstance("RSA/ECB/OAEPWithSHA-512AndMGF1Padding",
                JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, sharedKeyPair.getPublic());
        byte[] ct = enc.doFinal(msg);

        Cipher dec = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding",
                JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, sharedKeyPair.getPrivate());
        try
        {
            dec.doFinal(ct);
            Assertions.fail("OAEP-SHA-512 ciphertext must NOT decrypt as OAEP-SHA-256");
        }
        catch (BadPaddingException expected) {}
    }

    /**
     * For 2048-bit RSA + SHA-256 OAEP, max plaintext = 256 - 64 - 2 = 190.
     * The boundary case must encrypt cleanly; one byte over must reject.
     */
    @Test
    public void testOAEP_SHA256_MaxInputLength_acceptsAtLimit() throws Exception
    {
        byte[] msg = randomMessage(190);
        Cipher enc = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding",
                JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, sharedKeyPair.getPublic());
        byte[] ct = enc.doFinal(msg);

        Cipher dec = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding",
                JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, sharedKeyPair.getPrivate());
        Assertions.assertArrayEquals(msg, dec.doFinal(ct));
    }

    @Test
    public void testOAEP_SHA256_MaxInputLength_rejectsAboveLimit() throws Exception
    {
        byte[] msg = randomMessage(191);
        Cipher enc = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding",
                JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, sharedKeyPair.getPublic());
        try
        {
            enc.doFinal(msg);
            Assertions.fail("encrypt of 191 bytes (max + 1) must be rejected");
        }
        catch (javax.crypto.IllegalBlockSizeException expected) {}
    }

    @Test
    public void testOAEP_SHA512_MaxInputLength_acceptsAtLimit() throws Exception
    {
        // 2048 - 128 - 2 = 126 bytes max for SHA-512.
        byte[] msg = randomMessage(126);
        Cipher enc = Cipher.getInstance("RSA/ECB/OAEPWithSHA-512AndMGF1Padding",
                JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, sharedKeyPair.getPublic());
        byte[] ct = enc.doFinal(msg);

        Cipher dec = Cipher.getInstance("RSA/ECB/OAEPWithSHA-512AndMGF1Padding",
                JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, sharedKeyPair.getPrivate());
        Assertions.assertArrayEquals(msg, dec.doFinal(ct));
    }

    @Test
    public void testOAEP_SHA512_MaxInputLength_rejectsAboveLimit() throws Exception
    {
        byte[] msg = randomMessage(127);
        Cipher enc = Cipher.getInstance("RSA/ECB/OAEPWithSHA-512AndMGF1Padding",
                JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, sharedKeyPair.getPublic());
        try
        {
            enc.doFinal(msg);
            Assertions.fail("encrypt of 127 bytes (max + 1) must be rejected");
        }
        catch (javax.crypto.IllegalBlockSizeException expected) {}
    }


    // -----------------------------------------------------------------
    // BouncyCastle parity
    // -----------------------------------------------------------------

    @Test
    public void testOAEP_SHA256_BCEncrypt_JostleDecrypt() throws Exception
    {
        byte[] msg = randomMessage(64);
        OAEPParameterSpec spec = new OAEPParameterSpec(
                "SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"),
                PSource.PSpecified.DEFAULT);

        Cipher bcEnc = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding",
                BouncyCastleProvider.PROVIDER_NAME);
        bcEnc.init(Cipher.ENCRYPT_MODE, sharedKeyPair.getPublic(), spec);
        byte[] ct = bcEnc.doFinal(msg);

        Cipher joDec = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding",
                JostleProvider.PROVIDER_NAME);
        joDec.init(Cipher.DECRYPT_MODE, sharedKeyPair.getPrivate(), spec);
        byte[] pt = joDec.doFinal(ct);
        Assertions.assertArrayEquals(msg, pt);
    }

    @Test
    public void testOAEP_SHA256_JostleEncrypt_BCDecrypt() throws Exception
    {
        byte[] msg = randomMessage(64);
        OAEPParameterSpec spec = new OAEPParameterSpec(
                "SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"),
                PSource.PSpecified.DEFAULT);

        Cipher joEnc = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding",
                JostleProvider.PROVIDER_NAME);
        joEnc.init(Cipher.ENCRYPT_MODE, sharedKeyPair.getPublic(), spec);
        byte[] ct = joEnc.doFinal(msg);

        Cipher bcDec = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding",
                BouncyCastleProvider.PROVIDER_NAME);
        bcDec.init(Cipher.DECRYPT_MODE, sharedKeyPair.getPrivate(), spec);
        byte[] pt = bcDec.doFinal(ct);
        Assertions.assertArrayEquals(msg, pt);
    }

    @Test
    public void testOAEP_SHA384_MGF1SHA256_BCDecrypt_Cross() throws Exception
    {
        // Asymmetric digest/MGF combination — exercise the path where
        // OAEP uses SHA-384 but MGF1 uses SHA-256.
        byte[] msg = randomMessage(64);
        OAEPParameterSpec spec = new OAEPParameterSpec(
                "SHA-384", "MGF1", new MGF1ParameterSpec("SHA-256"),
                PSource.PSpecified.DEFAULT);

        Cipher joEnc = Cipher.getInstance("RSA/ECB/OAEPPadding", JostleProvider.PROVIDER_NAME);
        joEnc.init(Cipher.ENCRYPT_MODE, sharedKeyPair.getPublic(), spec);
        byte[] ct = joEnc.doFinal(msg);

        Cipher bcDec = Cipher.getInstance("RSA/ECB/OAEPPadding",
                BouncyCastleProvider.PROVIDER_NAME);
        bcDec.init(Cipher.DECRYPT_MODE, sharedKeyPair.getPrivate(), spec);
        byte[] pt = bcDec.doFinal(ct);
        Assertions.assertArrayEquals(msg, pt);
    }


    // -----------------------------------------------------------------
    // Multi-trial cross-provider agreement (CLAUDE.md "Run agreement
    // tests against BouncyCastle, with random inputs")
    // -----------------------------------------------------------------

    /**
     * Per-trial fresh keypair, random plaintext length and content, both
     * directions (Jostle→BC and BC→Jostle), all 9 OAEP digest variants.
     * Catches digest-specific encoding bugs that a single-key/single-trial
     * BC parity test would miss.
     */
    @Test
    public void testOAEP_AgreementWithBC_AllDigests_MultiTrial() throws Exception
    {
        SecureRandom sr = seededRandom("testOAEP_AgreementWithBC_AllDigests_MultiTrial");
        // (digest, max plaintext for 2048-bit modulus = 256 - 2*hLen - 2)
        Object[][] variants = {
                {"SHA-1", 214},
                {"SHA-224", 198},
                {"SHA-256", 190},
                {"SHA-384", 158},
                {"SHA-512", 126},
                {"SHA3-224", 198},
                {"SHA3-256", 190},
                {"SHA3-384", 158},
                {"SHA3-512", 126},
        };

        for (int trial = 0; trial < 10; trial++)
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", JostleProvider.PROVIDER_NAME);
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();

            for (Object[] v : variants)
            {
                String digest = (String) v[0];
                int max = (Integer) v[1];
                int msgLen = sr.nextInt(max + 1); // 0..max inclusive
                byte[] msg = new byte[msgLen];
                sr.nextBytes(msg);

                OAEPParameterSpec params = new OAEPParameterSpec(
                        digest, "MGF1", new MGF1ParameterSpec(digest),
                        PSource.PSpecified.DEFAULT);
                String alias = "RSA/ECB/OAEPWith" + digest + "AndMGF1Padding";

                // Jostle encrypt → BC decrypt
                Cipher joEnc = Cipher.getInstance(alias, JostleProvider.PROVIDER_NAME);
                joEnc.init(Cipher.ENCRYPT_MODE, kp.getPublic(), params);
                byte[] ct = joEnc.doFinal(msg);

                Cipher bcDec = Cipher.getInstance(alias, BouncyCastleProvider.PROVIDER_NAME);
                bcDec.init(Cipher.DECRYPT_MODE, kp.getPrivate(), params);
                Assertions.assertArrayEquals(msg, bcDec.doFinal(ct),
                        "trial=" + trial + " " + digest + " msgLen=" + msgLen + ": BC failed to decrypt Jostle ct");

                // BC encrypt → Jostle decrypt
                Cipher bcEnc = Cipher.getInstance(alias, BouncyCastleProvider.PROVIDER_NAME);
                bcEnc.init(Cipher.ENCRYPT_MODE, kp.getPublic(), params);
                byte[] ct2 = bcEnc.doFinal(msg);

                Cipher joDec = Cipher.getInstance(alias, JostleProvider.PROVIDER_NAME);
                joDec.init(Cipher.DECRYPT_MODE, kp.getPrivate(), params);
                Assertions.assertArrayEquals(msg, joDec.doFinal(ct2),
                        "trial=" + trial + " " + digest + " msgLen=" + msgLen + ": Jostle failed to decrypt BC ct");
            }
        }
    }


    // -----------------------------------------------------------------
    // Output buffer variant
    // -----------------------------------------------------------------

    @Test
    public void testOAEP_DoFinal_intoExternalBuffer() throws Exception
    {
        byte[] msg = randomMessage(32);
        Cipher enc = Cipher.getInstance("RSA/ECB/OAEPPadding", JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, sharedKeyPair.getPublic());
        byte[] ct = new byte[enc.getOutputSize(msg.length)];
        int written = enc.doFinal(msg, 0, msg.length, ct, 0);
        Assertions.assertEquals(256, written);

        Cipher dec = Cipher.getInstance("RSA/ECB/OAEPPadding", JostleProvider.PROVIDER_NAME);
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
