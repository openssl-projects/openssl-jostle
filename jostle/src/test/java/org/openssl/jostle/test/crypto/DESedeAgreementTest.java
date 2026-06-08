/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.crypto;


import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.encoders.Hex;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.Security;

/**
 * Cross-provider agreement coverage for DESede (3-key Triple DES) —
 * ECB and CBC modes, which are the variants OpenSSL 3.5 keeps in its
 * default provider. Tests confirm Jostle and BouncyCastle produce
 * byte-identical ciphertexts and that one's decrypt accepts the
 * other's encrypt. Plus key-length boundaries, key-algorithm
 * rejection, OID alias, KeyGenerator behaviour, and the
 * tampered-ciphertext negative path.
 */
public class DESedeAgreementTest
{
    /**
     * Class-level seeding random — used to derive each test's local
     * SHA1PRNG seed. Per CLAUDE.md: "cache one SecureRandom per test
     * class, not per @Test method."
     */
    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * PKCS#9 OID for {@code des-EDE3-CBC}.
     */
    private static final String DES_EDE3_CBC_OID = "1.2.840.113549.3.7";

    /**
     * DES block size in bytes — used for boundary tests around the
     * CFB/CBC IV length and chunking-matrix block-aligned offsets.
     */
    private static final int DES_BLOCK = 8;

    /**
     * Per-test seeded random. The seed is logged on every call so a
     * flaky failure can be reproduced by re-running with the same
     * seed (per CLAUDE.md).
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
    static void before()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }


    // -----------------------------------------------------------------
    // Cross-provider agreement — Jostle <-> BouncyCastle byte-equal.
    // -----------------------------------------------------------------

    @Test
    public void testECB_noPadding_agreesWithBC() throws Exception
    {
        // ECB has no IV. Message length must be a block multiple.
        agreeBothDirections("DESede/ECB/NoPadding", 5 * DES_BLOCK, DES_BLOCK, -1,
                seededRandom("testECB_noPadding_agreesWithBC"));
    }

    @Test
    public void testECB_pkcs7Padding_agreesWithBC() throws Exception
    {
        agreeBothDirections("DESede/ECB/PKCS7Padding", 5 * DES_BLOCK + 1, 1, -1,
                seededRandom("testECB_pkcs7Padding_agreesWithBC"));
    }

    @Test
    public void testECB_pkcs5Padding_agreesWithBC() throws Exception
    {
        // PKCS#5 and PKCS#7 padding are equivalent for the 8-byte DES
        // block — both registered aliases should drive identical output.
        agreeBothDirections("DESede/ECB/PKCS5Padding", 5 * DES_BLOCK + 1, 1, -1,
                seededRandom("testECB_pkcs5Padding_agreesWithBC"));
    }

    @Test
    public void testCBC_noPadding_agreesWithBC() throws Exception
    {
        agreeBothDirections("DESede/CBC/NoPadding", 5 * DES_BLOCK, DES_BLOCK, DES_BLOCK,
                seededRandom("testCBC_noPadding_agreesWithBC"));
    }

    @Test
    public void testCBC_pkcs7Padding_agreesWithBC() throws Exception
    {
        agreeBothDirections("DESede/CBC/PKCS7Padding", 5 * DES_BLOCK + 1, 1, DES_BLOCK,
                seededRandom("testCBC_pkcs7Padding_agreesWithBC"));
    }

    @Test
    public void testCBC_pkcs5Padding_agreesWithBC() throws Exception
    {
        agreeBothDirections("DESede/CBC/PKCS5Padding", 5 * DES_BLOCK + 1, 1, DES_BLOCK,
                seededRandom("testCBC_pkcs5Padding_agreesWithBC"));
    }


    // -----------------------------------------------------------------
    // TripleDES alias resolves to the same cipher.
    // -----------------------------------------------------------------

    @Test
    public void testTripleDESAlias_resolvesToDESede() throws Exception
    {
        // Both names must produce byte-equal output for the same key /
        // IV / plaintext — confirms the alias points at the same SPI
        // rather than at, say, a stubbed-out implementation.
        SecureRandom sr = seededRandom("testTripleDESAlias_resolvesToDESede");
        byte[] key = new byte[24];
        sr.nextBytes(key);
        byte[] iv = new byte[DES_BLOCK];
        sr.nextBytes(iv);
        byte[] msg = new byte[32];
        sr.nextBytes(msg);

        Cipher viaDESede = Cipher.getInstance("DESede/CBC/PKCS7Padding", JostleProvider.PROVIDER_NAME);
        viaDESede.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DESede"), new IvParameterSpec(iv));
        byte[] ctA = viaDESede.doFinal(msg);

        Cipher viaTripleDES = Cipher.getInstance("TripleDES/CBC/PKCS7Padding", JostleProvider.PROVIDER_NAME);
        viaTripleDES.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DESede"), new IvParameterSpec(iv));
        byte[] ctB = viaTripleDES.doFinal(msg);

        Assertions.assertArrayEquals(ctA, ctB,
                "TripleDES alias must resolve to the DESede cipher");
    }


    // -----------------------------------------------------------------
    // OID alias (1.2.840.113549.3.7) resolves to a working DES-EDE3-CBC.
    // -----------------------------------------------------------------

    @Test
    public void testOidAlias_resolvesToDESede_CBC() throws Exception
    {
        SecureRandom sr = seededRandom("testOidAlias_resolvesToDESede_CBC");
        byte[] key = new byte[24];
        sr.nextBytes(key);
        byte[] iv = new byte[DES_BLOCK];
        sr.nextBytes(iv);
        byte[] msg = new byte[16];
        sr.nextBytes(msg);

        Cipher viaName = Cipher.getInstance("DESede/CBC/PKCS7Padding", JostleProvider.PROVIDER_NAME);
        viaName.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DESede"), new IvParameterSpec(iv));
        byte[] expected = viaName.doFinal(msg);

        // Form-1 lookup — JCE finds the OID-registered Cipher and
        // does NOT call engineSetMode/Padding. The OID-bound SPI
        // pre-locks mode=CBC, padding defaults to NoPadding.
        // Cross-check by decrypting with the named-form CBC/NoPadding
        // to confirm the bytes match (modulo padding handling).
        Cipher viaOid = Cipher.getInstance(DES_EDE3_CBC_OID, JostleProvider.PROVIDER_NAME);
        viaOid.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DESede"), new IvParameterSpec(iv));

        // Encrypt a block-aligned message via the OID form (no padding
        // configured) and via the named form with NoPadding — bytes
        // must match.
        byte[] alignedMsg = new byte[16];
        sr.nextBytes(alignedMsg);

        Cipher viaNameNoPad = Cipher.getInstance("DESede/CBC/NoPadding", JostleProvider.PROVIDER_NAME);
        viaNameNoPad.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DESede"), new IvParameterSpec(iv));
        byte[] expectedNoPad = viaNameNoPad.doFinal(alignedMsg);

        byte[] viaOidCt = viaOid.doFinal(alignedMsg);
        Assertions.assertArrayEquals(expectedNoPad, viaOidCt,
                "OID alias must produce the same ciphertext as DESede/CBC/NoPadding");
    }


    // -----------------------------------------------------------------
    // Negative path: tampered ciphertext must NOT decrypt to plaintext.
    // -----------------------------------------------------------------

    @Test
    public void testTamperedCiphertext_doesNotRoundTrip() throws Exception
    {
        SecureRandom sr = seededRandom("testTamperedCiphertext_doesNotRoundTrip");
        byte[] key = new byte[24];
        sr.nextBytes(key);
        byte[] iv = new byte[DES_BLOCK];
        sr.nextBytes(iv);
        byte[] msg = new byte[40];
        sr.nextBytes(msg);

        Cipher enc = Cipher.getInstance("DESede/CBC/NoPadding", JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DESede"), new IvParameterSpec(iv));
        byte[] ct = enc.doFinal(msg);

        // Flip a bit in the middle block — that block AND the next one
        // will decrypt to garbage (CBC error propagation properties).
        // Block-aligned msg with NoPadding means decrypt won't throw,
        // it just produces wrong plaintext.
        byte[] tampered = ct.clone();
        tampered[16] ^= (byte) 0x01;

        Cipher dec = Cipher.getInstance("DESede/CBC/NoPadding", JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "DESede"), new IvParameterSpec(iv));
        byte[] decoded = dec.doFinal(tampered);

        Assertions.assertFalse(Arrays.areEqual(msg, decoded),
                "tampered ciphertext must not decrypt to the original plaintext");
    }

    @Test
    public void testTamperedPadding_rejectsAtDoFinal() throws Exception
    {
        // PKCS7 padding has integrity-style checks; tampering the last
        // ciphertext block should yield BadPaddingException with high
        // probability. Repeat the test a few times so a lucky padding
        // accident doesn't make the assertion flaky.
        SecureRandom sr = seededRandom("testTamperedPadding_rejectsAtDoFinal");
        byte[] key = new byte[24];
        sr.nextBytes(key);
        byte[] iv = new byte[DES_BLOCK];
        sr.nextBytes(iv);

        boolean sawBadPadding = false;
        for (int trial = 0; trial < 20; trial++)
        {
            byte[] msg = new byte[37]; // not a block multiple → padding present
            sr.nextBytes(msg);

            Cipher enc = Cipher.getInstance("DESede/CBC/PKCS7Padding", JostleProvider.PROVIDER_NAME);
            enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DESede"), new IvParameterSpec(iv));
            byte[] ct = enc.doFinal(msg);

            // Tamper the final ciphertext byte — this corrupts the
            // last decrypted block, which is the one carrying padding.
            byte[] tampered = ct.clone();
            tampered[tampered.length - 1] ^= (byte) 0xFF;

            Cipher dec = Cipher.getInstance("DESede/CBC/PKCS7Padding", JostleProvider.PROVIDER_NAME);
            dec.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "DESede"), new IvParameterSpec(iv));
            try
            {
                byte[] out = dec.doFinal(tampered);
                // No exception — only legitimate if the corrupted last
                // byte happens to remain a valid padding marker. The
                // result MUST differ from the original plaintext.
                Assertions.assertFalse(Arrays.areEqual(msg, out),
                        "tampered ciphertext that didn't throw still must not roundtrip");
            }
            catch (BadPaddingException expected)
            {
                sawBadPadding = true;
            }
        }
        Assertions.assertTrue(sawBadPadding,
                "expected at least one BadPaddingException across 20 tampering trials");
    }


    // -----------------------------------------------------------------
    // Key length boundary tests (per CLAUDE.md: probe at boundary + 1).
    // -----------------------------------------------------------------

    @Test
    public void testWrongKeyLength_24IsAccepted_othersRejected() throws Exception
    {
        // 24 bytes is the canonical 3-key TDES size — must succeed.
        Cipher ok = Cipher.getInstance("DESede/ECB/NoPadding", JostleProvider.PROVIDER_NAME);
        ok.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[24], "DESede"));

        // Below — 23 (one short of valid) and 16 (the 2-key DES-EDE
        // shorthand we intentionally don't accept) must throw. We skip
        // len=0 because SecretKeySpec rejects empty keys at construction
        // before our SPI ever sees them — that's a JDK-level check, not
        // an SPI-level one.
        for (int len : new int[]{8, 15, 16, 17, 23, 25, 32})
        {
            Cipher c = Cipher.getInstance("DESede/ECB/NoPadding", JostleProvider.PROVIDER_NAME);
            byte[] k = new byte[len];
            try
            {
                c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k, "DESede"));
                Assertions.fail("DESede must reject " + len + "-byte key");
            }
            catch (InvalidKeyException expected)
            {
                Assertions.assertTrue(expected.getMessage().contains("24"),
                        "rejection message should mention required 24-byte size: "
                                + expected.getMessage());
            }
        }
    }

    @Test
    public void testWrongKeyAlgorithm_rejected() throws Exception
    {
        // AES key wrapped in a DESede transformation — must reject.
        Cipher c = Cipher.getInstance("DESede/ECB/NoPadding", JostleProvider.PROVIDER_NAME);
        SecretKeySpec wrong = new SecretKeySpec(new byte[24], "AES");
        try
        {
            c.init(Cipher.ENCRYPT_MODE, wrong);
            Assertions.fail("expected InvalidKeyException for wrong key algorithm");
        }
        catch (InvalidKeyException expected)
        {
            Assertions.assertEquals("unsupported key algorithm AES", expected.getMessage());
        }

        // Both DESede AND TripleDES algorithm names must be accepted
        // — the SPI's validateKeyAlg override honours both per JCE
        // convention.
        Cipher ok = Cipher.getInstance("DESede/ECB/NoPadding", JostleProvider.PROVIDER_NAME);
        ok.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[24], "DESede"));

        Cipher okAlias = Cipher.getInstance("DESede/ECB/NoPadding", JostleProvider.PROVIDER_NAME);
        okAlias.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[24], "TripleDES"));
    }

    @Test
    public void testAcceptsWrapNameAndCaseInsensitiveKeyAlgorithms() throws Exception
    {
        // validateKeyAlg accepts "DESede"/"TripleDES", their JCE key-wrap
        // spellings (a CEK recovered via Cipher.unwrap on the CMS KEM/KTS path is
        // tagged with the wrap name, not the bare cipher name), and case variants.
        // Each accepted alias must not only init without throwing but key the
        // cipher identically to a plain "DESede" key.
        SecureRandom rng = seededRandom("testAcceptsWrapNameAndCaseInsensitiveKeyAlgorithms");
        byte[] keyBytes = new byte[24];
        rng.nextBytes(keyBytes);
        byte[] pt = new byte[16];
        rng.nextBytes(pt);

        Cipher ref = Cipher.getInstance("DESede/ECB/NoPadding", JostleProvider.PROVIDER_NAME);
        ref.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "DESede"));
        byte[] refCt = ref.doFinal(pt);

        String[] acceptedAliases = {"DESedeWrap", "DESEDEWRAP", "TripleDESWrap", "desede", "tripledes"};
        for (String alias : acceptedAliases)
        {
            Cipher enc = Cipher.getInstance("DESede/ECB/NoPadding", JostleProvider.PROVIDER_NAME);
            enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, alias));   // must not throw
            byte[] ct = enc.doFinal(pt);
            Assertions.assertArrayEquals(refCt, ct,
                    alias + ": key did not encrypt identically to a DESede-tagged key");

            Cipher dec = Cipher.getInstance("DESede/ECB/NoPadding", JostleProvider.PROVIDER_NAME);
            dec.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyBytes, alias));
            Assertions.assertArrayEquals(pt, dec.doFinal(ct),
                    alias + ": round-trip failed for accepted key algorithm");
        }

        // A different family shares neither "DESEDE" nor "TRIPLEDES" prefix and
        // is still rejected, so the looser match is not a blanket accept-anything.
        try
        {
            Cipher cipher = Cipher.getInstance("DESede/ECB/NoPadding", JostleProvider.PROVIDER_NAME);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "AES"));
            Assertions.fail("AES key must not be accepted by a DESede cipher");
        }
        catch (InvalidKeyException expected)
        {
            Assertions.assertEquals("unsupported key algorithm AES", expected.getMessage());
        }

        // Single "DES" shares the leading "DES" with "DESede" but is NOT a prefix
        // of it — the match is alg.startsWith(expected), not the reverse — so a
        // single-DES key must still be rejected by a DESede cipher.
        try
        {
            Cipher cipher = Cipher.getInstance("DESede/ECB/NoPadding", JostleProvider.PROVIDER_NAME);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "DES"));
            Assertions.fail("single-DES key must not be accepted by a DESede cipher");
        }
        catch (InvalidKeyException expected)
        {
            Assertions.assertEquals("unsupported key algorithm DES", expected.getMessage());
        }
    }

    @Test
    public void testCBC_wrongIvLength_rejected() throws Exception
    {
        // DES block size is 8 bytes; IV must be 8. Probe boundary +/- 1.
        // The JCE contract for Cipher.init(opmode, key, AlgorithmParameterSpec)
        // is to throw InvalidAlgorithmParameterException for invalid IV
        // length — pin that exact type per CLAUDE.md "throw the right
        // JCE exception type". A bare RuntimeException, NPE, or
        // OpenSSLException leak from this path would be an SPI bug.
        SecureRandom sr = seededRandom("testCBC_wrongIvLength_rejected");
        byte[] key = new byte[24];
        sr.nextBytes(key);

        for (int ivLen : new int[]{0, 7, 9, 16})
        {
            Cipher c = Cipher.getInstance("DESede/CBC/PKCS7Padding", JostleProvider.PROVIDER_NAME);
            Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                    () -> c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DESede"),
                            new IvParameterSpec(new byte[ivLen])),
                    "DESede/CBC must reject " + ivLen + "-byte IV with InvalidAlgorithmParameterException");
        }

        // Exact 8-byte IV must succeed.
        Cipher okCipher = Cipher.getInstance("DESede/CBC/PKCS7Padding", JostleProvider.PROVIDER_NAME);
        okCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DESede"),
                new IvParameterSpec(new byte[DES_BLOCK]));
    }


    // -----------------------------------------------------------------
    // KeyGenerator behaviour.
    // -----------------------------------------------------------------

    @Test
    public void testKeyGenerator_generates24ByteKeys() throws Exception
    {
        // Default (no init) — KeyGenerator must produce a 24-byte
        // DESede key and the key's reported algorithm must be "DESede".
        KeyGenerator kg = KeyGenerator.getInstance("DESede", JostleProvider.PROVIDER_NAME);
        SecretKey k = kg.generateKey();
        Assertions.assertEquals(24, k.getEncoded().length);
        Assertions.assertEquals("DESede", k.getAlgorithm());

        // The generated key must actually work as a DESede cipher key.
        Cipher c = Cipher.getInstance("DESede/ECB/NoPadding", JostleProvider.PROVIDER_NAME);
        c.init(Cipher.ENCRYPT_MODE, k);
        byte[] msg = new byte[DES_BLOCK];
        seededRandom("testKeyGenerator_generates24ByteKeys").nextBytes(msg);
        byte[] ct = c.doFinal(msg);
        Assertions.assertEquals(8, ct.length);

        c.init(Cipher.DECRYPT_MODE, k);
        Assertions.assertArrayEquals(msg, c.doFinal(ct));
    }

    @Test
    public void testKeyGenerator_init168_and_192_accepted() throws Exception
    {
        // JCE convention: 168 (effective key bits, parity stripped)
        // and 192 (full bits) both denote 3-key TDES. Both must
        // produce a 24-byte raw key.
        for (int keySize : new int[]{168, 192})
        {
            KeyGenerator kg = KeyGenerator.getInstance("DESede", JostleProvider.PROVIDER_NAME);
            kg.init(keySize);
            byte[] raw = kg.generateKey().getEncoded();
            Assertions.assertEquals(24, raw.length,
                    "init(" + keySize + ") must yield a 24-byte raw key");
        }
    }

    @Test
    public void testKeyGenerator_rejectsInvalidKeySize() throws Exception
    {
        // 112 / 128 are the 2-key TDES sizes; not supported. Probe a
        // few other invalid values around the boundaries.
        for (int keySize : new int[]{0, 56, 112, 128, 167, 169, 191, 193, 256})
        {
            KeyGenerator kg = KeyGenerator.getInstance("DESede", JostleProvider.PROVIDER_NAME);
            try
            {
                kg.init(keySize);
                Assertions.fail("DESede KeyGenerator must reject keysize " + keySize);
            }
            catch (IllegalArgumentException expected)
            {
                // good
            }
        }
    }

    @Test
    public void testKeyGenerator_aliasTripleDES() throws Exception
    {
        // The "TripleDES" KeyGenerator alias must produce a usable
        // DESede key (same as "DESede" name).
        KeyGenerator kg = KeyGenerator.getInstance("TripleDES", JostleProvider.PROVIDER_NAME);
        SecretKey k = kg.generateKey();
        Assertions.assertEquals(24, k.getEncoded().length);
    }


    // -----------------------------------------------------------------
    // Reset / re-use behaviour (per CLAUDE.md "test that the SPI is
    // correctly usable after reset"): two distinct encrypts on the
    // same instance, deterministic mode (ECB, no padding) → same
    // plaintext → same ciphertext both times.
    // -----------------------------------------------------------------

    @Test
    public void testReset_twoEncryptsOnSameInstance() throws Exception
    {
        SecureRandom sr = seededRandom("testReset_twoEncryptsOnSameInstance");
        byte[] key = new byte[24];
        sr.nextBytes(key);
        byte[] msg1 = new byte[16];
        sr.nextBytes(msg1);
        byte[] msg2 = new byte[24];
        sr.nextBytes(msg2);

        Cipher c = Cipher.getInstance("DESede/ECB/NoPadding", JostleProvider.PROVIDER_NAME);

        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DESede"));
        byte[] ct1 = c.doFinal(msg1);

        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DESede"));
        byte[] ct2 = c.doFinal(msg2);

        // ECB is deterministic — encrypting msg1 again must reproduce
        // ct1 exactly. Catches a reset that fails to clear residual
        // ctx state.
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DESede"));
        byte[] ct1Again = c.doFinal(msg1);
        Assertions.assertArrayEquals(ct1, ct1Again,
                "ECB encrypt of identical plaintext after reset must produce identical ciphertext");

        // And the second encrypt produced different output (different
        // plaintexts).
        Assertions.assertFalse(Arrays.areEqual(ct1, ct2),
                "different plaintexts must produce different ciphertexts (sanity)");
    }


    // -----------------------------------------------------------------
    // Chunking variation (per CLAUDE.md "Vary the chunking, and
    // randomise the inputs"). For each chunking pattern run the same
    // plaintext and assert byte-identical ciphertext + correct decrypt.
    // -----------------------------------------------------------------

    /**
     * Regression: the 3-arg auto-allocating
     * {@link Cipher#update(byte[], int, int)} path must work for
     * sub-block input on padded modes. Previously the native
     * {@code block_cipher_get_update_size} undersized the output buffer
     * (returning 0 for sub-block input) while
     * {@code block_cipher_ctx_update}'s {@code out_len &gt;= in_len}
     * safety guard rejected the call — the auto-allocating path
     * couldn't reach the EVP layer at all.
     */
    @Test
    public void testAutoAllocatingUpdate_subBlockInput_padded() throws Exception
    {
        SecureRandom sr = seededRandom("testAutoAllocatingUpdate_subBlockInput_padded");

        for (String xform : new String[]{"DESede/CBC/PKCS7Padding", "DESede/ECB/PKCS7Padding"})
        {
            byte[] key = new byte[24];
            sr.nextBytes(key);
            byte[] iv = xform.contains("/CBC/") ? new byte[DES_BLOCK] : null;
            if (iv != null)
            {
                sr.nextBytes(iv);
            }
            byte[] msg = new byte[41]; // 5 full blocks + 1 partial
            sr.nextBytes(msg);

            Cipher c = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
            SecretKeySpec ksp = new SecretKeySpec(key, "DESede");
            if (iv == null)
            {
                c.init(Cipher.ENCRYPT_MODE, ksp);
            }
            else
            {
                c.init(Cipher.ENCRYPT_MODE, ksp, new IvParameterSpec(iv));
            }

            // Feed byte-by-byte through the 3-arg auto-allocating update.
            // Each call returns a freshly-allocated byte[] sized via
            // getUpdateSize internally — this is the exact path that
            // used to throw before the get_update_size fix.
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            for (int i = 0; i < msg.length; i++)
            {
                byte[] part = c.update(msg, i, 1);
                if (part != null)
                {
                    out.write(part);
                }
            }
            // doFinal() with no args — previously NPE'd because the
            // SPI's engineDoFinal(byte[],int,int,byte[],int) handed
            // null straight to NI.update; the input-null check now
            // skips that update when inputLen == 0.
            out.write(c.doFinal());
            byte[] chunkedCt = out.toByteArray();

            // Compare against a one-shot encrypt with the same key/IV.
            byte[] oneShotCt = oneShotEncrypt(xform, key, iv, msg);
            Assertions.assertArrayEquals(oneShotCt, chunkedCt,
                    xform + ": auto-allocating byte-by-byte update must match one-shot");
        }
    }

    @Test
    public void testChunkingMatrix_paddedModes_sameOutputAcrossPartitions() throws Exception
    {
        // Byte-by-byte and arbitrary-offset chunking only applies to
        // padded modes. Jostle's unpadded `update` requires each call's
        // input length to be a block multiple (see the
        // JO_NOT_BLOCK_ALIGNED check in block_cipher_ctx.c) — this is
        // a deliberate design choice, not a bug. Block-aligned chunking
        // for NoPadding is covered separately below.
        SecureRandom sr = seededRandom("testChunkingMatrix_paddedModes_sameOutputAcrossPartitions");

        String[] xforms = {
                "DESede/CBC/PKCS7Padding",
                "DESede/ECB/PKCS7Padding"
        };

        for (String xform : xforms)
        {
            // 41 bytes — 5 full blocks plus a partial, exercises the
            // partial-block buffering at every chunking pattern.
            int msgLen = 41;
            byte[] key = new byte[24];
            sr.nextBytes(key);
            byte[] iv = xform.contains("/CBC/") ? new byte[DES_BLOCK] : null;
            if (iv != null)
            {
                sr.nextBytes(iv);
            }
            byte[] msg = new byte[msgLen];
            sr.nextBytes(msg);

            byte[] oneShot = oneShotEncrypt(xform, key, iv, msg);

            // Pattern 1 — byte-by-byte update + doFinal(empty).
            int[] byteByByteSplits = new int[msgLen];
            java.util.Arrays.fill(byteByByteSplits, 1);
            byte[] byteByByte = chunkEncrypt(xform, key, iv, msg, byteByByteSplits);
            Assertions.assertArrayEquals(oneShot, byteByByte,
                    xform + ": byte-by-byte chunking must match one-shot");

            // Pattern 2 — block-1 / block / block+1 alignments.
            byte[] adversarial = chunkEncrypt(xform, key, iv, msg, adversarialChunks(msgLen));
            Assertions.assertArrayEquals(oneShot, adversarial,
                    xform + ": adversarial-offset chunking must match one-shot");

            // Pattern 3 — random splits.
            byte[] randomSplit = chunkEncrypt(xform, key, iv, msg, randomSplitsOf(sr, msgLen, 5));
            Assertions.assertArrayEquals(oneShot, randomSplit,
                    xform + ": random-split chunking must match one-shot");

            // Round-trip confirms the ciphertext decrypts to the
            // original plaintext (since all chunkings match the one-
            // shot bytes, decrypting one means decrypting all).
            byte[] decoded = oneShotDecrypt(xform, key, iv, oneShot);
            Assertions.assertArrayEquals(msg, decoded,
                    xform + ": round-trip decrypt must recover plaintext");
        }
    }

    @Test
    public void testChunkingMatrix_unpaddedModes_blockAlignedSplits() throws Exception
    {
        // Unpadded modes accept update only with block-aligned input
        // lengths. Vary the split point across block boundaries.
        SecureRandom sr = seededRandom("testChunkingMatrix_unpaddedModes_blockAlignedSplits");

        String[] xforms = {
                "DESede/CBC/NoPadding",
                "DESede/ECB/NoPadding"
        };

        for (String xform : xforms)
        {
            int msgLen = 5 * DES_BLOCK;
            byte[] key = new byte[24];
            sr.nextBytes(key);
            byte[] iv = xform.contains("/CBC/") ? new byte[DES_BLOCK] : null;
            if (iv != null)
            {
                sr.nextBytes(iv);
            }
            byte[] msg = new byte[msgLen];
            sr.nextBytes(msg);

            byte[] oneShot = oneShotEncrypt(xform, key, iv, msg);

            // Split at every block boundary: feeds 1 block per update.
            int[] perBlockSplits = new int[msgLen / DES_BLOCK];
            java.util.Arrays.fill(perBlockSplits, DES_BLOCK);
            byte[] perBlock = chunkEncrypt(xform, key, iv, msg, perBlockSplits);
            Assertions.assertArrayEquals(oneShot, perBlock,
                    xform + ": per-block chunking must match one-shot");

            // Split at one varied block boundary across the message.
            for (int splitBlocks = 1; splitBlocks < msgLen / DES_BLOCK; splitBlocks++)
            {
                int splitAt = splitBlocks * DES_BLOCK;
                int[] twoSplits = {splitAt, msgLen - splitAt};
                byte[] split = chunkEncrypt(xform, key, iv, msg, twoSplits);
                Assertions.assertArrayEquals(oneShot, split,
                        xform + ": split at block-" + splitBlocks + " must match one-shot");
            }
        }
    }


    // -----------------------------------------------------------------
    // Offset-write contract (per CLAUDE.md "Verify offset-write contracts
    // via functional round-trip, not sentinel bytes"). Confirm:
    //   1. bytes preceding outOff are byte-for-byte untouched
    //   2. the writtenLen bytes starting at outOff decrypt to the plaintext
    //   3. a window starting at outOff-1 does NOT decrypt — proves the
    //      write landed at exactly outOff, not one byte earlier.
    // -----------------------------------------------------------------

    @Test
    public void testOffsetWrite_doFinal_DESedeCBC() throws Exception
    {
        SecureRandom sr = seededRandom("testOffsetWrite_doFinal_DESedeCBC");
        byte[] key = new byte[24];
        sr.nextBytes(key);
        byte[] iv = new byte[DES_BLOCK];
        sr.nextBytes(iv);

        SecretKeySpec ksp = new SecretKeySpec(key, "DESede");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // Plaintext is a block multiple — NoPadding so ciphertext length
        // equals plaintext length, making the shifted-window check exact.
        byte[] msg = new byte[3 * DES_BLOCK];
        sr.nextBytes(msg);
        int writtenLen = msg.length;

        int outOff = 11;
        int prefix = outOff;
        int trailer = 7;
        byte[] big = new byte[prefix + writtenLen + trailer];
        sr.nextBytes(big);

        byte[] expectedPrefix = new byte[prefix];
        System.arraycopy(big, 0, expectedPrefix, 0, prefix);

        Cipher enc = Cipher.getInstance("DESede/CBC/NoPadding", JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, ksp, ivSpec);
        int actuallyWritten = enc.doFinal(msg, 0, msg.length, big, outOff);
        Assertions.assertEquals(writtenLen, actuallyWritten,
                "doFinal must report the ciphertext length it wrote");

        // 1. Bytes preceding outOff must be unchanged.
        byte[] actualPrefix = new byte[prefix];
        System.arraycopy(big, 0, actualPrefix, 0, prefix);
        Assertions.assertArrayEquals(expectedPrefix, actualPrefix,
                "doFinal must not touch bytes before outOff");

        // 2. Bytes at [outOff, outOff+writtenLen) decrypt to the plaintext.
        byte[] window = new byte[writtenLen];
        System.arraycopy(big, outOff, window, 0, writtenLen);
        Cipher dec = Cipher.getInstance("DESede/CBC/NoPadding", JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, ksp, ivSpec);
        byte[] recovered = dec.doFinal(window);
        Assertions.assertArrayEquals(msg, recovered,
                "the writtenLen bytes from outOff must decrypt to the original plaintext");

        // 3. Negative: a window starting at outOff-1 must NOT decrypt
        //    to the plaintext. If the SPI silently shifted by one byte,
        //    the window would still round-trip — this catches that.
        if (outOff >= 1)
        {
            byte[] shifted = new byte[writtenLen];
            System.arraycopy(big, outOff - 1, shifted, 0, writtenLen);
            dec.init(Cipher.DECRYPT_MODE, ksp, ivSpec);
            byte[] shiftedDecoded = dec.doFinal(shifted);
            Assertions.assertFalse(Arrays.areEqual(msg, shiftedDecoded),
                    "shifted window (outOff-1) must NOT decrypt to plaintext");
        }
    }


    // -----------------------------------------------------------------
    // AlgorithmParameters init path (per CLAUDE.md SPI review). JCE
    // callers can hand parameters as AlgorithmParameters rather than
    // an AlgorithmParameterSpec — the SPI must accept both shapes.
    // -----------------------------------------------------------------

    @Test
    public void testAlgorithmParameters_init_cbc() throws Exception
    {
        SecureRandom sr = seededRandom("testAlgorithmParameters_init_cbc");
        byte[] key = new byte[24];
        sr.nextBytes(key);
        byte[] iv = new byte[DES_BLOCK];
        sr.nextBytes(iv);
        byte[] msg = new byte[16];
        sr.nextBytes(msg);

        // Build an AlgorithmParameters by initializing one from the IV
        // via BC (Jostle's AlgorithmParameters surface for DESede isn't
        // registered separately; BC's is the canonical reference).
        AlgorithmParameters algParams = AlgorithmParameters.getInstance("DESede",
                BouncyCastleProvider.PROVIDER_NAME);
        algParams.init(new IvParameterSpec(iv));

        // Encrypt via the IvParameterSpec path.
        Cipher viaSpec = Cipher.getInstance("DESede/CBC/PKCS7Padding", JostleProvider.PROVIDER_NAME);
        viaSpec.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DESede"), new IvParameterSpec(iv));
        byte[] expected = viaSpec.doFinal(msg);

        // Encrypt via the AlgorithmParameters path — must match.
        Cipher viaAlgParams = Cipher.getInstance("DESede/CBC/PKCS7Padding", JostleProvider.PROVIDER_NAME);
        viaAlgParams.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DESede"), algParams);
        byte[] actual = viaAlgParams.doFinal(msg);

        Assertions.assertArrayEquals(expected, actual,
                "init via AlgorithmParameters must produce the same ciphertext as init via IvParameterSpec");

        // Confirm decrypt via AlgorithmParameters path also works.
        Cipher dec = Cipher.getInstance("DESede/CBC/PKCS7Padding", JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "DESede"), algParams);
        Assertions.assertArrayEquals(msg, dec.doFinal(actual));
    }


    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    /**
     * Verify Jostle and BouncyCastle produce byte-equal ciphertexts
     * for the same key/IV/plaintext, and that each provider's decrypt
     * accepts the other's encrypt.
     */
    private static void agreeBothDirections(String xform, int maxMsgLen, int step, int ivLen, SecureRandom sr) throws Exception
    {
        for (int msgLen = 0; msgLen < maxMsgLen; msgLen += step)
        {
            byte[] key = new byte[24];
            sr.nextBytes(key);
            SecretKeySpec ksp = new SecretKeySpec(key, "DESede");

            IvParameterSpec ivSpec = null;
            if (ivLen > -1)
            {
                byte[] iv = new byte[ivLen];
                sr.nextBytes(iv);
                ivSpec = new IvParameterSpec(iv);
            }

            byte[] msg = new byte[msgLen];
            sr.nextBytes(msg);

            // Encrypt with each provider — bytes must match.
            byte[] bcCt = encrypt(xform, BouncyCastleProvider.PROVIDER_NAME, ksp, ivSpec, msg);
            byte[] jostleCt = encrypt(xform, JostleProvider.PROVIDER_NAME, ksp, ivSpec, msg);
            if (!Arrays.areEqual(bcCt, jostleCt))
            {
                System.out.println("xform=" + xform + " msgLen=" + msgLen);
                System.out.println("  key   = " + Hex.toHexString(key));
                System.out.println("  msg   = " + Hex.toHexString(msg));
                System.out.println("  BC    = " + Hex.toHexString(bcCt));
                System.out.println("  Jostle= " + Hex.toHexString(jostleCt));
            }
            Assertions.assertArrayEquals(bcCt, jostleCt,
                    xform + ": BC and Jostle ciphertexts differ at msgLen=" + msgLen);

            // Each provider decrypts the OTHER's ciphertext correctly.
            byte[] bcDecOfJostle = decrypt(xform, BouncyCastleProvider.PROVIDER_NAME, ksp, ivSpec, jostleCt);
            byte[] jostleDecOfBc = decrypt(xform, JostleProvider.PROVIDER_NAME, ksp, ivSpec, bcCt);

            Assertions.assertArrayEquals(msg, bcDecOfJostle,
                    xform + ": BC decrypt of Jostle ciphertext didn't match plaintext");
            Assertions.assertArrayEquals(msg, jostleDecOfBc,
                    xform + ": Jostle decrypt of BC ciphertext didn't match plaintext");
        }
    }

    private static byte[] encrypt(String xform, String provider, SecretKeySpec key, IvParameterSpec iv, byte[] msg)
            throws Exception
    {
        Cipher c = Cipher.getInstance(xform, provider);
        if (iv == null)
        {
            c.init(Cipher.ENCRYPT_MODE, key);
        }
        else
        {
            c.init(Cipher.ENCRYPT_MODE, key, iv);
        }
        try
        {
            return c.doFinal(msg);
        }
        catch (IllegalBlockSizeException e)
        {
            throw new RuntimeException("unexpected block-size error in NoPadding test: " + e.getMessage(), e);
        }
    }

    /**
     * One-shot encrypt with Jostle. Used as the reference output for
     * chunking-matrix comparisons.
     */
    private static byte[] oneShotEncrypt(String xform, byte[] key, byte[] iv, byte[] msg) throws Exception
    {
        Cipher c = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
        SecretKeySpec ksp = new SecretKeySpec(key, "DESede");
        if (iv == null)
        {
            c.init(Cipher.ENCRYPT_MODE, ksp);
        }
        else
        {
            c.init(Cipher.ENCRYPT_MODE, ksp, new IvParameterSpec(iv));
        }
        return c.doFinal(msg);
    }

    private static byte[] oneShotDecrypt(String xform, byte[] key, byte[] iv, byte[] ct) throws Exception
    {
        Cipher c = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
        SecretKeySpec ksp = new SecretKeySpec(key, "DESede");
        if (iv == null)
        {
            c.init(Cipher.DECRYPT_MODE, ksp);
        }
        else
        {
            c.init(Cipher.DECRYPT_MODE, ksp, new IvParameterSpec(iv));
        }
        return c.doFinal(ct);
    }

    /**
     * Encrypt by feeding {@code msg} through {@code update} in the given
     * chunk sizes, then a final empty {@code doFinal}. The chunk sizes
     * must sum to {@code msg.length}.
     *
     * <p>Uses the 5-argument {@code update}/{@code doFinal} variants with
     * a pre-allocated output buffer (sized from {@code getOutputSize}),
     * matching the pattern in {@code SM4AgreementTest.exercise_complexUpdateDoFinal}.
     * The 3-argument variants don't compose well with sub-block update
     * sizes in Jostle's current implementation — out-buffer auto-sizing
     * conflicts with an internal "out_len &gt;= in_len" check.
     */
    private static byte[] chunkEncrypt(String xform, byte[] key, byte[] iv, byte[] msg, int[] chunks)
            throws Exception
    {
        Cipher c = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
        SecretKeySpec ksp = new SecretKeySpec(key, "DESede");
        if (iv == null)
        {
            c.init(Cipher.ENCRYPT_MODE, ksp);
        }
        else
        {
            c.init(Cipher.ENCRYPT_MODE, ksp, new IvParameterSpec(iv));
        }

        int totalCipherLen = c.getOutputSize(msg.length);
        byte[] out = new byte[totalCipherLen];
        int written = 0;
        int off = 0;
        for (int len : chunks)
        {
            written += c.update(msg, off, len, out, written);
            off += len;
        }
        written += c.doFinal(msg, off, 0, out, written);

        // Trim to actually-written length — getOutputSize may overshoot
        // on padded modes when the final block is fully formed.
        if (written == out.length)
        {
            return out;
        }
        byte[] trimmed = new byte[written];
        System.arraycopy(out, 0, trimmed, 0, written);
        return trimmed;
    }

    /**
     * Produce a chunk sequence using block-1 / block / block+1
     * lengths so partial-block boundaries land in different places
     * across the message (per CLAUDE.md "adversarial offsets" rule).
     * The final chunk takes whatever's left to make the sequence
     * sum to {@code total}.
     */
    private static int[] adversarialChunks(int total)
    {
        java.util.ArrayList<Integer> chunks = new java.util.ArrayList<Integer>();
        int remaining = total;
        int[] cycle = {DES_BLOCK - 1, DES_BLOCK, DES_BLOCK + 1};
        int i = 0;
        while (remaining > cycle[i % cycle.length])
        {
            int take = cycle[i % cycle.length];
            chunks.add(take);
            remaining -= take;
            i++;
        }
        if (remaining > 0)
        {
            chunks.add(remaining);
        }
        int[] out = new int[chunks.size()];
        for (int j = 0; j < out.length; j++)
        {
            out[j] = chunks.get(j);
        }
        return out;
    }

    /**
     * Partition {@code total} into {@code partitionCount} random chunk
     * sizes that sum to {@code total}. Used by the chunking-matrix
     * tests to exercise non-block-aligned splits.
     */
    private static int[] randomSplitsOf(SecureRandom sr, int total, int partitionCount)
    {
        if (partitionCount <= 1)
        {
            return new int[]{total};
        }
        int[] splits = new int[partitionCount];
        int remaining = total;
        for (int i = 0; i < partitionCount - 1; i++)
        {
            // Each chunk can be 0..remaining; bias toward smaller so
            // we don't accidentally produce one giant chunk at the start.
            int take = sr.nextInt(remaining + 1);
            splits[i] = take;
            remaining -= take;
        }
        splits[partitionCount - 1] = remaining;
        return splits;
    }

    private static byte[] decrypt(String xform, String provider, SecretKeySpec key, IvParameterSpec iv, byte[] ct)
            throws Exception
    {
        Cipher c = Cipher.getInstance(xform, provider);
        if (iv == null)
        {
            c.init(Cipher.DECRYPT_MODE, key);
        }
        else
        {
            c.init(Cipher.DECRYPT_MODE, key, iv);
        }
        return c.doFinal(ct);
    }
}
