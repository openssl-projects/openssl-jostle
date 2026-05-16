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

package org.openssl.jostle.test.kdf;

import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.X963KDFKeySpec;
import org.openssl.jostle.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;

/**
 * Tests for the standalone ANSI X9.63 KDF {@link SecretKeyFactory}.
 *
 * <p>Coverage follows the CLAUDE.md test guidelines:
 * <ol>
 *   <li>BC agreement — Jostle's {@code X963KDF} produces output
 *       byte-identical to BC's {@code BCJSSE} / {@code BC} X9.63 KDF
 *       implementation for the same inputs across multiple random
 *       trials.</li>
 *   <li>Per-PRF transformation lookups (with/without forced digest)
 *       all resolve to a working factory.</li>
 *   <li>Digest-mismatch rejection — a pinned-PRF transformation
 *       rejects a spec naming a different digest.</li>
 *   <li>Constructor input validation — all four
 *       {@link X963KDFKeySpec} negative paths (null Z, empty Z, zero
 *       output length, null digest).</li>
 *   <li>Deterministic-stream property — two derivations with the
 *       same Z + sharedInfo + digest produce identical output; longer
 *       output extends a shorter output (since X9.63 KDF is a
 *       hash-counter stream).</li>
 *   <li>SharedInfo binding — different shared info produces
 *       different output.</li>
 * </ol>
 */
public class X963KDFTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }


    // -----------------------------------------------------------------
    // BC agreement — randomised across trials per CLAUDE.md
    // "Run agreement tests against BouncyCastle, with random inputs"
    // -----------------------------------------------------------------

    @Test
    public void x963kdf_BCAgreement_SHA256() throws Exception
    {
        // 10 trials with random Z, sharedInfo, and output length.
        for (int trial = 0; trial < 10; trial++)
        {
            int zLen = 16 + RANDOM.nextInt(48);
            int sharedInfoLen = RANDOM.nextInt(64);
            int outLen = 16 + RANDOM.nextInt(96);

            byte[] z = randomBytes(zLen);
            byte[] sharedInfo = sharedInfoLen == 0 ? null : randomBytes(sharedInfoLen);

            byte[] joKey = deriveJo("X963KDFwithSHA256", z, sharedInfo, outLen, "SHA-256");
            byte[] bcKey = deriveBcLowLevel(new SHA256Digest(), z, sharedInfo, outLen);

            Assertions.assertTrue(Arrays.areEqual(joKey, bcKey),
                    "trial " + trial + " (zLen=" + zLen
                            + " sharedInfoLen=" + sharedInfoLen
                            + " outLen=" + outLen
                            + "): Jostle output differs from BC reference");
        }
    }

    @Test
    public void x963kdf_BCAgreement_SHA1() throws Exception
    {
        for (int trial = 0; trial < 5; trial++)
        {
            int zLen = 20 + trial * 4;
            int outLen = 16 + trial * 8;
            byte[] z = randomBytes(zLen);
            byte[] sharedInfo = randomBytes(8 + trial);

            byte[] joKey = deriveJo("X963KDFwithSHA1", z, sharedInfo, outLen, "SHA-1");
            byte[] bcKey = deriveBcLowLevel(new SHA1Digest(), z, sharedInfo, outLen);

            Assertions.assertTrue(Arrays.areEqual(joKey, bcKey),
                    "SHA-1 trial " + trial + ": Jostle output differs from BC");
        }
    }


    // -----------------------------------------------------------------
    // Bare X963KDF — accepts any PRF carried in the spec
    // -----------------------------------------------------------------

    @Test
    public void x963kdf_bareForm_acceptsAnyPRF() throws Exception
    {
        byte[] z = randomBytes(32);
        byte[] sharedInfo = randomBytes(16);

        SecretKeyFactory bare = SecretKeyFactory.getInstance("X963KDF",
                JostleProvider.PROVIDER_NAME);

        byte[] sha256 = bare.generateSecret(new X963KDFKeySpec(z, sharedInfo, 32, "SHA-256")).getEncoded();
        byte[] sha384 = bare.generateSecret(new X963KDFKeySpec(z, sharedInfo, 32, "SHA-384")).getEncoded();

        Assertions.assertFalse(Arrays.areEqual(sha256, sha384),
                "Same Z/sharedInfo with different PRFs must produce different output");
    }


    // -----------------------------------------------------------------
    // Pinned PRF rejects mismatched spec
    // -----------------------------------------------------------------

    @Test
    public void x963kdf_digestMismatch_rejected() throws Exception
    {
        SecretKeyFactory pinned = SecretKeyFactory.getInstance("X963KDFwithSHA256",
                JostleProvider.PROVIDER_NAME);
        byte[] z = randomBytes(16);
        X963KDFKeySpec spec = new X963KDFKeySpec(z, null, 32, "SHA-384");
        try
        {
            pinned.generateSecret(spec);
            Assertions.fail("expected InvalidKeySpecException for PRF mismatch");
        }
        catch (InvalidKeySpecException expected)
        {
            Assertions.assertNotNull(expected.getMessage());
            Assertions.assertTrue(
                    expected.getMessage().contains("does not match forced PRF"),
                    "unexpected message: " + expected.getMessage());
        }
    }


    // -----------------------------------------------------------------
    // X963KDFKeySpec constructor negative paths
    // -----------------------------------------------------------------

    @Test
    public void x963kdfKeySpec_nullZ_rejected()
    {
        try
        {
            new X963KDFKeySpec(null, null, 32, "SHA-256");
            Assertions.fail("expected IllegalArgumentException for null Z");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("z is null", expected.getMessage());
        }
    }

    @Test
    public void x963kdfKeySpec_emptyZ_rejected()
    {
        try
        {
            new X963KDFKeySpec(new byte[0], null, 32, "SHA-256");
            Assertions.fail("expected IllegalArgumentException for empty Z");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("z is empty", expected.getMessage());
        }
    }

    @Test
    public void x963kdfKeySpec_zeroOutLength_rejected()
    {
        try
        {
            new X963KDFKeySpec(new byte[]{1, 2, 3}, null, 0, "SHA-256");
            Assertions.fail("expected IllegalArgumentException for zero output length");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("outLengthBytes must be positive",
                    expected.getMessage());
        }
    }

    @Test
    public void x963kdfKeySpec_nullDigest_rejected()
    {
        try
        {
            new X963KDFKeySpec(new byte[]{1, 2, 3}, null, 32, null);
            Assertions.fail("expected IllegalArgumentException for null digest");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("digestAlgorithm is null", expected.getMessage());
        }
    }


    // -----------------------------------------------------------------
    // Deterministic stream property
    // -----------------------------------------------------------------

    @Test
    public void x963kdf_sameInputs_sameOutput() throws Exception
    {
        byte[] z = randomBytes(32);
        byte[] info = randomBytes(16);

        byte[] a = deriveJo("X963KDFwithSHA256", z, info, 64, "SHA-256");
        byte[] b = deriveJo("X963KDFwithSHA256", z, info, 64, "SHA-256");
        Assertions.assertTrue(Arrays.areEqual(a, b),
                "X9.63 KDF must be deterministic for the same inputs");
    }

    @Test
    public void x963kdf_longerOutputExtendsShorter() throws Exception
    {
        // X9.63 KDF emits Hash(Z || counter || sharedInfo) for counter
        // = 1, 2, 3, ... concatenated. So a longer output is exactly
        // the shorter output extended.
        byte[] z = randomBytes(32);
        byte[] info = randomBytes(16);

        byte[] outShort = deriveJo("X963KDFwithSHA256", z, info, 16, "SHA-256");
        byte[] outLong = deriveJo("X963KDFwithSHA256", z, info, 48, "SHA-256");

        for (int i = 0; i < outShort.length; i++)
        {
            Assertions.assertEquals(outShort[i], outLong[i],
                    "byte " + i + " of longer output should match shorter output");
        }
    }


    // -----------------------------------------------------------------
    // SharedInfo binding
    // -----------------------------------------------------------------

    @Test
    public void x963kdf_differentSharedInfo_differentOutput() throws Exception
    {
        byte[] z = randomBytes(32);

        byte[] a = deriveJo("X963KDFwithSHA256", z, new byte[]{1, 2, 3, 4}, 32, "SHA-256");
        byte[] b = deriveJo("X963KDFwithSHA256", z, new byte[]{5, 6, 7, 8}, 32, "SHA-256");
        Assertions.assertFalse(Arrays.areEqual(a, b),
                "Different shared info must produce different output");
    }

    @Test
    public void x963kdf_nullVsEmptySharedInfo_sameOutput() throws Exception
    {
        // RFC X9.63 treats absent and empty shared-info equivalently
        // — both append zero bytes after the counter. OpenSSL follows
        // the same convention.
        byte[] z = randomBytes(32);

        byte[] withNull = deriveJo("X963KDFwithSHA256", z, null, 32, "SHA-256");
        byte[] withEmpty = deriveJo("X963KDFwithSHA256", z, new byte[0], 32, "SHA-256");
        Assertions.assertTrue(Arrays.areEqual(withNull, withEmpty),
                "Null shared info and empty shared info must produce the same output");
    }


    // -----------------------------------------------------------------
    // Unknown transformation
    // -----------------------------------------------------------------

    @Test
    public void x963kdf_unknownTransformation_throwsNoSuchAlgorithm() throws Exception
    {
        try
        {
            SecretKeyFactory.getInstance("X963KDFwithMadeUpDigest",
                    JostleProvider.PROVIDER_NAME);
            Assertions.fail("expected NoSuchAlgorithmException");
        }
        catch (NoSuchAlgorithmException expected)
        {
            // Good.
        }
    }


    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private static byte[] deriveJo(String xform, byte[] z, byte[] sharedInfo,
                                   int outLen, String digest) throws Exception
    {
        SecretKeyFactory kf = SecretKeyFactory.getInstance(xform, JostleProvider.PROVIDER_NAME);
        X963KDFKeySpec spec = new X963KDFKeySpec(z, sharedInfo, outLen, digest);
        SecretKey k = kf.generateSecret(spec);
        return k.getEncoded();
    }

    /**
     * Drive BC's low-level X9.63 KDF implementation and return the
     * derived bytes. We use {@code KDF2BytesGenerator} from BC's
     * crypto layer — KDF2 with the BC convention (counter starts at
     * 1) matches the ANSI X9.63 KDF, which is what OpenSSL's
     * "X963KDF" implements.
     */
    private static byte[] deriveBcLowLevel(org.bouncycastle.crypto.Digest digest,
                                           byte[] z, byte[] sharedInfo, int outLen)
    {
        org.bouncycastle.crypto.generators.KDF2BytesGenerator kdf =
                new org.bouncycastle.crypto.generators.KDF2BytesGenerator(digest);
        kdf.init(new KDFParameters(z, sharedInfo));
        byte[] out = new byte[outLen];
        kdf.generateBytes(out, 0, outLen);
        return out;
    }

    private static byte[] randomBytes(int n)
    {
        byte[] b = new byte[n];
        RANDOM.nextBytes(b);
        return b;
    }
}
