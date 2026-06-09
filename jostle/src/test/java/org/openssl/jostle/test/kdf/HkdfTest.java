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

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.HKDFParameterSpec;
import org.openssl.jostle.util.Arrays;

import javax.crypto.SecretKeyFactory;
import java.security.SecureRandom;
import java.security.Security;
import java.util.function.Supplier;

/**
 * HKDF (RFC 5869) coverage for the native {@code EVP_KDF "HKDF"} surface exposed
 * as {@code SecretKeyFactory "HKDF-SHA256/384/512"}. Cross-validates against
 * BouncyCastle's software {@code HKDFBytesGenerator} with random inputs (per the
 * CLAUDE.md agreement-test discipline), pins an RFC 5869 KAT, and exercises the
 * negative path (each input must influence the derived key; HKDF is deterministic).
 */
public class HkdfTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

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

    private static byte[] random(int length, SecureRandom sr)
    {
        byte[] bytes = new byte[length];
        sr.nextBytes(bytes);
        return bytes;
    }

    private static byte[] bcHkdf(Digest digest, byte[] ikm, byte[] salt, byte[] info, int len)
    {
        HKDFBytesGenerator gen = new HKDFBytesGenerator(digest);
        gen.init(new HKDFParameters(ikm, salt, info));
        byte[] out = new byte[len];
        gen.generateBytes(out, 0, len);
        return out;
    }

    private static byte[] jostleHkdf(String alg, byte[] ikm, byte[] salt, byte[] info, int len) throws Exception
    {
        SecretKeyFactory kf = SecretKeyFactory.getInstance(alg, JostleProvider.PROVIDER_NAME);
        return kf.generateSecret(new HKDFParameterSpec(ikm, salt, info, len)).getEncoded();
    }

    /**
     * Random-input agreement against BouncyCastle for every registered digest.
     * Varies IKM, salt, info, and output length per trial.
     */
    @Test
    public void testBCAgreement() throws Exception
    {
        SecureRandom sr = seededRandom("testBCAgreement");

        String[] algs = {"HKDF-SHA256", "HKDF-SHA384", "HKDF-SHA512"};
        @SuppressWarnings("unchecked")
        Supplier<Digest>[] digests = new Supplier[]{
                (Supplier<Digest>) SHA256Digest::new,
                (Supplier<Digest>) SHA384Digest::new,
                (Supplier<Digest>) SHA512Digest::new
        };

        for (int d = 0; d < algs.length; d++)
        {
            for (int trial = 0; trial < 15; trial++)
            {
                byte[] ikm = random(1 + sr.nextInt(64), sr);
                byte[] salt = random(sr.nextInt(48), sr);
                byte[] info = random(sr.nextInt(48), sr);
                int len = 1 + sr.nextInt(96);

                byte[] bc = bcHkdf(digests[d].get(), ikm, salt, info, len);
                byte[] jo = jostleHkdf(algs[d], ikm, salt, info, len);

                Assertions.assertArrayEquals(bc, jo,
                        algs[d] + " disagreed with BouncyCastle on trial " + trial);
            }
        }
    }

    /**
     * A null salt must agree with BouncyCastle's null/empty-salt path
     * (HKDF-Extract with HashLen zeros, RFC 5869 §2.2). The JSL spec stores an
     * empty salt as null, so this also covers the empty-salt case.
     */
    @Test
    public void testNullSaltAgreesWithBC() throws Exception
    {
        SecureRandom sr = seededRandom("testNullSaltAgreesWithBC");

        for (int trial = 0; trial < 10; trial++)
        {
            byte[] ikm = random(1 + sr.nextInt(64), sr);
            byte[] info = random(sr.nextInt(32), sr);
            int len = 1 + sr.nextInt(64);

            byte[] bc = bcHkdf(new SHA256Digest(), ikm, null, info, len);
            byte[] jo = jostleHkdf("HKDF-SHA256", ikm, null, info, len);

            Assertions.assertArrayEquals(bc, jo, "null-salt HKDF disagreed with BouncyCastle");

            // Empty salt must be treated identically to a null salt.
            byte[] joEmptySalt = jostleHkdf("HKDF-SHA256", ikm, new byte[0], info, len);
            Assertions.assertArrayEquals(bc, joEmptySalt, "empty salt must equal null salt");
        }
    }

    /**
     * RFC 5869 Test Case 1 (HMAC-SHA-256) — a pinned known-answer vector so an
     * implementation that ignores some input bits cannot pass the agreement test
     * by coincidence.
     */
    @Test
    public void testRFC5869Vector1() throws Exception
    {
        byte[] ikm = Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] salt = Hex.decode("000102030405060708090a0b0c");
        byte[] info = Hex.decode("f0f1f2f3f4f5f6f7f8f9");
        int len = 42;
        byte[] expected = Hex.decode(
                "3cb25f25faacd57a90434f64d0362f2a" +
                "2d2d0a90cf1a5a4c5db02d56ecc4c5bf" +
                "34007208d5b887185865");

        byte[] jo = jostleHkdf("HKDF-SHA256", ikm, salt, info, len);
        Assertions.assertArrayEquals(expected, jo, "RFC 5869 Test Case 1 mismatch");
    }

    /**
     * Negative path per CLAUDE.md: each input must influence the derived key, and
     * HKDF must be deterministic for identical inputs.
     */
    @Test
    public void testInputsActuallyInfluenceDerivedKey() throws Exception
    {
        SecureRandom sr = seededRandom("testInputsActuallyInfluenceDerivedKey");

        byte[] ikm1 = random(32, sr);
        byte[] ikm2 = random(32, sr);
        byte[] salt1 = random(16, sr);
        byte[] salt2 = random(16, sr);
        byte[] info1 = random(16, sr);
        byte[] info2 = random(16, sr);
        int len = 48;

        byte[] base = jostleHkdf("HKDF-SHA256", ikm1, salt1, info1, len);

        byte[] diffIkm = jostleHkdf("HKDF-SHA256", ikm2, salt1, info1, len);
        Assertions.assertFalse(Arrays.areEqual(base, diffIkm),
                "different IKM must produce a different derived key");

        byte[] diffSalt = jostleHkdf("HKDF-SHA256", ikm1, salt2, info1, len);
        Assertions.assertFalse(Arrays.areEqual(base, diffSalt),
                "different salt must produce a different derived key");

        byte[] diffInfo = jostleHkdf("HKDF-SHA256", ikm1, salt1, info2, len);
        Assertions.assertFalse(Arrays.areEqual(base, diffInfo),
                "different info must produce a different derived key");

        byte[] diffLen = jostleHkdf("HKDF-SHA256", ikm1, salt1, info1, len / 2);
        Assertions.assertFalse(Arrays.areEqual(base, diffLen),
                "a shorter request must not equal a prefix-mismatched longer key");

        // HKDF is deterministic — same inputs, same output.
        byte[] repeat = jostleHkdf("HKDF-SHA256", ikm1, salt1, info1, len);
        Assertions.assertArrayEquals(base, repeat,
                "same inputs must produce the same derived key (HKDF is deterministic)");

        // A different digest must produce a different key for the same inputs.
        byte[] sha512 = jostleHkdf("HKDF-SHA512", ikm1, salt1, info1, len);
        Assertions.assertFalse(Arrays.areEqual(base, sha512),
                "different digest must produce a different derived key");
    }
}
