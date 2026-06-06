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

package org.openssl.jostle.test.md;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;

/**
 * Tests for the fixed-output SHAKE MessageDigest registrations
 * {@code SHAKE128-256} and {@code SHAKE256-512} added to {@code ProvMD}.
 *
 * <p>These names treat SHAKE as a plain hash squeezed to a fixed length
 * (256 / 512 bits) — the form BouncyCastle's CMS/PKIX layer asks for. JSL
 * maps them onto SHAKE-128 / SHAKE-256 with a fixed 32 / 64-byte output, so
 * the output must byte-match BC's default-length {@code SHAKE128} /
 * {@code SHAKE256} digests (which produce 32 / 64 bytes).
 */
public class ShakeFixedLengthTest
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
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    public void testDigestLengths() throws Exception
    {
        Assertions.assertEquals(32,
                MessageDigest.getInstance("SHAKE128-256", JostleProvider.PROVIDER_NAME).getDigestLength());
        Assertions.assertEquals(64,
                MessageDigest.getInstance("SHAKE256-512", JostleProvider.PROVIDER_NAME).getDigestLength());
    }

    @Test
    public void testShake128_256_agreesWithBC() throws Exception
    {
        agreesWithBC("testShake128_256_agreesWithBC", "SHAKE128-256", "SHAKE128", 32);
    }

    @Test
    public void testShake256_512_agreesWithBC() throws Exception
    {
        agreesWithBC("testShake256_512_agreesWithBC", "SHAKE256-512", "SHAKE256", 64);
    }

    /**
     * Multi-trial random-input agreement: JSL's fixed-length SHAKE digest must
     * equal BC's default-length SHAKE digest of the same input. Varies the
     * input length per trial so a length-dependent finalisation bug surfaces.
     */
    private static void agreesWithBC(String testName, String jslName, String bcName, int expectedLen)
            throws Exception
    {
        SecureRandom sr = seededRandom(testName);
        for (int trial = 0; trial < 25; trial++)
        {
            byte[] msg = new byte[sr.nextInt(4096)];
            sr.nextBytes(msg);

            MessageDigest jsl = MessageDigest.getInstance(jslName, JostleProvider.PROVIDER_NAME);
            MessageDigest bc = MessageDigest.getInstance(bcName, BouncyCastleProvider.PROVIDER_NAME);

            byte[] jslOut = jsl.digest(msg);
            byte[] bcOut = bc.digest(msg);

            Assertions.assertEquals(expectedLen, jslOut.length, jslName + ": wrong output length");
            Assertions.assertArrayEquals(bcOut, jslOut,
                    jslName + " vs BC " + bcName + ": digest mismatch at trial=" + trial + " len=" + msg.length);
        }
    }

    @Test
    public void testChunkingMatchesOneShot() throws Exception
    {
        SecureRandom sr = seededRandom("testChunkingMatchesOneShot");
        for (String name : new String[]{"SHAKE128-256", "SHAKE256-512"})
        {
            byte[] msg = new byte[1024 + sr.nextInt(1024)];
            sr.nextBytes(msg);

            MessageDigest oneShot = MessageDigest.getInstance(name, JostleProvider.PROVIDER_NAME);
            byte[] expected = oneShot.digest(msg);

            // Byte-by-byte update must produce the identical digest.
            MessageDigest incremental = MessageDigest.getInstance(name, JostleProvider.PROVIDER_NAME);
            for (byte b : msg)
            {
                incremental.update(b);
            }
            Assertions.assertArrayEquals(expected, incremental.digest(),
                    name + ": byte-by-byte digest diverged from one-shot");
        }
    }

    /**
     * Negative path: distinct inputs must produce distinct digests, and a
     * single-bit change must change the output. A stub that ignores input
     * bytes (or hashes only a prefix) fails here.
     */
    @Test
    public void testDistinctInputsProduceDistinctDigests() throws Exception
    {
        SecureRandom sr = seededRandom("testDistinctInputsProduceDistinctDigests");
        for (String name : new String[]{"SHAKE128-256", "SHAKE256-512"})
        {
            byte[] a = new byte[128];
            sr.nextBytes(a);
            byte[] b = Arrays.clone(a);
            b[64] ^= 0x01; // single-bit difference

            byte[] da = MessageDigest.getInstance(name, JostleProvider.PROVIDER_NAME).digest(a);
            byte[] db = MessageDigest.getInstance(name, JostleProvider.PROVIDER_NAME).digest(b);

            Assertions.assertFalse(Arrays.areEqual(da, db),
                    name + ": single-bit-different inputs produced identical digests");
        }
    }
}
