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
import org.bouncycastle.crypto.agreement.kdf.ConcatenationKDFGenerator;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.SSKDFParameterSpec;
import org.openssl.jostle.util.Arrays;

import javax.crypto.SecretKeyFactory;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;

/**
 * SP 800-56C one-step KDF coverage for the native {@code EVP_KDF "SSKDF"}
 * surface exposed as {@code SecretKeyFactory "SSKDF-<digest>"}.
 *
 * <p>Cross-validated against BouncyCastle's software
 * {@code ConcatenationKDFGenerator} — the same construction,
 * {@code H(counter || Z || FixedInfo)} — with random inputs, plus the vectors
 * OpenSSL itself ships and a differentiator per input.</p>
 */
public class SSKDFTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final int TRIALS = 15;

    private static final String[] ALGS = {
            "SSKDF-SHA1", "SSKDF-SHA224", "SSKDF-SHA256", "SSKDF-SHA384", "SSKDF-SHA512"
    };

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

    private static Digest bcDigestFor(String alg)
    {
        if (alg.endsWith("SHA1"))
        {
            return new SHA1Digest();
        }
        if (alg.endsWith("SHA224"))
        {
            return new SHA224Digest();
        }
        if (alg.endsWith("SHA256"))
        {
            return new SHA256Digest();
        }
        if (alg.endsWith("SHA384"))
        {
            return new SHA384Digest();
        }
        if (alg.endsWith("SHA512"))
        {
            return new SHA512Digest();
        }
        throw new IllegalArgumentException("no BC digest for " + alg);
    }

    private static byte[] jostle(String alg, SSKDFParameterSpec spec) throws Exception
    {
        return SecretKeyFactory.getInstance(alg, JostleProvider.PROVIDER_NAME)
                .generateSecret(spec).getEncoded();
    }

    private static byte[] bcConcat(Digest digest, byte[] secret, byte[] info, int len)
    {
        ConcatenationKDFGenerator gen = new ConcatenationKDFGenerator(digest);
        gen.init(new KDFParameters(secret, info));
        byte[] out = new byte[len];
        gen.generateBytes(out, 0, len);
        return out;
    }

    // ---------------------------------------------------------------- KATs

    /**
     * The SHA-1 and SHA-256 vectors OpenSSL's own {@code evpkdf_ss.txt} carries.
     * There are no official NIST vectors for the one-step KDF; these come from
     * the widely-used singlestep-kdf vector set OpenSSL adopted.
     */
    @Test
    public void oneStepVectors() throws Exception
    {
        Assertions.assertArrayEquals(Hex.decode("b5a3c52e97ae6e8c5069954354eab3c7"),
                jostle("SSKDF-SHA1", new SSKDFParameterSpec(
                        Hex.decode("d09a6b1a472f930db4f5e6b967900744"),
                        Hex.decode("b117255ab5f1b6b96fc434b0"), 16)));

        Assertions.assertArrayEquals(Hex.decode("1003b650ddd3f0891a15166db5ec881d"),
                jostle("SSKDF-SHA1", new SSKDFParameterSpec(
                        Hex.decode("343666c0dd34b756e70f759f14c304f5"),
                        Hex.decode("722b28448d7eab85491bce09"), 16)));

        Assertions.assertArrayEquals(Hex.decode("f0b80d6ae4c1e19e2105a37024e35dc6"),
                jostle("SSKDF-SHA256", new SSKDFParameterSpec(
                        Hex.decode("afc4e154498d4770aa8365f6903dc83b"),
                        Hex.decode("662af20379b29d5ef813e655"), 16)));

        // Differentiator per vector: the two SHA-1 vectors above differ only in
        // their inputs, so a stub returning a constant fails already — but a
        // factory that ignored FixedInfo would still pass both. Flip one bit.
        byte[] info = Hex.decode("662af20379b29d5ef813e655");
        info[0] ^= (byte) 0x01;
        Assertions.assertFalse(Arrays.areEqual(Hex.decode("f0b80d6ae4c1e19e2105a37024e35dc6"),
                        jostle("SSKDF-SHA256", new SSKDFParameterSpec(
                                Hex.decode("afc4e154498d4770aa8365f6903dc83b"), info, 16))),
                "flipping a FixedInfo bit must change the derived key");
    }

    // ----------------------------------------------------------- agreement

    @Test
    public void agreesWithBouncyCastle() throws Exception
    {
        SecureRandom sr = seededRandom("agreesWithBouncyCastle");

        for (String alg : ALGS)
        {
            for (int trial = 0; trial < TRIALS; trial++)
            {
                byte[] secret = random(16 + sr.nextInt(48), sr);
                // BC's ConcatenationKDFGenerator dereferences otherInfo, so the
                // agreement runs with a non-empty FixedInfo; the absent/empty
                // case is covered by absentInfoEqualsEmptyInfo below.
                byte[] info = random(1 + sr.nextInt(64), sr);
                int len = 1 + sr.nextInt(200);

                Assertions.assertArrayEquals(
                        bcConcat(bcDigestFor(alg), secret, info, len),
                        jostle(alg, new SSKDFParameterSpec(secret, info, len)),
                        alg + " len=" + len);
            }
        }
    }

    // ------------------------------------------------------- negative path

    @Test
    public void everyInputInfluencesTheDerivedKey() throws Exception
    {
        SecureRandom sr = seededRandom("everyInputInfluencesTheDerivedKey");
        byte[] secret = random(32, sr);
        byte[] info = random(20, sr);

        byte[] base = jostle("SSKDF-SHA256", new SSKDFParameterSpec(secret, info, 40));

        Assertions.assertFalse(Arrays.areEqual(base,
                        jostle("SSKDF-SHA256", new SSKDFParameterSpec(random(32, sr), info, 40))),
                "the shared secret must influence the derived key");
        Assertions.assertFalse(Arrays.areEqual(base,
                        jostle("SSKDF-SHA256", new SSKDFParameterSpec(secret, random(20, sr), 40))),
                "FixedInfo must influence the derived key");
        Assertions.assertFalse(Arrays.areEqual(base,
                        jostle("SSKDF-SHA384", new SSKDFParameterSpec(secret, info, 40))),
                "the digest must influence the derived key");
    }

    /**
     * Absent FixedInfo and empty FixedInfo are the same derivation. Measured on
     * every supported OpenSSL build, and relied on by the NI, which represents
     * "no FixedInfo" as a null array with no distinct sentinel.
     */
    @Test
    public void absentInfoEqualsEmptyInfo() throws Exception
    {
        SecureRandom sr = seededRandom("absentInfoEqualsEmptyInfo");
        byte[] secret = random(32, sr);

        Assertions.assertArrayEquals(
                jostle("SSKDF-SHA256", new SSKDFParameterSpec(secret, null, 32)),
                jostle("SSKDF-SHA256", new SSKDFParameterSpec(secret, new byte[0], 32)));
    }

    @Test
    public void derivationIsDeterministic() throws Exception
    {
        SecureRandom sr = seededRandom("derivationIsDeterministic");
        SSKDFParameterSpec spec = new SSKDFParameterSpec(random(32, sr), random(12, sr), 48);

        Assertions.assertArrayEquals(jostle("SSKDF-SHA256", spec), jostle("SSKDF-SHA256", spec));
    }

    // -------------------------------------------------------- spec contract

    @Test
    public void specRejectsInvalidArguments()
    {
        byte[] secret = new byte[32];

        Assertions.assertEquals("secret is null", Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> new SSKDFParameterSpec(null, null, 16)).getMessage());

        for (int badLen : new int[]{0, -1, Integer.MIN_VALUE})
        {
            Assertions.assertEquals("output length must be positive", Assertions.assertThrows(
                    IllegalArgumentException.class,
                    () -> new SSKDFParameterSpec(secret, null, badLen)).getMessage());
        }

        Assertions.assertEquals(1, new SSKDFParameterSpec(secret, null, 1).getOutputLength());
    }

    @Test
    public void specAccessorsReturnCopies()
    {
        byte[] secret = new byte[]{1, 2, 3, 4};
        byte[] info = new byte[]{5, 6};
        SSKDFParameterSpec spec = new SSKDFParameterSpec(secret, info, 16);

        spec.getSecret()[0] = (byte) 0xff;
        spec.getInfo()[0] = (byte) 0xff;
        Assertions.assertEquals(1, spec.getSecret()[0]);
        Assertions.assertEquals(5, spec.getInfo()[0]);

        secret[0] = (byte) 0xff;
        Assertions.assertEquals(1, spec.getSecret()[0]);
    }

    @Test
    public void factoryRejectsWrongKeySpec() throws Exception
    {
        SecretKeyFactory f = SecretKeyFactory.getInstance("SSKDF-SHA256",
                JostleProvider.PROVIDER_NAME);

        Assertions.assertEquals("unsupported KeySpec null", Assertions.assertThrows(
                InvalidKeySpecException.class, () -> f.generateSecret(null)).getMessage());

        Assertions.assertTrue(Assertions.assertThrows(InvalidKeySpecException.class,
                        () -> f.generateSecret(new javax.crypto.spec.PBEKeySpec("x".toCharArray())))
                .getMessage().startsWith("unsupported KeySpec javax.crypto.spec.PBEKeySpec"));
    }

    @Test
    public void everyRegisteredNameDerives() throws Exception
    {
        SecureRandom sr = seededRandom("everyRegisteredNameDerives");

        for (String alg : ALGS)
        {
            byte[] out = jostle(alg, new SSKDFParameterSpec(random(32, sr), random(8, sr), 32));
            Assertions.assertEquals(32, out.length, alg);
            Assertions.assertFalse(Arrays.areEqual(new byte[32], out), alg + " produced zeros");
        }
    }
}
