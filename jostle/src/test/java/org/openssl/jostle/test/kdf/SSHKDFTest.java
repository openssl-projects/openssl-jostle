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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.SSHKDFParameterSpec;
import org.openssl.jostle.util.Arrays;

import javax.crypto.SecretKeyFactory;
import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;

/**
 * RFC 4253 section 7.2 SSH key-derivation coverage for the native
 * {@code EVP_KDF "SSHKDF"} surface exposed as
 * {@code SecretKeyFactory "SSHKDF-<digest>"}.
 *
 * <p>BouncyCastle has no SSH KDF, so the independent reference is
 * {@link #rfc4253Reference} — the RFC's own recurrence written directly against
 * a JDK {@code MessageDigest}. That is a genuinely independent implementation
 * (different code, different digest provider) rather than a pinned table, which
 * matters because it exercises arbitrary random inputs and every output length,
 * not the handful of lengths the CAVS vectors happen to cover. The NIST CAVS
 * vectors are pinned as well, for all six key types.</p>
 */
public class SSHKDFTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final int TRIALS = 15;

    private static final String[] ALGS = {
            "SSHKDF-SHA1", "SSHKDF-SHA224", "SSHKDF-SHA256", "SSHKDF-SHA384", "SSHKDF-SHA512"
    };

    /** CAVS 14.1 test group 1: K, H and session id shared by the six type vectors. */
    private static final byte[] CAVS_K = Hex.decode(
            "0000008055bae931c07fd824bf10add1902b6fbc7c665347383498a686929ff5"
                    + "a25f8e40cb6645ea814fb1a5e0a11f852f86255641e5ed986e83a78bc8269480"
                    + "eac0b0dfd770cab92e7a28dd87ff452466d6ae867cead63b366b1c286e6c4811"
                    + "a9f14c27aea14c5171d49b78c06e3735d36e6a3be321dd5fc82308f34ee1cb17"
                    + "fba94a59");
    private static final byte[] CAVS_H = Hex.decode("a4ebd45934f56792b5112dcd75a1075fdc889245");

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

    private static String jceDigestFor(String alg)
    {
        if (alg.endsWith("SHA1"))
        {
            return "SHA-1";
        }
        if (alg.endsWith("SHA224"))
        {
            return "SHA-224";
        }
        if (alg.endsWith("SHA256"))
        {
            return "SHA-256";
        }
        if (alg.endsWith("SHA384"))
        {
            return "SHA-384";
        }
        if (alg.endsWith("SHA512"))
        {
            return "SHA-512";
        }
        throw new IllegalArgumentException("no digest for " + alg);
    }

    private static byte[] jostle(String alg, SSHKDFParameterSpec spec) throws Exception
    {
        return SecretKeyFactory.getInstance(alg, JostleProvider.PROVIDER_NAME)
                .generateSecret(spec).getEncoded();
    }

    /**
     * RFC 4253 section 7.2, written out:
     * <pre>
     *   K1 = HASH(K || H || X || session_id)
     *   K2 = HASH(K || H || K1)
     *   K3 = HASH(K || H || K1 || K2)
     *   key = K1 || K2 || K3 ...
     * </pre>
     * Deliberately built on the JDK's {@code MessageDigest} (resolved through
     * BouncyCastle or the JDK, never through Jostle) so the comparison is
     * against code and a digest implementation that share nothing with the
     * native path under test.
     */
    private static byte[] rfc4253Reference(String digestName, byte[] k, byte[] h,
                                           byte[] sessionId, char type, int len)
            throws Exception
    {
        MessageDigest md = MessageDigest.getInstance(digestName,
                BouncyCastleProvider.PROVIDER_NAME);
        ByteArrayOutputStream produced = new ByteArrayOutputStream();

        md.update(k);
        md.update(h);
        md.update((byte) type);
        md.update(sessionId);
        byte[] block = md.digest();
        produced.write(block);

        while (produced.size() < len)
        {
            md.reset();
            md.update(k);
            md.update(h);
            md.update(produced.toByteArray());
            block = md.digest();
            produced.write(block);
        }

        return Arrays.copyOfRange(produced.toByteArray(), 0, len);
    }

    // ---------------------------------------------------------------- KATs

    /** NIST CAVS 14.1 SHA-1 vectors, all six key types from one exchange. */
    @Test
    public void cavsVectorsAllSixTypes() throws Exception
    {
        Object[][] vectors = {
                {SSHKDFParameterSpec.KeyType.INITIAL_IV_CLIENT_TO_SERVER, "e2f627c0b43f1ac1"},
                {SSHKDFParameterSpec.KeyType.INITIAL_IV_SERVER_TO_CLIENT, "58471445f342b181"},
                {SSHKDFParameterSpec.KeyType.ENCRYPTION_KEY_CLIENT_TO_SERVER,
                        "1ca9d310f86d51f6cb8e7007cb2b220d55c5281ce680b533"},
                {SSHKDFParameterSpec.KeyType.ENCRYPTION_KEY_SERVER_TO_CLIENT,
                        "2c60df8603d34cc1dbb03c11f725a44b44008851c73d6844"},
                {SSHKDFParameterSpec.KeyType.INTEGRITY_KEY_CLIENT_TO_SERVER,
                        "472eb8a26166ae6aa8e06868e45c3b26e6eeed06"},
                {SSHKDFParameterSpec.KeyType.INTEGRITY_KEY_SERVER_TO_CLIENT,
                        "e3e2fdb9d7bc21165a3dbe47e1eceb7764390bab"},
        };

        for (Object[] v : vectors)
        {
            SSHKDFParameterSpec.KeyType type = (SSHKDFParameterSpec.KeyType) v[0];
            byte[] expected = Hex.decode((String) v[1]);
            Assertions.assertArrayEquals(expected,
                    jostle("SSHKDF-SHA1", new SSHKDFParameterSpec(
                            CAVS_K, CAVS_H, CAVS_H, type, expected.length)),
                    "CAVS vector for type " + type.getCode());
        }
    }

    /** A second CAVS exchange, so a factory keyed to one K/H pair cannot pass. */
    @Test
    public void cavsVectorsSecondExchange() throws Exception
    {
        byte[] k = Hex.decode(
                "0000008100ec6f2c5f0517fd92f730567bd783138302917c277552b1b3fdf2b6"
                        + "7d6edb6fa81bd17f7ebbe339b54b171341e6522b91611f8274cc88652a458f80"
                        + "41261040818a268497e949e12f57271318b2b3194c29760cbb767c0fc8833b27"
                        + "2994e18682da807e6c9f235d88ef89c203c6f756d25cc2bea199b02c955b8b40"
                        + "cbc04f9208");
        byte[] h = Hex.decode("ee40eef61bea3da8c2b1cec40fc4cdac892a2626");
        byte[] sessionId = Hex.decode("ca9aad244e24797fd348d1250387c8aa45a0110a");

        Assertions.assertArrayEquals(Hex.decode("55a1015757de84cb"),
                jostle("SSHKDF-SHA1", new SSHKDFParameterSpec(k, h, sessionId,
                        SSHKDFParameterSpec.KeyType.INITIAL_IV_CLIENT_TO_SERVER, 8)));
        Assertions.assertArrayEquals(Hex.decode("7e57f61d5735f4fb"),
                jostle("SSHKDF-SHA1", new SSHKDFParameterSpec(k, h, sessionId,
                        SSHKDFParameterSpec.KeyType.INITIAL_IV_SERVER_TO_CLIENT, 8)));
        Assertions.assertArrayEquals(Hex.decode("dd1c24bde1af845e82207541e3e173aec822fb904a94ae3c"),
                jostle("SSHKDF-SHA1", new SSHKDFParameterSpec(k, h, sessionId,
                        SSHKDFParameterSpec.KeyType.ENCRYPTION_KEY_CLIENT_TO_SERVER, 24)));

        // The session id is distinct from H in this exchange, unlike the first
        // one — so this vector also proves the two are not being conflated.
        Assertions.assertFalse(Arrays.areEqual(Hex.decode("55a1015757de84cb"),
                        jostle("SSHKDF-SHA1", new SSHKDFParameterSpec(k, h, h,
                                SSHKDFParameterSpec.KeyType.INITIAL_IV_CLIENT_TO_SERVER, 8))),
                "the session id must be used, not H a second time");
    }

    // ----------------------------------------------------------- agreement

    /**
     * Random inputs against the RFC 4253 recurrence, at every registered digest
     * and every key type, with output lengths that straddle the digest size in
     * both directions (so the multi-block continuation path is exercised).
     */
    @Test
    public void agreesWithRfc4253Reference() throws Exception
    {
        SecureRandom sr = seededRandom("agreesWithRfc4253Reference");

        for (String alg : ALGS)
        {
            String digestName = jceDigestFor(alg);
            for (int trial = 0; trial < TRIALS; trial++)
            {
                byte[] k = random(32 + sr.nextInt(96), sr);
                byte[] h = random(20 + sr.nextInt(44), sr);
                byte[] sessionId = random(20 + sr.nextInt(44), sr);
                SSHKDFParameterSpec.KeyType type =
                        SSHKDFParameterSpec.KeyType.values()[
                                sr.nextInt(SSHKDFParameterSpec.KeyType.values().length)];
                int len = 1 + sr.nextInt(200);

                Assertions.assertArrayEquals(
                        rfc4253Reference(digestName, k, h, sessionId, type.getCode().charAt(0), len),
                        jostle(alg, new SSHKDFParameterSpec(k, h, sessionId, type, len)),
                        alg + " type=" + type.getCode() + " len=" + len);
            }
        }
    }

    /**
     * Output lengths exactly at, one below and one above the digest size — the
     * boundary where the RFC's continuation recurrence starts.
     */
    @Test
    public void agreesAcrossTheBlockBoundary() throws Exception
    {
        SecureRandom sr = seededRandom("agreesAcrossTheBlockBoundary");

        for (String alg : ALGS)
        {
            String digestName = jceDigestFor(alg);
            int h = MessageDigest.getInstance(digestName,
                    BouncyCastleProvider.PROVIDER_NAME).getDigestLength();
            byte[] k = random(64, sr);
            byte[] exch = random(32, sr);
            byte[] sessionId = random(32, sr);

            for (int len : new int[]{1, h - 1, h, h + 1, 2 * h, 2 * h + 1, 3 * h - 1})
            {
                Assertions.assertArrayEquals(
                        rfc4253Reference(digestName, k, exch, sessionId, 'C', len),
                        jostle(alg, new SSHKDFParameterSpec(k, exch, sessionId,
                                SSHKDFParameterSpec.KeyType.ENCRYPTION_KEY_CLIENT_TO_SERVER, len)),
                        alg + " len=" + len);
            }
        }
    }

    // ------------------------------------------------------- negative path

    @Test
    public void everyInputInfluencesTheDerivedKey() throws Exception
    {
        SecureRandom sr = seededRandom("everyInputInfluencesTheDerivedKey");
        byte[] k = random(64, sr);
        byte[] h = random(32, sr);
        byte[] sessionId = random(32, sr);

        byte[] base = jostle("SSHKDF-SHA256", new SSHKDFParameterSpec(k, h, sessionId,
                SSHKDFParameterSpec.KeyType.ENCRYPTION_KEY_CLIENT_TO_SERVER, 40));

        Assertions.assertFalse(Arrays.areEqual(base,
                        jostle("SSHKDF-SHA256", new SSHKDFParameterSpec(random(64, sr), h, sessionId,
                                SSHKDFParameterSpec.KeyType.ENCRYPTION_KEY_CLIENT_TO_SERVER, 40))),
                "the shared secret must influence the derived key");
        Assertions.assertFalse(Arrays.areEqual(base,
                        jostle("SSHKDF-SHA256", new SSHKDFParameterSpec(k, random(32, sr), sessionId,
                                SSHKDFParameterSpec.KeyType.ENCRYPTION_KEY_CLIENT_TO_SERVER, 40))),
                "the exchange hash must influence the derived key");
        Assertions.assertFalse(Arrays.areEqual(base,
                        jostle("SSHKDF-SHA256", new SSHKDFParameterSpec(k, h, random(32, sr),
                                SSHKDFParameterSpec.KeyType.ENCRYPTION_KEY_CLIENT_TO_SERVER, 40))),
                "the session id must influence the derived key");
        Assertions.assertFalse(Arrays.areEqual(base,
                        jostle("SSHKDF-SHA384", new SSHKDFParameterSpec(k, h, sessionId,
                                SSHKDFParameterSpec.KeyType.ENCRYPTION_KEY_CLIENT_TO_SERVER, 40))),
                "the digest must influence the derived key");
    }

    /**
     * All six key types from one exchange must be pairwise distinct. A factory
     * that dropped the type letter would hand the same bytes out as the IV, the
     * encryption key AND the integrity key — catastrophic, and completely
     * invisible to a round trip.
     */
    @Test
    public void theSixKeyTypesArePairwiseDistinct() throws Exception
    {
        SecureRandom sr = seededRandom("theSixKeyTypesArePairwiseDistinct");
        byte[] k = random(64, sr);
        byte[] h = random(32, sr);
        byte[] sessionId = random(32, sr);

        SSHKDFParameterSpec.KeyType[] types = SSHKDFParameterSpec.KeyType.values();
        byte[][] derived = new byte[types.length][];
        for (int i = 0; i < types.length; i++)
        {
            derived[i] = jostle("SSHKDF-SHA256",
                    new SSHKDFParameterSpec(k, h, sessionId, types[i], 32));
        }

        for (int i = 0; i < types.length; i++)
        {
            for (int j = i + 1; j < types.length; j++)
            {
                Assertions.assertFalse(Arrays.areEqual(derived[i], derived[j]),
                        "types " + types[i].getCode() + " and " + types[j].getCode()
                                + " produced the same key");
            }
        }
    }

    @Test
    public void derivationIsDeterministic() throws Exception
    {
        SecureRandom sr = seededRandom("derivationIsDeterministic");
        SSHKDFParameterSpec spec = new SSHKDFParameterSpec(random(64, sr), random(32, sr),
                random(32, sr), SSHKDFParameterSpec.KeyType.INTEGRITY_KEY_SERVER_TO_CLIENT, 48);

        Assertions.assertArrayEquals(jostle("SSHKDF-SHA256", spec), jostle("SSHKDF-SHA256", spec));
    }

    // -------------------------------------------------------- spec contract

    @Test
    public void specRejectsInvalidArguments()
    {
        byte[] k = new byte[32];
        byte[] h = new byte[20];
        SSHKDFParameterSpec.KeyType type = SSHKDFParameterSpec.KeyType.INITIAL_IV_CLIENT_TO_SERVER;

        Assertions.assertEquals("shared secret is null", Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> new SSHKDFParameterSpec(null, h, h, type, 16)).getMessage());

        Assertions.assertEquals("exchange hash is null", Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> new SSHKDFParameterSpec(k, null, h, type, 16)).getMessage());

        Assertions.assertEquals("session id is null", Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> new SSHKDFParameterSpec(k, h, null, type, 16)).getMessage());

        Assertions.assertEquals("type is null", Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> new SSHKDFParameterSpec(k, h, h, null, 16)).getMessage());

        // SSHKDF is the KDF that ACCEPTS a zero-length request in OpenSSL and
        // emits a zero-length key, so this rejection is load-bearing, not a
        // belt-and-braces duplicate of a provider check.
        for (int badLen : new int[]{0, -1, Integer.MIN_VALUE})
        {
            Assertions.assertEquals("output length must be positive", Assertions.assertThrows(
                    IllegalArgumentException.class,
                    () -> new SSHKDFParameterSpec(k, h, h, type, badLen)).getMessage());
        }

        Assertions.assertEquals(1, new SSHKDFParameterSpec(k, h, h, type, 1).getOutputLength());
    }

    @Test
    public void specAccessorsReturnCopies()
    {
        byte[] k = new byte[]{1, 2, 3, 4};
        byte[] h = new byte[]{5, 6};
        byte[] sessionId = new byte[]{7, 8};
        SSHKDFParameterSpec spec = new SSHKDFParameterSpec(k, h, sessionId,
                SSHKDFParameterSpec.KeyType.INITIAL_IV_CLIENT_TO_SERVER, 16);

        spec.getSharedSecret()[0] = (byte) 0xff;
        spec.getExchangeHash()[0] = (byte) 0xff;
        spec.getSessionId()[0] = (byte) 0xff;
        Assertions.assertEquals(1, spec.getSharedSecret()[0]);
        Assertions.assertEquals(5, spec.getExchangeHash()[0]);
        Assertions.assertEquals(7, spec.getSessionId()[0]);

        k[0] = (byte) 0xff;
        Assertions.assertEquals(1, spec.getSharedSecret()[0]);
    }

    /** The RFC 4253 letter codes are part of the wire contract, so pin them. */
    @Test
    public void keyTypeCodesMatchRfc4253()
    {
        Assertions.assertEquals("A",
                SSHKDFParameterSpec.KeyType.INITIAL_IV_CLIENT_TO_SERVER.getCode());
        Assertions.assertEquals("B",
                SSHKDFParameterSpec.KeyType.INITIAL_IV_SERVER_TO_CLIENT.getCode());
        Assertions.assertEquals("C",
                SSHKDFParameterSpec.KeyType.ENCRYPTION_KEY_CLIENT_TO_SERVER.getCode());
        Assertions.assertEquals("D",
                SSHKDFParameterSpec.KeyType.ENCRYPTION_KEY_SERVER_TO_CLIENT.getCode());
        Assertions.assertEquals("E",
                SSHKDFParameterSpec.KeyType.INTEGRITY_KEY_CLIENT_TO_SERVER.getCode());
        Assertions.assertEquals("F",
                SSHKDFParameterSpec.KeyType.INTEGRITY_KEY_SERVER_TO_CLIENT.getCode());
        Assertions.assertEquals(6, SSHKDFParameterSpec.KeyType.values().length);
    }

    @Test
    public void factoryRejectsWrongKeySpec() throws Exception
    {
        SecretKeyFactory f = SecretKeyFactory.getInstance("SSHKDF-SHA256",
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
            byte[] out = jostle(alg, new SSHKDFParameterSpec(random(64, sr), random(20, sr),
                    random(20, sr), SSHKDFParameterSpec.KeyType.INITIAL_IV_CLIENT_TO_SERVER, 32));
            Assertions.assertEquals(32, out.length, alg);
            Assertions.assertFalse(Arrays.areEqual(new byte[32], out), alg + " produced zeros");
        }
    }
}
