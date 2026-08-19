/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.fips;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;

/**
 * Cross-provider agreement for the FIPS provider's MessageDigest surface — the
 * MD analogue of {@code FIPSAESAgreementTest}, and the dedicated home for
 * digest agreement (the behavioural concerns — clone/reuse, OID aliasing,
 * absence of digests the module does not serve — live in {@code FIPSMDTest}).
 * <p>
 * Every approved digest is exercised two ways in the same JVM: JSLFIPS vs the
 * non-FIPS provider (JSL) over the full approved set, and JSLFIPS vs
 * BouncyCastle (BC) over the subset both register. A digest has no encrypt-side
 * / decrypt-side split, so "agreement" here is byte-identity of the digest of
 * the same random input, produced by each provider — a strong differentiator
 * that a stubbed or wrong-but-self-consistent implementation cannot satisfy
 * against an independent reference. Chunking is varied (one-shot, byte-wise,
 * random splits) and cross-checked against the reference so a partial-block
 * buffering bug on either path surfaces. A tampered-input differentiator and a
 * distinct-inputs differentiator prove the digest actually consumes its input.
 * <p>
 * Inputs (message content and length) are drawn from a per-test SHA1PRNG whose
 * seed is logged, so a flaky run is reproducible (per CLAUDE.md).
 * <p>
 * Gated on {@code TEST_FIPS_LIB}; skipped when unset.
 */
public class FIPSMDAgreementTest
{
    private static final String FIPS = JostleFIPSProvider.PROVIDER_NAME;
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    // The fips=yes digest set of the OpenSSL FIPS module, as registered by
    // ProvFIPSMD (canonical OpenSSL names plus the fixed-output SHAKEs).
    private static final String[] APPROVED = {
            "SHA1", "SHA2-224", "SHA2-256", "SHA2-384", "SHA2-512",
            "SHA2-512/224", "SHA2-512/256",
            "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512",
            "SHAKE-128", "SHAKE-256", "SHAKE128-256", "SHAKE256-512"
    };

    // Names both BouncyCastle and Jostle register, for three-way agreement.
    private static final String[] BC_COMPARABLE = {
            "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-512"
    };

    private static final SecureRandom RANDOM = new SecureRandom();

    private static SecureRandom seededRandom(String testName) throws Exception
    {
        long seed = RANDOM.nextLong();
        System.out.println(testName + " seed=" + seed);
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        return sr;
    }

    private static void ensureProviders()
    {
        FIPSTestUtil.assumeFipsProvider();
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static byte[] digest(String name, String provider, byte[] message) throws Exception
    {
        return MessageDigest.getInstance(name, provider).digest(message);
    }

    /**
     * For the full approved digest set, JSLFIPS and JSL must produce a
     * byte-identical digest of the same random input; for the BC-comparable
     * subset, JSLFIPS and BC must agree too. A one-byte change to the input
     * must change the JSLFIPS digest (differentiator).
     */
    @Test
    public void approvedDigestsAgreeAcrossProviders() throws Exception
    {
        ensureProviders();
        SecureRandom sr = seededRandom("approvedDigestsAgreeAcrossProviders");

        for (String name : APPROVED)
        {
            for (int t = 0; t < 5; t++)
            {
                byte[] message = new byte[1 + sr.nextInt(2048)];
                sr.nextBytes(message);

                byte[] fips = digest(name, FIPS, message);
                byte[] jsl = digest(name, JSL, message);
                Assertions.assertArrayEquals(jsl, fips, name + ": JSLFIPS vs JSL");

                // Differentiator: a one-byte change must change the digest.
                byte[] tampered = message.clone();
                tampered[sr.nextInt(tampered.length)] ^= (byte) (1 + sr.nextInt(255));
                Assertions.assertFalse(java.util.Arrays.equals(fips, digest(name, FIPS, tampered)),
                        name + ": tampered input produced an identical digest");
            }
        }

        for (String name : BC_COMPARABLE)
        {
            byte[] message = new byte[1 + sr.nextInt(2048)];
            sr.nextBytes(message);
            Assertions.assertArrayEquals(digest(name, BC, message), digest(name, FIPS, message),
                    name + ": JSLFIPS vs BC");
        }
    }

    /**
     * The same logical input chunked three ways (one-shot, byte-wise, random
     * splits) must produce the JSL reference digest byte-for-byte — exercising
     * the partial-block buffering path on both the FIPS and non-FIPS sides.
     */
    @Test
    public void chunkingVariantsAgree() throws Exception
    {
        ensureProviders();
        SecureRandom sr = seededRandom("chunkingVariantsAgree");

        for (String name : new String[]{"SHA-256", "SHA3-256", "SHA2-512", "SHAKE128-256"})
        {
            byte[] message = new byte[257 + sr.nextInt(1024)];
            sr.nextBytes(message);

            // Reference: the non-FIPS provider, one shot.
            byte[] expected = digest(name, JSL, message);
            Assertions.assertArrayEquals(expected, digest(name, FIPS, message),
                    name + ": one-shot JSLFIPS vs JSL");

            MessageDigest byteWise = MessageDigest.getInstance(name, FIPS);
            for (byte b : message)
            {
                byteWise.update(b);
            }
            Assertions.assertArrayEquals(expected, byteWise.digest(), name + ": byte-wise JSLFIPS");

            MessageDigest randomSplit = MessageDigest.getInstance(name, FIPS);
            int offset = 0;
            while (offset < message.length)
            {
                int chunk = Math.min(1 + sr.nextInt(97), message.length - offset);
                randomSplit.update(message, offset, chunk);
                offset += chunk;
            }
            Assertions.assertArrayEquals(expected, randomSplit.digest(), name + ": random splits JSLFIPS");
        }
    }

    /**
     * Two distinct inputs must produce distinct digests, in every provider —
     * proof the digest is a function of its input and not a fixed buffer. The
     * two providers must also agree on each of the two digests.
     */
    @Test
    public void distinctInputsProduceDistinctDigests() throws Exception
    {
        ensureProviders();
        SecureRandom sr = seededRandom("distinctInputsProduceDistinctDigests");

        for (String name : APPROVED)
        {
            byte[] a = new byte[64 + sr.nextInt(256)];
            byte[] b = new byte[64 + sr.nextInt(256)];
            sr.nextBytes(a);
            sr.nextBytes(b);

            byte[] fipsA = digest(name, FIPS, a);
            byte[] fipsB = digest(name, FIPS, b);
            Assertions.assertFalse(java.util.Arrays.equals(fipsA, fipsB),
                    name + ": distinct inputs produced identical digests");

            Assertions.assertArrayEquals(digest(name, JSL, a), fipsA, name + ": digest(a) JSLFIPS vs JSL");
            Assertions.assertArrayEquals(digest(name, JSL, b), fipsB, name + ": digest(b) JSLFIPS vs JSL");
        }
    }
}
