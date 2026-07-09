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

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.jcajce.spec.HKDFParameterSpec;
import org.openssl.jostle.util.Arrays;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.SecureRandom;
import java.security.Security;

/**
 * Cross-provider agreement for the FIPS provider's KDF surface (PBKDF2 and
 * HKDF).
 * <p>
 * The FIPS analogue of {@code kdf/PBKdf2Test} + {@code kdf/HkdfTest}, and the
 * KDF sibling of {@link FIPSAESAgreementTest} — same {@code FIPS}/{@code JSL}/
 * {@code BC} mold, same seeded-random discipline. KDF output is deterministic
 * given its inputs, so for every approved KDF and several random parameter sets
 * the derived key is compared three ways in the same JVM:
 * <ol>
 *   <li>JSLFIPS vs the non-FIPS provider (JSL), and</li>
 *   <li>JSLFIPS vs BouncyCastle (BC).</li>
 * </ol>
 * Byte-identical derived keys across three independent implementations is a
 * strong differentiator that a stubbed or wrong-but-self-consistent KDF cannot
 * satisfy. Where the pinned BouncyCastle release does not register a name
 * through its JCE {@code SecretKeyFactory} (the SHA-512/224 and SHA-512/256
 * truncated PBKDF2 PRFs), the comparison falls back to JSLFIPS vs JSL only. For
 * HKDF, BC's JCE {@code SecretKeyFactory} uses a different spec type, so the BC
 * reference is BouncyCastle's low-level {@code HKDFBytesGenerator} (exactly as
 * {@code kdf/HkdfTest} does).
 * <p>
 * FIPS constraint (SP 800-132, enforced inside the module): PBKDF2 needs a salt
 * of at least 16 bytes, an iteration count of at least 1000, and a password of
 * at least 14 bytes, or the derivation is refused. HKDF has no such lower
 * bound. Every other input (password/IKM content and length, salt, info, and
 * output length) is drawn from a per-test SHA1PRNG whose seed is logged so a
 * flaky run is reproducible (per CLAUDE.md).
 * <p>
 * Gated on {@code TEST_FIPS_LIB}; skipped when unset.
 */
public class FIPSKDFAgreementTest
{
    private static final String FIPS = JostleFIPSProvider.PROVIDER_NAME;
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    /**
     * PBKDF2 PRFs registered by JSLFIPS ({@code ProvFIPSKDF}), by the non-FIPS
     * provider ({@code ProvPBKDF}), AND served by BouncyCastle's JCE
     * {@code SecretKeyFactory} (the set proven cross-compatible in
     * {@code kdf/PBKdf2Test.testBCAgreement}). Compared three ways. The bare
     * "PBKDF2" defaults to HMAC-SHA1 in all three.
     */
    private static final String[] PBKDF2_THREE_WAY = {
            "PBKDF2",
            "PBKDF2WITHHMACSHA1",
            "PBKDF2WITHHMACSHA224",
            "PBKDF2WITHHMACSHA256",
            "PBKDF2WITHHMACSHA384",
            "PBKDF2WITHHMACSHA512",
            "PBKDF2WITHHMACSHA3-224",
            "PBKDF2WITHHMACSHA3-256",
            "PBKDF2WITHHMACSHA3-384",
            "PBKDF2WITHHMACSHA3-512",
    };

    /**
     * PBKDF2 PRFs registered by JSLFIPS and JSL but NOT served through the
     * pinned BouncyCastle release's JCE {@code SecretKeyFactory} (SHA-512/224,
     * SHA-512/256 — see the commented-out entries in
     * {@code kdf/PBKdf2Test.testBCAgreement}). Compared JSLFIPS vs JSL only.
     */
    private static final String[] PBKDF2_TWO_WAY = {
            "PBKDF2WITHHMACSHA512-224",
            "PBKDF2WITHHMACSHA512-256",
    };

    /** HKDF variants registered by JSLFIPS and JSL. */
    private static final String[] HKDF_ALGS = {"HKDF-SHA256", "HKDF-SHA384", "HKDF-SHA512"};

    // FIPS PBKDF2 lower bounds (SP 800-132), enforced by the module.
    private static final int MIN_SALT_BYTES = 16;
    private static final int MIN_ITERATIONS = 1000;
    private static final int MIN_PASSWORD_BYTES = 14;

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

    private static byte[] randomBytes(int length, SecureRandom sr)
    {
        byte[] bytes = new byte[length];
        sr.nextBytes(bytes);
        return bytes;
    }

    /**
     * A random password of at least {@link #MIN_PASSWORD_BYTES} characters,
     * drawn from printable ASCII (33..126). Each character is a single UTF-8
     * byte, so the character count equals the byte count the module sees — this
     * both satisfies the FIPS lower bound unambiguously and keeps the
     * char[]-to-byte[] conversion identical across JSLFIPS, JSL, and BC.
     */
    private static char[] randomPassword(SecureRandom sr)
    {
        int len = MIN_PASSWORD_BYTES + sr.nextInt(16);
        char[] pw = new char[len];
        for (int i = 0; i < len; i++)
        {
            pw[i] = (char) ('!' + sr.nextInt(94));
        }
        return pw;
    }

    private static byte[] pbkdf2(String provider, String alg, PBEKeySpec spec) throws Exception
    {
        return SecretKeyFactory.getInstance(alg, provider).generateSecret(spec).getEncoded();
    }

    private static byte[] hkdfJce(String provider, String alg, byte[] ikm, byte[] salt, byte[] info, int len)
            throws Exception
    {
        return SecretKeyFactory.getInstance(alg, provider)
                .generateSecret(new HKDFParameterSpec(ikm, salt, info, len)).getEncoded();
    }

    /** BouncyCastle low-level HKDF reference (RFC 5869). */
    private static byte[] hkdfBc(Digest digest, byte[] ikm, byte[] salt, byte[] info, int len)
    {
        HKDFBytesGenerator gen = new HKDFBytesGenerator(digest);
        gen.init(new HKDFParameters(ikm, salt, info));
        byte[] out = new byte[len];
        gen.generateBytes(out, 0, len);
        return out;
    }

    private static Digest bcDigestFor(String alg)
    {
        if ("HKDF-SHA256".equals(alg))
        {
            return new SHA256Digest();
        }
        if ("HKDF-SHA384".equals(alg))
        {
            return new SHA384Digest();
        }
        if ("HKDF-SHA512".equals(alg))
        {
            return new SHA512Digest();
        }
        throw new IllegalArgumentException("no BC digest for " + alg);
    }

    /**
     * PBKDF2 over every PRF that JSLFIPS, JSL, and BouncyCastle all serve:
     * derived key must be byte-identical across the three implementations.
     * Differentiator: a changed salt must change the derived key.
     */
    @Test
    public void pbkdf2AgreesThreeWay() throws Exception
    {
        ensureProviders();
        SecureRandom sr = seededRandom("pbkdf2AgreesThreeWay");

        for (String alg : PBKDF2_THREE_WAY)
        {
            for (int trial = 0; trial < 6; trial++)
            {
                char[] password = randomPassword(sr);
                byte[] salt = randomBytes(MIN_SALT_BYTES + sr.nextInt(16), sr);
                int iterations = MIN_ITERATIONS + sr.nextInt(1024);
                int keyBits = (16 + sr.nextInt(48)) * 8; // 128..504 bits, byte-aligned

                PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyBits);
                String tag = alg + " trial=" + trial;

                byte[] fips = pbkdf2(FIPS, alg, spec);
                byte[] jsl = pbkdf2(JSL, alg, spec);
                byte[] bc = pbkdf2(BC, alg, spec);

                Assertions.assertArrayEquals(jsl, fips, tag + ": JSLFIPS vs JSL");
                Assertions.assertArrayEquals(bc, fips, tag + ": JSLFIPS vs BC");
                Assertions.assertEquals(keyBits >> 3, fips.length, tag + ": key length");

                // Differentiator: a changed salt must change the derived key.
                byte[] salt2 = Arrays.clone(salt);
                salt2[0] ^= 0x01;
                byte[] fipsAlt = pbkdf2(FIPS, alg, new PBEKeySpec(password, salt2, iterations, keyBits));
                Assertions.assertFalse(Arrays.areEqual(fips, fipsAlt),
                        tag + ": changed salt produced identical key");
            }
        }
    }

    /**
     * The truncated SHA-512 PBKDF2 PRFs are registered by JSLFIPS and JSL but
     * not by the pinned BouncyCastle release's JCE SecretKeyFactory, so the
     * comparison is JSLFIPS vs JSL. Differentiator: a changed password must
     * change the derived key.
     */
    @Test
    public void pbkdf2TruncatedVariantsAgreeWithJsl() throws Exception
    {
        ensureProviders();
        SecureRandom sr = seededRandom("pbkdf2TruncatedVariantsAgreeWithJsl");

        for (String alg : PBKDF2_TWO_WAY)
        {
            for (int trial = 0; trial < 6; trial++)
            {
                char[] password = randomPassword(sr);
                byte[] salt = randomBytes(MIN_SALT_BYTES + sr.nextInt(16), sr);
                int iterations = MIN_ITERATIONS + sr.nextInt(1024);
                int keyBits = (16 + sr.nextInt(48)) * 8; // 128..504 bits, byte-aligned

                PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyBits);
                String tag = alg + " trial=" + trial;

                byte[] fips = pbkdf2(FIPS, alg, spec);
                byte[] jsl = pbkdf2(JSL, alg, spec);

                Assertions.assertArrayEquals(jsl, fips, tag + ": JSLFIPS vs JSL");
                Assertions.assertEquals(keyBits >> 3, fips.length, tag + ": key length");

                // Differentiator: a changed password must change the derived key.
                char[] password2 = Arrays.clone(password);
                password2[0] ^= 0x01;
                byte[] fipsAlt = pbkdf2(FIPS, alg, new PBEKeySpec(password2, salt, iterations, keyBits));
                Assertions.assertFalse(Arrays.areEqual(fips, fipsAlt),
                        tag + ": changed password produced identical key");
            }
        }
    }

    /**
     * HKDF over every registered digest: JSLFIPS (JCE spec) vs JSL (JCE spec)
     * and vs BouncyCastle's low-level HKDFBytesGenerator. Derived key must be
     * byte-identical across all three. Differentiator: a changed IKM must
     * change the derived key.
     */
    @Test
    public void hkdfAgreesThreeWay() throws Exception
    {
        ensureProviders();
        SecureRandom sr = seededRandom("hkdfAgreesThreeWay");

        for (String alg : HKDF_ALGS)
        {
            for (int trial = 0; trial < 10; trial++)
            {
                byte[] ikm = randomBytes(1 + sr.nextInt(64), sr);
                byte[] salt = randomBytes(sr.nextInt(48), sr);
                byte[] info = randomBytes(sr.nextInt(48), sr);
                int len = 1 + sr.nextInt(96);

                String tag = alg + " trial=" + trial;

                byte[] fips = hkdfJce(FIPS, alg, ikm, salt, info, len);
                byte[] jsl = hkdfJce(JSL, alg, ikm, salt, info, len);
                byte[] bc = hkdfBc(bcDigestFor(alg), ikm, salt, info, len);

                Assertions.assertArrayEquals(jsl, fips, tag + ": JSLFIPS vs JSL");
                Assertions.assertArrayEquals(bc, fips, tag + ": JSLFIPS vs BC");
                Assertions.assertEquals(len, fips.length, tag + ": output length");

                // Differentiator: a changed IKM must change the derived key.
                byte[] ikm2 = Arrays.clone(ikm);
                ikm2[0] ^= 0x01;
                byte[] fipsAlt = hkdfJce(FIPS, alg, ikm2, salt, info, len);
                Assertions.assertFalse(Arrays.areEqual(fips, fipsAlt),
                        tag + ": changed IKM produced identical key");
            }
        }
    }
}
