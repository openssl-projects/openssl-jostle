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

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * XDH (X25519/X448) and the KDFs (PBKDF2, HKDF) through the FIPS provider
 * ("JSLFIPS"): agreement secrets and derived keys match BouncyCastle / the
 * non-FIPS provider, and variants the module does not serve are absent. Gated on
 * TEST_FIPS_LIB; skipped when unset.
 */
public class FIPSXDHKDFTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    private static void ensureProviders()
    {
        FIPSTestUtil.assumeFipsProvider();
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * XDH is SERVED by JSLFIPS, and its secrets match the non-FIPS provider.
     *
     * <p>The module implements X25519/X448 — keygen and agreement both succeed
     * under the FIPS lib ctx — so JSLFIPS exposes them. Cert #4985 lists XDH key
     * agreement as a non-approved service (Table 8, §4.4 Table 13); that is a
     * compliance determination for the operator, not a capability this provider
     * withholds. This test previously asserted the opposite, from the period when
     * the surface was filtered against the policy.
     *
     * <p>Byte-equality against JSL over the SAME key material is the check that
     * matters: it proves the FIPS path computes the real shared secret rather
     * than something merely self-consistent.
     */
    @Test
    public void xdhServedByJslfipsAndAgreesWithJsl()
        throws Exception
    {
        ensureProviders();

        for (String alg : new String[]{"X25519", "X448"})
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(alg, JostleFIPSProvider.PROVIDER_NAME);
            KeyPair alice = kpg.generateKeyPair();
            KeyPair bob = kpg.generateKeyPair();

            KeyAgreement fips = KeyAgreement.getInstance(alg, JostleFIPSProvider.PROVIDER_NAME);
            fips.init(alice.getPrivate());
            fips.doPhase(bob.getPublic(), true);
            byte[] fipsSecret = fips.generateSecret();
            Assertions.assertEquals("X25519".equals(alg) ? 32 : 56, fipsSecret.length);

            // Same key material through JSL: secrets must be identical.
            KeyFactory jslKf = KeyFactory.getInstance(alg, JostleProvider.PROVIDER_NAME);
            KeyAgreement jsl = KeyAgreement.getInstance(alg, JostleProvider.PROVIDER_NAME);
            jsl.init(jslKf.generatePrivate(
                    new java.security.spec.PKCS8EncodedKeySpec(alice.getPrivate().getEncoded())));
            jsl.doPhase(jslKf.generatePublic(
                    new X509EncodedKeySpec(bob.getPublic().getEncoded())), true);
            Assertions.assertArrayEquals(jsl.generateSecret(), fipsSecret,
                    alg + ": JSLFIPS and JSL shared secrets differ");

            // Differentiator: a third party's key must give a different secret.
            KeyPair carol = kpg.generateKeyPair();
            KeyAgreement other = KeyAgreement.getInstance(alg, JostleFIPSProvider.PROVIDER_NAME);
            other.init(alice.getPrivate());
            other.doPhase(carol.getPublic(), true);
            Assertions.assertFalse(Arrays.equals(fipsSecret, other.generateSecret()),
                    alg + ": a different peer key produced the same secret");
        }
    }

    @Test
    public void pbkdf2AgreesAcrossProviders()
        throws Exception
    {
        ensureProviders();

        char[] password = "correct horse battery staple".toCharArray();
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        PBEKeySpec spec = new PBEKeySpec(password, salt, 2048, 256);

        byte[] fips = SecretKeyFactory.getInstance("PBKDF2WITHHMACSHA256", JostleFIPSProvider.PROVIDER_NAME)
                .generateSecret(spec).getEncoded();
        byte[] jsl = SecretKeyFactory.getInstance("PBKDF2WITHHMACSHA256", JostleProvider.PROVIDER_NAME)
                .generateSecret(spec).getEncoded();
        byte[] bc = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256", BouncyCastleProvider.PROVIDER_NAME)
                .generateSecret(spec).getEncoded();
        Assertions.assertArrayEquals(jsl, fips, "JSLFIPS vs JSL");
        Assertions.assertArrayEquals(bc, fips, "JSLFIPS vs BC");

        // Differentiator: a different salt must change the key.
        byte[] salt2 = salt.clone();
        salt2[0] ^= 0x01;
        byte[] fips2 = SecretKeyFactory.getInstance("PBKDF2WITHHMACSHA256", JostleFIPSProvider.PROVIDER_NAME)
                .generateSecret(new PBEKeySpec(password, salt2, 2048, 256)).getEncoded();
        Assertions.assertFalse(Arrays.equals(fips, fips2), "different salt produced identical key");
    }

    @Test
    public void hkdfAgreesWithNonFipsProvider()
        throws Exception
    {
        ensureProviders();

        // HKDF key material enters through the JSL/JSLFIPS-specific KeySpec;
        // agreement is checked against the non-FIPS provider (BC's HKDF SKF
        // uses a different spec type).
        byte[] ikm = new byte[32];
        byte[] salt = new byte[16];
        byte[] info = new byte[12];
        RANDOM.nextBytes(ikm);
        RANDOM.nextBytes(salt);
        RANDOM.nextBytes(info);

        org.openssl.jostle.jcajce.spec.HKDFParameterSpec spec =
                new org.openssl.jostle.jcajce.spec.HKDFParameterSpec(ikm, salt, info, 64);

        byte[] fips = SecretKeyFactory.getInstance("HKDF-SHA256", JostleFIPSProvider.PROVIDER_NAME)
                .generateSecret(spec).getEncoded();
        byte[] jsl = SecretKeyFactory.getInstance("HKDF-SHA256", JostleProvider.PROVIDER_NAME)
                .generateSecret(spec).getEncoded();
        Assertions.assertArrayEquals(jsl, fips, "JSLFIPS vs JSL HKDF");
        Assertions.assertEquals(64, fips.length);

        // Differentiator: different info must change the output.
        byte[] info2 = info.clone();
        info2[0] ^= 0x01;
        byte[] fips2 = SecretKeyFactory.getInstance("HKDF-SHA256", JostleFIPSProvider.PROVIDER_NAME)
                .generateSecret(new org.openssl.jostle.jcajce.spec.HKDFParameterSpec(ikm, salt, info2, 64))
                .getEncoded();
        Assertions.assertFalse(Arrays.equals(fips, fips2), "different info produced identical key");
    }

    @Test
    public void kdfsNotServedByModuleRejected()
        throws Exception
    {
        ensureProviders();

        for (String name : new String[]{"SCRYPT", "PBKDF2WITHHMACMD5", "PBKDF2WITHHMACSM3", "PBKDF2WITHHMACRIPEMD160"})
        {
            Assertions.assertThrows(NoSuchAlgorithmException.class,
                    () -> SecretKeyFactory.getInstance(name, JostleFIPSProvider.PROVIDER_NAME),
                    name + " must not resolve through JSLFIPS");
        }

        // ... while the non-FIPS provider still serves scrypt in the same JVM.
        Assertions.assertNotNull(SecretKeyFactory.getInstance("SCRYPT", JostleProvider.PROVIDER_NAME));
    }

    @Test
    public void kdfsNotServedByModule_md5sha1AndBlake2()
        throws Exception
    {
        ensureProviders();

        // MD5-SHA1 and both BLAKE2 PBKDF2 PRFs: JSL registers them, JSLFIPS does
        // not, because the FIPS module does not implement those digests at all
        // (probe-confirmed: MD5, MD5-SHA1, BLAKE2S-256 and BLAKE2B-512 all fail
        // to fetch under the FIPS lib ctx). The PRF is unavailable, so the
        // PBKDF2 variant over it cannot work. Completes the served-surface lock
        // alongside kdfsNotServedByModuleRejected.
        for (String name : new String[]{"PBKDF2WITHHMACMD5-SHA1", "PBKDF2WITHHMACBLAKE2B-512", "PBKDF2WITHHMACBLAKE2S-256"})
        {
            Assertions.assertThrows(NoSuchAlgorithmException.class,
                    () -> SecretKeyFactory.getInstance(name, JostleFIPSProvider.PROVIDER_NAME),
                    name + " must not resolve through JSLFIPS");

            // ... while the non-FIPS provider still serves it in the same JVM.
            Assertions.assertNotNull(SecretKeyFactory.getInstance(name, JostleProvider.PROVIDER_NAME),
                    name + " must still resolve through JSL");
        }
    }
}
