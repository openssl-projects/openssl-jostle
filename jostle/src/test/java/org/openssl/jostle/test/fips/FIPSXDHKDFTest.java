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
 * non-FIPS provider, and unapproved variants are rejected. Gated on
 * JOSTLE_TEST_FIPS_DIR; skipped when unset.
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

    @Test
    public void xdhSharedSecretsMatchBouncyCastle()
        throws Exception
    {
        ensureProviders();

        for (String curve : new String[]{"X25519", "X448"})
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(curve, JostleFIPSProvider.PROVIDER_NAME);
            KeyPair alice = kpg.generateKeyPair();
            KeyPair bob = kpg.generateKeyPair();

            KeyAgreement fipsKa = KeyAgreement.getInstance(curve, JostleFIPSProvider.PROVIDER_NAME);
            fipsKa.init(alice.getPrivate());
            fipsKa.doPhase(bob.getPublic(), true);
            byte[] fipsSecret = fipsKa.generateSecret();

            // BC's XDH agreement requires BC/JDK key types: hop through
            // encodings via BC's KeyFactory.
            KeyFactory bcKf = KeyFactory.getInstance(curve, BouncyCastleProvider.PROVIDER_NAME);
            java.security.PrivateKey bcBobPriv = bcKf.generatePrivate(
                    new java.security.spec.PKCS8EncodedKeySpec(bob.getPrivate().getEncoded()));
            PublicKey bcAlicePub = bcKf.generatePublic(new X509EncodedKeySpec(alice.getPublic().getEncoded()));

            KeyAgreement bcKa = KeyAgreement.getInstance(curve, BouncyCastleProvider.PROVIDER_NAME);
            bcKa.init(bcBobPriv);
            bcKa.doPhase(bcAlicePub, true);
            Assertions.assertArrayEquals(fipsSecret, bcKa.generateSecret(),
                    curve + ": JSLFIPS(alice) and BC(bob) must derive the same secret");

            // Encoding round-trip: JSLFIPS KeyFactory decodes BC-visible bytes.
            KeyFactory fipsKf = KeyFactory.getInstance(curve, JostleFIPSProvider.PROVIDER_NAME);
            PublicKey decoded = fipsKf.generatePublic(new X509EncodedKeySpec(bob.getPublic().getEncoded()));
            fipsKa.init(alice.getPrivate());
            fipsKa.doPhase(decoded, true);
            Assertions.assertArrayEquals(fipsSecret, fipsKa.generateSecret(),
                    curve + ": decoded peer key must derive the same secret");
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
    public void unapprovedKdfsRejected()
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
}
