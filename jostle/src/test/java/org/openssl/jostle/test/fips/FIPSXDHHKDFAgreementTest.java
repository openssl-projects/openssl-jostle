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

package org.openssl.jostle.test.fips;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.jcajce.spec.UserKeyingMaterialSpec;
import org.openssl.jostle.util.Arrays;

import javax.crypto.KeyAgreement;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * RFC 8418 HKDF key agreement under JSLFIPS — against JSL and against
 * BouncyCastle. The base twin is {@code XDHHKDFAgreementTest}; neither
 * substitutes for the other, since this one drives the FIPS interface library
 * and the module's own {@code OSSL_LIB_CTX}.
 *
 * <p><b>Module-dependent by design.</b> The two supported modules disagree
 * about XDH itself — 3.1.2 serves it, 3.5.8 does not — so
 * {@code ProvFIPSXDH} registers the whole family behind one fetch gate and
 * these schemes follow it. The gate is asserted rather than assumed: the cells
 * skip only when JSLFIPS genuinely does not register X25519, and
 * {@link #theSchemesTrackTheXdhGateExactly} pins that the three HKDF names are
 * present exactly when XDH is, so a partial registration fails rather than
 * quietly reducing coverage.
 */
public class FIPSXDHHKDFAgreementTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final String[][] SCHEMES = {
            {"XDHwithSHA256HKDF", "1.2.840.113549.1.9.16.3.19"},
            {"XDHwithSHA384HKDF", "1.2.840.113549.1.9.16.3.20"},
            {"XDHwithSHA512HKDF", "1.2.840.113549.1.9.16.3.21"},
    };

    private static final String[] CURVES = {"X25519", "X448"};
    private static final String AES256_WRAP = "2.16.840.1.101.3.4.1.45";

    @BeforeAll
    static void before()
    {
        FIPSTestUtil.assumeFipsProvider();
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * All-or-nothing with the XDH gate. A module serving XDH must serve all
     * three schemes; one that does not must serve none. Checking a single name
     * would miss a partial registration, which is the defect worth catching.
     */
    @Test
    public void theSchemesTrackTheXdhGateExactly()
    {
        boolean xdh = resolves("KeyPairGenerator", "X25519");
        for (String[] scheme : SCHEMES)
        {
            Assertions.assertEquals(xdh, resolves("KeyAgreement", scheme[0]),
                    scheme[0] + " must be registered exactly when the module serves XDH");
            Assertions.assertEquals(xdh, resolves("KeyAgreement", scheme[1]),
                    scheme[1] + " must be registered exactly when the module serves XDH");
        }
    }

    /**
     * JSLFIPS against JSL and against BouncyCastle, every scheme, both curves,
     * all four salt shapes. The keys are generated once and crossed into each
     * provider as encodings — the sanctioned crossing.
     */
    @Test
    public void agreesWithJslAndBouncyCastleAcrossEveryUkmAndSaltShape() throws Exception
    {
        assumeXdh();

        for (String curve : CURVES)
        {
            KeyPair a = KeyPairGenerator.getInstance(curve, fips()).generateKeyPair();
            KeyPair b = KeyPairGenerator.getInstance(curve, fips()).generateKeyPair();

            for (String[] scheme : SCHEMES)
            {
                byte[] ukm = randomBytes(1 + RANDOM.nextInt(64));
                byte[] distinctSalt = randomBytes(1 + RANDOM.nextInt(64));
                byte[][] salts = {null, distinctSalt, ukm, new byte[0]};
                String[] saltNames = {"no salt", "distinct salt", "salt = ukm", "empty salt"};

                for (int i = 0; i != salts.length; i++)
                {
                    String what = curve + " " + scheme[0] + " " + saltNames[i];

                    byte[] inModule = derive(fips(), scheme[0], a.getPrivate(), b.getPublic(),
                            ukm, salts[i]);
                    byte[] inBase = derive(jsl(), scheme[0], a.getPrivate(), b.getPublic(),
                            ukm, salts[i]);
                    byte[] inBc = derive(bc(), scheme[0], a.getPrivate(), b.getPublic(),
                            ukm, salts[i]);

                    Assertions.assertTrue(Arrays.areEqual(inModule, inBase),
                            what + ": JSLFIPS and JSL must derive the same KEK");
                    Assertions.assertTrue(Arrays.areEqual(inModule, inBc),
                            what + ": JSLFIPS and BC must derive the same KEK");

                    byte[] reversed = derive(fips(), scheme[0], b.getPrivate(), a.getPublic(),
                            ukm, salts[i]);
                    Assertions.assertTrue(Arrays.areEqual(inModule, reversed),
                            what + ": both parties must reach the same KEK");
                }
            }
        }
    }

    /**
     * The salt reaches the module's HKDF too — without this the FIPS cells
     * above would pass against an implementation that ignored it, since every
     * provider would ignore it alike.
     */
    @Test
    public void theSaltChangesTheDerivedKeyUnderTheModule() throws Exception
    {
        assumeXdh();

        KeyPair a = KeyPairGenerator.getInstance("X25519", fips()).generateKeyPair();
        KeyPair b = KeyPairGenerator.getInstance("X25519", fips()).generateKeyPair();
        byte[] ukm = randomBytes(16);

        byte[] none = derive(fips(), "XDHwithSHA256HKDF", a.getPrivate(), b.getPublic(), ukm, null);
        byte[] salted = derive(fips(), "XDHwithSHA256HKDF", a.getPrivate(), b.getPublic(), ukm, randomBytes(16));

        Assertions.assertFalse(Arrays.areEqual(none, salted),
                "a salt must change the KEK under the module");
    }

    // ----- helpers -----

    private static void assumeXdh()
    {
        Assumptions.assumeTrue(resolves("KeyPairGenerator", "X25519"),
                "the loaded FIPS module does not serve XDH");
    }

    private static boolean resolves(String type, String algorithm)
    {
        return Security.getProvider(JostleFIPSProvider.PROVIDER_NAME)
                .getService(type, algorithm) != null;
    }

    private static Provider fips()
    {
        return Security.getProvider(JostleFIPSProvider.PROVIDER_NAME);
    }

    private static Provider jsl()
    {
        return Security.getProvider(JostleProvider.PROVIDER_NAME);
    }

    private static Provider bc()
    {
        return Security.getProvider("BC");
    }

    private static byte[] randomBytes(int len)
    {
        byte[] b = new byte[len];
        RANDOM.nextBytes(b);
        return b;
    }

    private static byte[] derive(Provider provider, String alg, PrivateKey priv, PublicKey pub,
            byte[] ukm, byte[] salt) throws Exception
    {
        String curve = priv.getAlgorithm();
        KeyFactory kf = KeyFactory.getInstance(curve, provider);
        PrivateKey ourPriv = kf.generatePrivate(new PKCS8EncodedKeySpec(priv.getEncoded()));
        PublicKey theirPub = kf.generatePublic(new X509EncodedKeySpec(pub.getEncoded()));

        KeyAgreement ka = KeyAgreement.getInstance(alg, provider);
        ka.init(ourPriv, spec(provider, ukm, salt));
        ka.doPhase(theirPub, true);
        return ka.generateSecret(AES256_WRAP).getEncoded();
    }

    private static AlgorithmParameterSpec spec(Provider provider, byte[] ukm, byte[] salt)
            throws Exception
    {
        if (provider == bc())
        {
            Class<?> c = Class.forName("org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec");
            if (salt == null)
            {
                return (AlgorithmParameterSpec) c.getConstructor(byte[].class).newInstance(ukm);
            }
            return (AlgorithmParameterSpec) c.getConstructor(byte[].class, byte[].class)
                    .newInstance(ukm, salt);
        }
        if (salt == null)
        {
            return new UserKeyingMaterialSpec(ukm);
        }
        return new UserKeyingMaterialSpec(ukm, salt);
    }
}
