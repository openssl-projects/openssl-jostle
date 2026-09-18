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
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * RFC 6637 §7 SP 800-56C one-step KDF for X25519 / X448 under JSLFIPS —
 * against JSL and against BouncyCastle. The base twin is
 * {@code XDHCKDFAgreementTest}; neither substitutes for the other.
 *
 * <p><b>Module-dependent by design</b> — same gate as
 * {@code FIPSXDHHKDFAgreementTest}: the six CKDF names follow the XDH
 * fetch gate exactly, asserted rather than assumed.
 */
public class FIPSXDHCKDFAgreementTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final String[] CURVES = {"X25519", "X448"};
    private static final String[] DIGESTS = {"SHA256", "SHA384", "SHA512"};
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

    private static String name(String curve, String digest)
    {
        return curve + "with" + digest + "CKDF";
    }

    private static String otherCurve(String curve)
    {
        return "X25519".equals(curve) ? "X448" : "X25519";
    }

    /**
     * All-or-nothing with the XDH gate. A module serving XDH must serve
     * every CKDF name; one that does not must serve none.
     */
    @Test
    public void theSchemesTrackTheXdhGateExactly()
    {
        boolean xdh = resolves("KeyPairGenerator", "X25519");
        for (String curve : CURVES)
        {
            for (String digest : DIGESTS)
            {
                Assertions.assertEquals(xdh, resolves("KeyAgreement", name(curve, digest)),
                        name(curve, digest) + " must be registered exactly when the module serves XDH");
            }
        }
    }

    @Test
    public void agreesWithJslAndBouncyCastle() throws Exception
    {
        assumeXdh();

        for (String curve : CURVES)
        {
            for (String digest : DIGESTS)
            {
                String name = name(curve, digest);
                KeyPair a = KeyPairGenerator.getInstance(curve, fips()).generateKeyPair();
                KeyPair b = KeyPairGenerator.getInstance(curve, fips()).generateKeyPair();
                byte[] param = randomBytes(1 + RANDOM.nextInt(48));

                byte[] inModule = derive(fips(), name, a.getPrivate(), b.getPublic(), param);
                byte[] inBase = derive(jsl(), name, a.getPrivate(), b.getPublic(), param);
                byte[] inBc = derive(bc(), name, a.getPrivate(), b.getPublic(), param);

                Assertions.assertTrue(Arrays.areEqual(inModule, inBase),
                        name + ": JSLFIPS and JSL must derive the same KEK");
                Assertions.assertTrue(Arrays.areEqual(inModule, inBc),
                        name + ": JSLFIPS and BC must derive the same KEK");

                byte[] reversed = derive(fips(), name, b.getPrivate(), a.getPublic(), param);
                Assertions.assertTrue(Arrays.areEqual(inModule, reversed),
                        name + ": both parties must reach the same KEK");
            }
        }
    }

    /** RFC 6637 §8 makes Param mandatory under JSLFIPS too — same check as JSL. */
    @Test
    public void ckdfRefusesMissingParamTyped() throws Exception
    {
        assumeXdh();

        for (String curve : CURVES)
        {
            String name = name(curve, "SHA256");
            KeyPair kp = KeyPairGenerator.getInstance(curve, fips()).generateKeyPair();

            Assertions.assertThrows(java.security.InvalidKeyException.class, () ->
                    KeyAgreement.getInstance(name, fips()).init(kp.getPrivate()),
                    name + ": init(Key) with no Param must be refused typed under JSLFIPS");

            Assertions.assertThrows(java.security.InvalidAlgorithmParameterException.class, () ->
                    KeyAgreement.getInstance(name, fips()).init(kp.getPrivate(),
                            new UserKeyingMaterialSpec(null)),
                    name + ": a null Param must be refused typed under JSLFIPS");

            Assertions.assertThrows(java.security.InvalidAlgorithmParameterException.class, () ->
                    KeyAgreement.getInstance(name, fips()).init(kp.getPrivate(),
                            new UserKeyingMaterialSpec(new byte[0])),
                    name + ": an empty Param must be refused typed under JSLFIPS");
        }
    }

    /** Foreign spec refusal under JSLFIPS — same provider-agnostic check as JSL. */
    @Test
    public void ckdfRefusesForeignParameterSpecTyped() throws Exception
    {
        assumeXdh();

        for (String curve : CURVES)
        {
            String name = name(curve, "SHA256");
            KeyPair kp = KeyPairGenerator.getInstance(curve, fips()).generateKeyPair();
            KeyAgreement ka = KeyAgreement.getInstance(name, fips());
            Assertions.assertThrows(java.security.InvalidAlgorithmParameterException.class, () ->
                    ka.init(kp.getPrivate(),
                            new org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec(new byte[16])),
                    name + ": BC's own UserKeyingMaterialSpec must be refused typed under JSLFIPS");
        }
    }

    /** Curve-bound under JSLFIPS too — the wrong curve's local key is refused typed. */
    @Test
    public void wrongCurveLocalKeyIsRefusedTypedAtInit() throws Exception
    {
        assumeXdh();

        for (String curve : CURVES)
        {
            String name = name(curve, "SHA256");
            KeyPair wrongCurveKey = KeyPairGenerator.getInstance(otherCurve(curve), fips()).generateKeyPair();

            Assertions.assertThrows(InvalidKeyException.class, () ->
                    KeyAgreement.getInstance(name, fips()).init(wrongCurveKey.getPrivate(),
                            new UserKeyingMaterialSpec(new byte[16])),
                    name + ": a " + otherCurve(curve) + " private key must be refused typed under JSLFIPS");
        }
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
            byte[] param) throws Exception
    {
        String curve = priv.getAlgorithm();
        KeyFactory kf = KeyFactory.getInstance(curve, provider);
        PrivateKey ourPriv = kf.generatePrivate(new PKCS8EncodedKeySpec(priv.getEncoded()));
        PublicKey theirPub = kf.generatePublic(new X509EncodedKeySpec(pub.getEncoded()));

        KeyAgreement ka = KeyAgreement.getInstance(alg, provider);
        ka.init(ourPriv, spec(provider, param));
        ka.doPhase(theirPub, true);
        return ka.generateSecret(AES256_WRAP).getEncoded();
    }

    private static java.security.spec.AlgorithmParameterSpec spec(Provider provider, byte[] param)
            throws Exception
    {
        if (provider == bc())
        {
            return new org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec(param);
        }
        return new UserKeyingMaterialSpec(param);
    }
}
