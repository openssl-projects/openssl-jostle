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
import org.openssl.jostle.jcajce.spec.HybridValueParameterSpec;
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
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.nio.charset.StandardCharsets;

/**
 * RFC 9580 §5.1.6/§5.1.7's v6 hybrid HKDF for X25519 / X448 under JSLFIPS —
 * against JSL and against BouncyCastle. The base twin is
 * {@code XDHHybridHKDFAgreementTest}; neither substitutes for the other.
 *
 * <p><b>Module-dependent by design</b> — same gate as
 * {@code FIPSXDHCKDFAgreementTest}: the two hybrid-HKDF names follow the
 * XDH fetch gate exactly, asserted rather than assumed.
 */
public class FIPSXDHHybridHKDFAgreementTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

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

    private static String name(String curve)
    {
        return "X25519".equals(curve) ? "X25519withSHA256HKDF" : "X448withSHA512HKDF";
    }

    private static String otherCurve(String curve)
    {
        return "X25519".equals(curve) ? "X448" : "X25519";
    }

    private static byte[] info(String curve)
    {
        return ("OpenPGP " + curve).getBytes(StandardCharsets.US_ASCII);
    }

    /**
     * All-or-nothing with the XDH gate. A module serving XDH must serve
     * both hybrid-HKDF names; one that does not must serve neither.
     */
    @Test
    public void theSchemesTrackTheXdhGateExactly()
    {
        boolean xdh = resolves("KeyPairGenerator", "X25519");
        for (String curve : CURVES)
        {
            Assertions.assertEquals(xdh, resolves("KeyAgreement", name(curve)),
                    name(curve) + " must be registered exactly when the module serves XDH");
        }
    }

    @Test
    public void agreesWithJslAndBouncyCastle() throws Exception
    {
        assumeXdh();

        for (String curve : CURVES)
        {
            String name = name(curve);
            KeyPair ephemeral = KeyPairGenerator.getInstance(curve, fips()).generateKeyPair();
            KeyPair recipient = KeyPairGenerator.getInstance(curve, fips()).generateKeyPair();
            byte[] t = randomBytes(2 * (curve.equals("X25519") ? 32 : 56));

            byte[] inModule = derive(fips(), name, curve, ephemeral.getPrivate(), recipient.getPublic(), t);
            byte[] inBase = derive(jsl(), name, curve, ephemeral.getPrivate(), recipient.getPublic(), t);
            byte[] inBc = derive(bc(), name, curve, ephemeral.getPrivate(), recipient.getPublic(), t);

            Assertions.assertTrue(Arrays.areEqual(inModule, inBase),
                    name + ": JSLFIPS and JSL must derive the same KEK");
            Assertions.assertTrue(Arrays.areEqual(inModule, inBc),
                    name + ": JSLFIPS and BC must derive the same KEK");
        }
    }

    /** RFC 9580 makes T and the HKDF info mandatory under JSLFIPS too — same check as JSL. */
    @Test
    public void hybridRefusesMissingSpecTyped() throws Exception
    {
        assumeXdh();

        for (String curve : CURVES)
        {
            String name = name(curve);
            KeyPair kp = KeyPairGenerator.getInstance(curve, fips()).generateKeyPair();

            Assertions.assertThrows(InvalidKeyException.class, () ->
                    KeyAgreement.getInstance(name, fips()).init(kp.getPrivate()),
                    name + ": init(Key) with no spec must be refused typed under JSLFIPS");

            Assertions.assertThrows(java.security.InvalidAlgorithmParameterException.class, () ->
                    KeyAgreement.getInstance(name, fips()).init(kp.getPrivate(),
                            new UserKeyingMaterialSpec(info(curve))),
                    name + ": a plain UserKeyingMaterialSpec must be refused typed under JSLFIPS");
        }
    }

    /** Foreign spec refusal under JSLFIPS — same provider-agnostic check as JSL. */
    @Test
    public void hybridRefusesForeignParameterSpecTyped() throws Exception
    {
        assumeXdh();

        for (String curve : CURVES)
        {
            String name = name(curve);
            KeyPair kp = KeyPairGenerator.getInstance(curve, fips()).generateKeyPair();
            KeyAgreement ka = KeyAgreement.getInstance(name, fips());
            Assertions.assertThrows(java.security.InvalidAlgorithmParameterException.class, () ->
                    ka.init(kp.getPrivate(),
                            new org.bouncycastle.jcajce.spec.HybridValueParameterSpec(new byte[16], true,
                                    new org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec(info(curve)))),
                    name + ": BC's own HybridValueParameterSpec must be refused typed under JSLFIPS");
        }
    }

    /**
     * RFC 9580 fixes the IKM as ephemeral || recipient || Z — T always
     * precedes Z. The two-argument constructor defaults to the append
     * form ({@code isPrependedT() == false}), refused typed under
     * JSLFIPS too.
     */
    @Test
    public void appendFormTIsRefusedTyped() throws Exception
    {
        assumeXdh();

        for (String curve : CURVES)
        {
            String name = name(curve);
            KeyPair kp = KeyPairGenerator.getInstance(curve, fips()).generateKeyPair();

            Assertions.assertThrows(java.security.InvalidAlgorithmParameterException.class, () ->
                    KeyAgreement.getInstance(name, fips()).init(kp.getPrivate(),
                            new HybridValueParameterSpec(new byte[16],
                                    new UserKeyingMaterialSpec(info(curve)))),
                    name + ": the two-argument (append T) constructor must be refused typed under JSLFIPS");
        }
    }

    /** Curve-bound under JSLFIPS too — the wrong curve's local key is refused typed. */
    @Test
    public void wrongCurveLocalKeyIsRefusedTypedAtInit() throws Exception
    {
        assumeXdh();

        for (String curve : CURVES)
        {
            String name = name(curve);
            KeyPair wrongCurveKey = KeyPairGenerator.getInstance(otherCurve(curve), fips()).generateKeyPair();

            Assertions.assertThrows(InvalidKeyException.class, () ->
                    KeyAgreement.getInstance(name, fips()).init(wrongCurveKey.getPrivate(),
                            new HybridValueParameterSpec(new byte[16], true,
                                    new UserKeyingMaterialSpec(info(curve)))),
                    name + ": a " + otherCurve(curve) + " private key must be refused typed under JSLFIPS");
        }
    }

    /** Raw shared secret is refused under JSLFIPS too — same seal as JSL. */
    @Test
    public void rawSharedSecretIsRefused() throws Exception
    {
        assumeXdh();

        for (String curve : CURVES)
        {
            String name = name(curve);
            Assertions.assertThrows(UnsupportedOperationException.class, () ->
            {
                KeyPair ephemeral = KeyPairGenerator.getInstance(curve, fips()).generateKeyPair();
                KeyPair recipient = KeyPairGenerator.getInstance(curve, fips()).generateKeyPair();
                byte[] t = randomBytes(2 * (curve.equals("X25519") ? 32 : 56));
                KeyAgreement ka = KeyAgreement.getInstance(name, fips());
                ka.init(ephemeral.getPrivate(), new HybridValueParameterSpec(t, true,
                        new UserKeyingMaterialSpec(info(curve))));
                ka.doPhase(recipient.getPublic(), true);
                ka.generateSecret();
            }, name + ": raw generateSecret() must be refused under JSLFIPS");
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

    private static byte[] derive(Provider provider, String alg, String curve, PrivateKey priv, PublicKey pub,
            byte[] t) throws Exception
    {
        KeyFactory kf = KeyFactory.getInstance(curve, provider);
        PrivateKey ourPriv = kf.generatePrivate(new PKCS8EncodedKeySpec(priv.getEncoded()));
        PublicKey theirPub = kf.generatePublic(new X509EncodedKeySpec(pub.getEncoded()));

        KeyAgreement ka = KeyAgreement.getInstance(alg, provider);
        ka.init(ourPriv, spec(provider, curve, t));
        ka.doPhase(theirPub, true);
        return ka.generateSecret(AES256_WRAP).getEncoded();
    }

    private static AlgorithmParameterSpec spec(Provider provider, String curve, byte[] t)
    {
        if (provider == bc())
        {
            return new org.bouncycastle.jcajce.spec.HybridValueParameterSpec(t, true,
                    new org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec(info(curve)));
        }
        return new HybridValueParameterSpec(t, true, new UserKeyingMaterialSpec(info(curve)));
    }
}
