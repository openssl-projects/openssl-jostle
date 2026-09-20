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
import org.openssl.jostle.test.util.CipherFamilies;
import org.openssl.jostle.test.util.ProviderSurfaceGuard;
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

    // ------------------------------------------------- surface discovery

    private static final String[] XEC_TYPES =
            {"KeyAgreement", "KeyFactory", "KeyPairGenerator"};

    /**
     * Every {@code xec} service JSLFIPS registers is DRIVEN, discovered rather
     * than listed, aliases included.
     *
     * <p>Gated on the MODULE, not on the provider: asking the provider whether
     * it registered XDH and then checking it registered XDH compares the
     * registration with itself. 3.1.2 serves the family and 3.5.8 does not, and
     * on the module that does not the assertion is that the WHOLE surface is
     * absent — a skip would pass equally against a registrar that had silently
     * dropped a family the module can serve. The all-or-nothing half across the
     * individual names is {@code FIPSXDHKDFTest.xdhServedIffModuleImplementsIt};
     * this cell adds that each registered name can actually be operated.
     */
    @Test
    public void everyRegisteredXdhServiceIsDriven()
    {
        if (!FIPSTestUtil.moduleServesKeyMgmt("X25519"))
        {
            Assertions.assertTrue(
                    ProviderSurfaceGuard.registeredSurface(
                            fips(), CipherFamilies.XEC_PREFIX, XEC_TYPES).isEmpty(),
                    "the module does not implement X25519, so JSLFIPS must register "
                            + "no xec service at all");
            return;
        }

        ProviderSurfaceGuard.assertEveryServiceDriven(
                fips(), CipherFamilies.XEC_PREFIX, "XDH (JSLFIPS)", XEC_TYPES,
                new ProviderSurfaceGuard.ServiceDriver()
                {
                    @Override
                    public void drive(String type, String algorithm) throws Exception
                    {
                        driveFipsXecService(type, algorithm);
                    }
                });
    }

    /** The curve a registered name identifies; the OIDs ARE the curve identifiers. */
    private static String xecCurveOf(String algorithm)
    {
        String a = algorithm.toUpperCase(java.util.Locale.ROOT);
        if (a.startsWith("OID."))
        {
            a = a.substring(4);
        }
        if ("1.3.101.110".equals(a))
        {
            return "X25519";
        }
        if ("1.3.101.111".equals(a))
        {
            return "X448";
        }
        if (a.startsWith("X448"))
        {
            return "X448";
        }
        // Bare XDH and the HKDF KeyAgreement OIDs name no curve: the KDF is what
        // is under test there, so drive one curve.
        return "X25519";
    }

    private static void driveFipsXecService(String type, String algorithm) throws Exception
    {
        String curve = xecCurveOf(algorithm);
        if ("KeyPairGenerator".equals(type))
        {
            KeyPair kp = KeyPairGenerator.getInstance(algorithm, fips()).generateKeyPair();
            Assertions.assertNotNull(kp.getPrivate(), algorithm + ": no private key");
            return;
        }
        if ("KeyFactory".equals(type))
        {
            KeyPair kp = KeyPairGenerator.getInstance(curve, fips()).generateKeyPair();
            KeyFactory kf = KeyFactory.getInstance(algorithm, fips());
            Assertions.assertArrayEquals(kp.getPublic().getEncoded(),
                    kf.generatePublic(new X509EncodedKeySpec(
                            kp.getPublic().getEncoded())).getEncoded(),
                    algorithm + ": public round-trip changed the encoding");
            Assertions.assertArrayEquals(kp.getPrivate().getEncoded(),
                    kf.generatePrivate(new PKCS8EncodedKeySpec(
                            kp.getPrivate().getEncoded())).getEncoded(),
                    algorithm + ": private round-trip changed the encoding");
            return;
        }
        if (!"KeyAgreement".equals(type))
        {
            throw new IllegalStateException("unknown service type " + type);
        }

        // Dispatch on the SPI CLASS. X25519WITHSHA256HKDF is the RFC 9580
        // hybrid and XDHWITHSHA256HKDF is the plain one; no pattern built from
        // the name can tell them apart.
        String cn = fips().getService(type, algorithm).getClassName();
        String spi = cn.substring(cn.lastIndexOf('.') + 1);

        KeyPair alice = KeyPairGenerator.getInstance(curve, fips()).generateKeyPair();
        KeyPair bob = KeyPairGenerator.getInstance(curve, fips()).generateKeyPair();

        if ("XDHKeyAgreementSpi".equals(spi))
        {
            // The module and mainline must derive the same raw secret.
            Assertions.assertArrayEquals(
                    rawSecret(jsl(), algorithm, curve, alice, bob),
                    rawSecret(fips(), algorithm, curve, alice, bob),
                    algorithm + ": module and base derived different raw secrets");
            return;
        }

        byte[] ukm = randomBytes(16 + RANDOM.nextInt(32));

        if ("XDHWithCKDFKeyAgreementSpi".equals(spi) || "XDHWithHKDFKeyAgreementSpi".equals(spi))
        {
            Assertions.assertArrayEquals(
                    fipsKek(jsl(), algorithm, curve, alice, bob, new UserKeyingMaterialSpec(ukm)),
                    fipsKek(fips(), algorithm, curve, alice, bob, new UserKeyingMaterialSpec(ukm)),
                    algorithm + ": module and base derived different KEKs");
            return;
        }

        if ("XDHWithHybridHKDFKeyAgreementSpi".equals(spi))
        {
            // Same T and UKM through the module and through mainline must give
            // the same bytes; the second measure is that T reaches the KDF.
            byte[] t1 = randomBytes(32);
            byte[] t2 = randomBytes(32);
            final byte[] inModule = fipsKek(fips(), algorithm, curve, alice, bob,
                    new HybridValueParameterSpec(t1, true, new UserKeyingMaterialSpec(ukm)));
            final byte[] inBase = fipsKek(jsl(), algorithm, curve, alice, bob,
                    new HybridValueParameterSpec(t1, true, new UserKeyingMaterialSpec(ukm)));
            final byte[] otherT = fipsKek(fips(), algorithm, curve, alice, bob,
                    new HybridValueParameterSpec(t2, true, new UserKeyingMaterialSpec(ukm)));
            final String name = algorithm;
            Assertions.assertAll(
                    () -> Assertions.assertArrayEquals(inBase, inModule,
                            name + ": module and base derived different KEKs"),
                    () -> Assertions.assertFalse(Arrays.areEqual(inModule, otherT),
                            name + ": the hybrid value does not reach the KDF"));
            return;
        }

        throw new IllegalStateException(algorithm + ": unknown SPI " + spi
                + " — teach the driver an operation for it");
    }

    /**
     * Keys belong to the provider instance that made them. Encodings are the
     * only crossing, so both halves are re-decoded through the target provider.
     */
    private static byte[] fipsKek(Provider p, String algorithm, String curve, KeyPair alice,
                                  KeyPair bob, java.security.spec.AlgorithmParameterSpec spec)
            throws Exception
    {
        KeyFactory kf = KeyFactory.getInstance(curve, p);
        KeyAgreement ka = KeyAgreement.getInstance(algorithm, p);
        ka.init(kf.generatePrivate(new PKCS8EncodedKeySpec(alice.getPrivate().getEncoded())), spec);
        ka.doPhase(kf.generatePublic(new X509EncodedKeySpec(bob.getPublic().getEncoded())), true);
        return ka.generateSecret(AES256_WRAP).getEncoded();
    }

    private static byte[] rawSecret(Provider p, String algorithm, String curve, KeyPair alice,
                                    KeyPair bob) throws Exception
    {
        KeyFactory kf = KeyFactory.getInstance(curve, p);
        KeyAgreement ka = KeyAgreement.getInstance(algorithm, p);
        ka.init(kf.generatePrivate(new PKCS8EncodedKeySpec(alice.getPrivate().getEncoded())));
        ka.doPhase(kf.generatePublic(new X509EncodedKeySpec(bob.getPublic().getEncoded())), true);
        return ka.generateSecret();
    }
}
