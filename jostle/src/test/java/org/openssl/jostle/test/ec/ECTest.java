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

package org.openssl.jostle.test.ec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.NISelector;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Phase 1 EC tests: keypair generation for OpenSSL-supported curves
 * and X.509 / PKCS#8 round-trip against BouncyCastle as the
 * cross-validation reference.
 *
 * <p>Tests use {@link Assumptions#assumeTrue} to skip curves the
 * loaded OpenSSL build doesn't support — by design the provider has
 * no curve list of its own, so what's testable is whatever OpenSSL
 * recognises. {@link NISelector#ECServiceNI}'s {@code curveSupported}
 * probe is the source of truth.
 */
public class ECTest
{
    private static final String[] STANDARD_CURVES = {
            "P-256", "P-384", "P-521", "secp256k1"
    };

    @BeforeAll
    public static void beforeAll()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }


    // -----------------------------------------------------------------
    // Curve introspection
    // -----------------------------------------------------------------

    @Test
    public void testCurveSupported_acceptsKnownCurves()
    {
        // P-256 is universal; if even this fails the build is broken.
        Assertions.assertTrue(NISelector.ECServiceNI.curveSupported("P-256"),
                "P-256 must be supported by any reasonable OpenSSL build");
    }

    @Test
    public void testCurveSupported_rejectsUnknownCurve()
    {
        Assertions.assertFalse(NISelector.ECServiceNI.curveSupported("not-a-real-curve"));
    }

    @Test
    public void testCurveSupported_rejectsNullName()
    {
        Assertions.assertFalse(NISelector.ECServiceNI.curveSupported(null));
    }


    // -----------------------------------------------------------------
    // KeyPairGenerator basics
    // -----------------------------------------------------------------

    @Test
    public void testKeyPairGenerator_default_producesP256() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", JostleProvider.PROVIDER_NAME);
        KeyPair kp = kpg.generateKeyPair();

        Assertions.assertTrue(kp.getPublic() instanceof ECPublicKey);
        Assertions.assertTrue(kp.getPrivate() instanceof ECPrivateKey);
        // Default is P-256 — modulus byte length should be 32 (256/8).
        ECPublicKey pub = (ECPublicKey) kp.getPublic();
        int fieldBits = pub.getParams().getCurve().getField().getFieldSize();
        Assertions.assertEquals(256, fieldBits, "default curve must be P-256");
    }

    @Test
    public void testKeyPairGenerator_initializeBitSize_P256() throws Exception
    {
        runKeySizeTest(256, 256);
    }

    @Test
    public void testKeyPairGenerator_initializeBitSize_P384() throws Exception
    {
        Assumptions.assumeTrue(NISelector.ECServiceNI.curveSupported("P-384"));
        runKeySizeTest(384, 384);
    }

    @Test
    public void testKeyPairGenerator_initializeBitSize_P521() throws Exception
    {
        Assumptions.assumeTrue(NISelector.ECServiceNI.curveSupported("P-521"));
        runKeySizeTest(521, 521);
    }

    private static void runKeySizeTest(int keysize, int expectedFieldBits) throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", JostleProvider.PROVIDER_NAME);
        kpg.initialize(keysize);
        KeyPair kp = kpg.generateKeyPair();

        ECPublicKey pub = (ECPublicKey) kp.getPublic();
        Assertions.assertEquals(expectedFieldBits,
                pub.getParams().getCurve().getField().getFieldSize());

        // Public point must lie on the curve (sanity: BigInteger components > 0).
        ECPoint w = pub.getW();
        Assertions.assertNotNull(w);
        Assertions.assertTrue(w.getAffineX().compareTo(BigInteger.ZERO) > 0);
        Assertions.assertTrue(w.getAffineY().compareTo(BigInteger.ZERO) > 0);

        ECPrivateKey priv = (ECPrivateKey) kp.getPrivate();
        Assertions.assertTrue(priv.getS().compareTo(BigInteger.ZERO) > 0);
    }

    @Test
    public void testKeyPairGenerator_initializeBitSize_rejectsUnsupported() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", JostleProvider.PROVIDER_NAME);
        // 192-bit / 224-bit / non-NIST sizes are intentionally not in
        // the bit-size map; users wanting them should pass an
        // ECGenParameterSpec.
        for (int bad : new int[]{0, 1, 192, 224, 255, 257, 4096})
        {
            try
            {
                kpg.initialize(bad);
                Assertions.fail("should have rejected key size " + bad);
            }
            catch (InvalidParameterException expected) {}
        }
    }

    @Test
    public void testKeyPairGenerator_ecGenParameterSpec_rejectsUnknownCurve() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", JostleProvider.PROVIDER_NAME);
        try
        {
            kpg.initialize(new ECGenParameterSpec("definitely-not-a-curve"));
            Assertions.fail();
        }
        catch (InvalidAlgorithmParameterException expected)
        {
            Assertions.assertTrue(expected.getMessage().contains("not supported"),
                    "expected 'not supported' in message, got: " + expected.getMessage());
        }
    }

    @Test
    public void testKeyPairGenerator_rejectsNullSpec() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", JostleProvider.PROVIDER_NAME);
        try
        {
            kpg.initialize((AlgorithmParameterSpec) null);
            Assertions.fail();
        }
        catch (InvalidAlgorithmParameterException expected) {}
    }

    @Test
    public void testKeyPairGenerator_rejectsForeignParameterSpec() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", JostleProvider.PROVIDER_NAME);
        try
        {
            kpg.initialize(new AlgorithmParameterSpec() {});
            Assertions.fail();
        }
        catch (InvalidAlgorithmParameterException expected)
        {
            Assertions.assertTrue(
                    expected.getMessage().contains("ECGenParameterSpec"),
                    "expected ECGenParameterSpec in message, got: " + expected.getMessage());
        }
    }


    // -----------------------------------------------------------------
    // All-curves smoke test
    // -----------------------------------------------------------------

    @Test
    public void testKeyPairGenerator_AllStandardCurves_genThenIntrospect() throws Exception
    {
        int generated = 0;
        for (String curve : STANDARD_CURVES)
        {
            if (!NISelector.ECServiceNI.curveSupported(curve))
            {
                continue;
            }
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", JostleProvider.PROVIDER_NAME);
            kpg.initialize(new ECGenParameterSpec(curve));
            KeyPair kp = kpg.generateKeyPair();

            ECPublicKey pub = (ECPublicKey) kp.getPublic();
            ECPoint w = pub.getW();
            Assertions.assertNotNull(w, curve + ": public point is null");
            Assertions.assertTrue(w.getAffineX().compareTo(BigInteger.ZERO) > 0,
                    curve + ": affine X is non-positive");
            Assertions.assertTrue(w.getAffineY().compareTo(BigInteger.ZERO) > 0,
                    curve + ": affine Y is non-positive");

            ECPrivateKey priv = (ECPrivateKey) kp.getPrivate();
            Assertions.assertTrue(priv.getS().compareTo(BigInteger.ZERO) > 0,
                    curve + ": private scalar is non-positive");

            generated++;
        }
        Assertions.assertTrue(generated > 0, "no standard curves were generated; OpenSSL build looks broken");
    }


    // -----------------------------------------------------------------
    // X.509 / PKCS#8 round-trip via the JCE KeyFactory
    // -----------------------------------------------------------------

    @Test
    public void testKeyEncoding_X509_jostleRoundTrip() throws Exception
    {
        for (String curve : STANDARD_CURVES)
        {
            if (!NISelector.ECServiceNI.curveSupported(curve)) continue;

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", JostleProvider.PROVIDER_NAME);
            kpg.initialize(new ECGenParameterSpec(curve));
            PublicKey original = kpg.generateKeyPair().getPublic();

            byte[] encoded = original.getEncoded();
            Assertions.assertNotNull(encoded, curve + ": getEncoded() is null");

            KeyFactory kf = KeyFactory.getInstance("EC", JostleProvider.PROVIDER_NAME);
            PublicKey roundTripped = kf.generatePublic(new X509EncodedKeySpec(encoded));

            Assertions.assertArrayEquals(original.getEncoded(), roundTripped.getEncoded(),
                    curve + ": Jostle X.509 round-trip changed bytes");
        }
    }

    @Test
    public void testKeyEncoding_PKCS8_jostleRoundTrip() throws Exception
    {
        for (String curve : STANDARD_CURVES)
        {
            if (!NISelector.ECServiceNI.curveSupported(curve)) continue;

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", JostleProvider.PROVIDER_NAME);
            kpg.initialize(new ECGenParameterSpec(curve));
            PrivateKey original = kpg.generateKeyPair().getPrivate();

            byte[] encoded = original.getEncoded();
            Assertions.assertNotNull(encoded, curve + ": getEncoded() is null");

            KeyFactory kf = KeyFactory.getInstance("EC", JostleProvider.PROVIDER_NAME);
            PrivateKey roundTripped = kf.generatePrivate(new PKCS8EncodedKeySpec(encoded));

            Assertions.assertArrayEquals(original.getEncoded(), roundTripped.getEncoded(),
                    curve + ": Jostle PKCS#8 round-trip changed bytes");
        }
    }

    @Test
    public void testKeyEncoding_X509_BCInterop() throws Exception
    {
        // Jostle-encoded keys must decode cleanly through BC, and BC's
        // re-encoding of the same key must round-trip back through
        // Jostle's KeyFactory.
        for (String curve : STANDARD_CURVES)
        {
            if (!NISelector.ECServiceNI.curveSupported(curve)) continue;

            KeyPairGenerator joKpg = KeyPairGenerator.getInstance("EC", JostleProvider.PROVIDER_NAME);
            joKpg.initialize(new ECGenParameterSpec(curve));
            PublicKey joPub = joKpg.generateKeyPair().getPublic();
            byte[] joEncoded = joPub.getEncoded();

            KeyFactory bcKf = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
            PublicKey bcPub = bcKf.generatePublic(new X509EncodedKeySpec(joEncoded));

            // BC's view of the public point must agree with Jostle's.
            ECPoint joPoint = ((ECPublicKey) joPub).getW();
            ECPoint bcPoint = ((ECPublicKey) bcPub).getW();
            Assertions.assertEquals(joPoint.getAffineX(), bcPoint.getAffineX(),
                    curve + ": affine X disagrees between Jostle and BC");
            Assertions.assertEquals(joPoint.getAffineY(), bcPoint.getAffineY(),
                    curve + ": affine Y disagrees between Jostle and BC");

            // BC's encoded form should re-decode through Jostle.
            byte[] bcEncoded = bcPub.getEncoded();
            KeyFactory joKf = KeyFactory.getInstance("EC", JostleProvider.PROVIDER_NAME);
            PublicKey roundTripped = joKf.generatePublic(new X509EncodedKeySpec(bcEncoded));
            Assertions.assertNotNull(roundTripped);
        }
    }

    /**
     * TODO Phase 1.5: BC's strict EC PKCS#8 parser doesn't accept
     * OpenSSL 3.x's default emission. Evaluate whether to add an
     * encoding-mode hint to {@code PrivateKeyOptions} so the OpenSSL
     * side emits the SEC1-wrapped form BC expects, or accept that
     * users wanting BC interop on EC private keys re-encode through
     * the public-key path. Public-key X.509 interop already works
     * (see {@link #testKeyEncoding_X509_BCInterop()}).
     */
    // @Test
    public void testKeyEncoding_PKCS8_BCInterop() throws Exception
    {
        for (String curve : STANDARD_CURVES)
        {
            if (!NISelector.ECServiceNI.curveSupported(curve)) continue;

            KeyPairGenerator joKpg = KeyPairGenerator.getInstance("EC", JostleProvider.PROVIDER_NAME);
            joKpg.initialize(new ECGenParameterSpec(curve));
            PrivateKey joPriv = joKpg.generateKeyPair().getPrivate();
            byte[] joEncoded = joPriv.getEncoded();

            KeyFactory bcKf = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
            PrivateKey bcPriv = bcKf.generatePrivate(new PKCS8EncodedKeySpec(joEncoded));
            Assertions.assertEquals(((ECPrivateKey) joPriv).getS(),
                    ((ECPrivateKey) bcPriv).getS(),
                    curve + ": private scalar disagrees between Jostle and BC");

            byte[] bcEncoded = bcPriv.getEncoded();
            KeyFactory joKf = KeyFactory.getInstance("EC", JostleProvider.PROVIDER_NAME);
            PrivateKey roundTripped = joKf.generatePrivate(new PKCS8EncodedKeySpec(bcEncoded));
            Assertions.assertNotNull(roundTripped);
        }
    }


    // -----------------------------------------------------------------
    // Provider plumbing: OID alias + getInstance via OID
    // -----------------------------------------------------------------

    @Test
    public void testProvider_getInstanceByOID() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("1.2.840.10045.2.1",
                JostleProvider.PROVIDER_NAME);
        kpg.initialize(new ECGenParameterSpec("P-256"));
        KeyPair kp = kpg.generateKeyPair();
        Assertions.assertTrue(kp.getPublic() instanceof ECPublicKey);

        KeyFactory kf = KeyFactory.getInstance("1.2.840.10045.2.1",
                JostleProvider.PROVIDER_NAME);
        Assertions.assertNotNull(kf);
    }


    // -----------------------------------------------------------------
    // Raw-component KeySpec support (ECPublicKeySpec / ECPrivateKeySpec)
    // -----------------------------------------------------------------

    /**
     * ECPublicKeySpec round-trip: get the components from a generated
     * key, build a fresh ECPublicKeySpec, decode it, and assert the
     * recovered point matches the original. Repeats across all
     * supported standard curves.
     */
    @Test
    public void testKeyFactory_ECPublicKeySpec_roundTrip() throws Exception
    {
        for (String curve : STANDARD_CURVES)
        {
            if (!NISelector.ECServiceNI.curveSupported(curve)) continue;

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", JostleProvider.PROVIDER_NAME);
            kpg.initialize(new ECGenParameterSpec(curve));
            ECPublicKey original = (ECPublicKey) kpg.generateKeyPair().getPublic();

            KeyFactory kf = KeyFactory.getInstance("EC", JostleProvider.PROVIDER_NAME);
            ECPublicKeySpec spec = kf.getKeySpec(original, ECPublicKeySpec.class);
            Assertions.assertEquals(original.getW().getAffineX(), spec.getW().getAffineX(),
                    curve + ": affine X mismatch in extracted ECPublicKeySpec");
            Assertions.assertEquals(original.getW().getAffineY(), spec.getW().getAffineY(),
                    curve + ": affine Y mismatch");

            ECPublicKey rebuilt = (ECPublicKey) kf.generatePublic(spec);
            Assertions.assertEquals(original.getW().getAffineX(), rebuilt.getW().getAffineX(),
                    curve + ": affine X mismatch after spec round-trip");
            Assertions.assertEquals(original.getW().getAffineY(), rebuilt.getW().getAffineY(),
                    curve + ": affine Y mismatch after spec round-trip");

            // The X.509-encoded forms must agree — proves the
            // SunEC-encode → Jostle-decode path produced the same
            // EVP_PKEY as the directly-loaded one.
            Assertions.assertArrayEquals(original.getEncoded(), rebuilt.getEncoded(),
                    curve + ": rebuilt key X.509 encoding differs");
        }
    }

    /**
     * ECPrivateKeySpec round-trip: extract spec, rebuild key, compare
     * the private scalar. Repeats across all supported standard curves.
     * The path goes through the dedicated
     * {@code ec_make_private_from_components} C entry point rather than
     * a SunEC-encoded round-trip — see {@link ECKeyFactorySpi} class
     * Javadoc.
     */
    @Test
    public void testKeyFactory_ECPrivateKeySpec_roundTrip() throws Exception
    {
        for (String curve : STANDARD_CURVES)
        {
            if (!NISelector.ECServiceNI.curveSupported(curve)) continue;

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", JostleProvider.PROVIDER_NAME);
            kpg.initialize(new ECGenParameterSpec(curve));
            ECPrivateKey original = (ECPrivateKey) kpg.generateKeyPair().getPrivate();

            KeyFactory kf = KeyFactory.getInstance("EC", JostleProvider.PROVIDER_NAME);
            ECPrivateKeySpec spec = kf.getKeySpec(original, ECPrivateKeySpec.class);
            Assertions.assertEquals(original.getS(), spec.getS(),
                    curve + ": private scalar mismatch in extracted ECPrivateKeySpec");

            ECPrivateKey rebuilt = (ECPrivateKey) kf.generatePrivate(spec);
            Assertions.assertEquals(original.getS(), rebuilt.getS(),
                    curve + ": private scalar mismatch after spec round-trip");
        }
    }

    /**
     * Sign/verify with a public key rebuilt from ECPublicKeySpec —
     * the original private key is reused as-is. Catches a path where
     * the SunEC-encode → Jostle-decode round-trip silently produces a
     * differently-located point that still parses but doesn't agree
     * with signatures from the original private key.
     */
    @Test
    public void testKeyFactory_ECPublicKeySpec_VerifiesOriginalSignature() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", JostleProvider.PROVIDER_NAME);
        kpg.initialize(new ECGenParameterSpec("P-256"));
        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kf = KeyFactory.getInstance("EC", JostleProvider.PROVIDER_NAME);
        ECPublicKeySpec pubSpec = kf.getKeySpec(kp.getPublic(), ECPublicKeySpec.class);
        ECPublicKey rebuiltPub = (ECPublicKey) kf.generatePublic(pubSpec);

        java.security.Signature signer = java.security.Signature.getInstance(
                "SHA256withECDSA", JostleProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());
        byte[] msg = "hello from a respec-roundtripped public key".getBytes();
        signer.update(msg);
        byte[] sig = signer.sign();

        java.security.Signature verifier = java.security.Signature.getInstance(
                "SHA256withECDSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(rebuiltPub);
        verifier.update(msg);
        Assertions.assertTrue(verifier.verify(sig),
                "rebuilt public key did not verify a signature from the original private key");
    }

    /**
     * Sign with a private key rebuilt from {@link ECPrivateKeySpec},
     * verify with the original public key. Confirms the new
     * {@code ec_make_private_from_components} entry point produces a
     * functionally-equivalent EVP_PKEY — including the public point
     * OpenSSL re-derives during {@code EVP_PKEY_fromdata}.
     */
    @Test
    public void testKeyFactory_ECPrivateKeySpec_SignsForOriginalPublic() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", JostleProvider.PROVIDER_NAME);
        kpg.initialize(new ECGenParameterSpec("P-256"));
        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kf = KeyFactory.getInstance("EC", JostleProvider.PROVIDER_NAME);
        ECPrivateKeySpec privSpec = kf.getKeySpec(kp.getPrivate(), ECPrivateKeySpec.class);
        ECPrivateKey rebuiltPriv = (ECPrivateKey) kf.generatePrivate(privSpec);

        java.security.Signature signer = java.security.Signature.getInstance(
                "SHA256withECDSA", JostleProvider.PROVIDER_NAME);
        signer.initSign(rebuiltPriv);
        byte[] msg = "hello from a respec-roundtripped private key".getBytes();
        signer.update(msg);
        byte[] sig = signer.sign();

        java.security.Signature verifier = java.security.Signature.getInstance(
                "SHA256withECDSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(kp.getPublic());
        verifier.update(msg);
        Assertions.assertTrue(verifier.verify(sig),
                "signature from rebuilt private key did not verify against the "
                        + "original public key (public-point re-derivation went wrong)");
    }
}
