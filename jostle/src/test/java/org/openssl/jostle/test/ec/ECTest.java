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
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
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
            "P-256", "P-384", "P-521", "secp256k1",
            // One binary-field curve to cover the GF(2^m) code paths in
            // both OpenSSL's EC code and Jostle's bridges. K-283 chosen
            // for being the most commonly used NIST K-curve still
            // supported in mainstream OpenSSL builds.
            "sect283k1"
    };

    /**
     * Class-level seeding random — used to derive each test's local
     * SHA1PRNG seed. Per CLAUDE.md: "cache one SecureRandom per test
     * class, not per @Test method."
     */
    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * Per-test seeded random. The seed is logged on every call so a
     * flaky failure can be reproduced by re-running with the same
     * seed (per CLAUDE.md "Random message content AND length").
     */
    private static SecureRandom seededRandom(String testName) throws Exception
    {
        long seed = RANDOM.nextLong();
        System.out.println(testName + " seed=" + seed);
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        return sr;
    }

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
            catch (InvalidParameterException expected)
            {
                Assertions.assertTrue(
                        expected.getMessage().contains("is not supported"),
                        "expected 'is not supported' in message for "
                                + "key size " + bad
                                + ", got: " + expected.getMessage());
            }
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
        catch (InvalidAlgorithmParameterException expected)
        {
            Assertions.assertEquals("AlgorithmParameterSpec is null",
                    expected.getMessage());
        }
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
    // Curve-name aliasing: names OpenSSL doesn't accept directly must
    // still resolve via canonicalisation (TLS / SECG callers use these)
    // -----------------------------------------------------------------

    /**
     * OpenSSL registers P-256 only under {@code prime256v1}/{@code P-256}
     * — NOT the SECG {@code secp256r1} nor the X9.62 OID. TLS
     * ({@code NamedGroup.getCurveName(secp256r1)}) and SECG callers use
     * {@code secp256r1}, so the provider must canonicalise it. Both forms
     * must produce a working P-256 key (256-bit field).
     */
    @Test
    public void testKeyPairGenerator_ecGenParameterSpec_secp256r1Alias() throws Exception
    {
        Assumptions.assumeTrue(NISelector.ECServiceNI.curveSupported("P-256"));
        for (String name : new String[]{"secp256r1", "1.2.840.10045.3.1.7"})
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", JostleProvider.PROVIDER_NAME);
            kpg.initialize(new ECGenParameterSpec(name));
            ECPublicKey pub = (ECPublicKey) kpg.generateKeyPair().getPublic();
            Assertions.assertEquals(256, pub.getParams().getCurve().getField().getFieldSize(),
                    name + " did not resolve to P-256");
        }
    }

    // -----------------------------------------------------------------
    // Explicit-parameters ECParameterSpec acceptance
    // -----------------------------------------------------------------

    /**
     * The generator accepts an explicit {@link ECParameterSpec} (standard
     * JCA), reverse-resolving the supplied domain parameters to a named
     * curve OpenSSL recognises. Drive it with the parameters of a real
     * P-256 key and prove the resulting key is a usable P-256 key via a
     * sign/verify round-trip (with a tampered-message negative check).
     */
    @Test
    public void testKeyPairGenerator_explicitECParameterSpec_P256() throws Exception
    {
        Assumptions.assumeTrue(NISelector.ECServiceNI.curveSupported("P-256"));
        SecureRandom sr = seededRandom("testKeyPairGenerator_explicitECParameterSpec_P256");

        // Source a genuine P-256 ECParameterSpec from a named-curve key.
        KeyPairGenerator seed = KeyPairGenerator.getInstance("EC", JostleProvider.PROVIDER_NAME);
        seed.initialize(new ECGenParameterSpec("P-256"));
        ECParameterSpec p256 = ((ECPublicKey) seed.generateKeyPair().getPublic()).getParams();

        // Now generate using the explicit-parameters surface.
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", JostleProvider.PROVIDER_NAME);
        kpg.initialize(p256);
        KeyPair kp = kpg.generateKeyPair();
        Assertions.assertEquals(256,
                ((ECPublicKey) kp.getPublic()).getParams().getCurve().getField().getFieldSize(),
                "explicit P-256 parameters did not resolve to a 256-bit curve");

        Signature signer = Signature.getInstance("SHA256withECDSA", JostleProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());
        byte[] msg = new byte[16 + sr.nextInt(256)];
        sr.nextBytes(msg);
        signer.update(msg);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance("SHA256withECDSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(kp.getPublic());
        verifier.update(msg);
        Assertions.assertTrue(verifier.verify(sig),
                "key from explicit ECParameterSpec produced an unverifiable signature");

        msg[0] ^= 1;
        Signature tampered = Signature.getInstance("SHA256withECDSA", JostleProvider.PROVIDER_NAME);
        tampered.initVerify(kp.getPublic());
        tampered.update(msg);
        Assertions.assertFalse(tampered.verify(sig),
                "verification passed on a tampered message");
    }

    /**
     * An explicit {@link ECParameterSpec} that matches no named curve
     * OpenSSL recognises must be rejected with
     * {@link InvalidAlgorithmParameterException} — key generation here is
     * named-curve only.
     */
    @Test
    public void testKeyPairGenerator_explicitECParameterSpec_unknownCurveRejected() throws Exception
    {
        // A small, made-up prime-field curve that matches no standard curve.
        EllipticCurve curve = new EllipticCurve(
                new ECFieldFp(BigInteger.valueOf(23)),
                BigInteger.valueOf(1), BigInteger.valueOf(1));
        ECParameterSpec bogus = new ECParameterSpec(
                curve, new ECPoint(BigInteger.valueOf(3), BigInteger.valueOf(10)),
                BigInteger.valueOf(7), 1);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", JostleProvider.PROVIDER_NAME);
        try
        {
            kpg.initialize(bogus);
            Assertions.fail("expected rejection of an unknown explicit EC curve");
        }
        catch (InvalidAlgorithmParameterException expected)
        {
            Assertions.assertTrue(
                    expected.getMessage().contains("do not match any named curve"),
                    "unexpected message: " + expected.getMessage());
        }
    }


    // -----------------------------------------------------------------
    // All-curves smoke test
    // -----------------------------------------------------------------

    /**
     * NIST K-NNN / B-NNN aliases must resolve to the matching SECG
     * {@code sectNNNk1}/{@code sectNNNrN} curve. Important for users
     * migrating from BouncyCastle, which exposes binary-field curves
     * by their NIST short names. The pairs below mirror NIST FIPS 186
     * Annex D's name-to-SECG mapping.
     */
    @Test
    public void testKeyPairGenerator_acceptsNistBKAliases() throws Exception
    {
        // (NIST short name, SECG canonical name, expected field bits)
        String[][] aliases = {
                {"K-163", "sect163k1", "163"},
                {"K-233", "sect233k1", "233"},
                {"K-283", "sect283k1", "283"},
                {"K-409", "sect409k1", "409"},
                {"K-571", "sect571k1", "571"},
                // NOTE: NIST B-163 maps to sect163r2, not r1.
                {"B-163", "sect163r2", "163"},
                {"B-233", "sect233r1", "233"},
                {"B-283", "sect283r1", "283"},
                {"B-409", "sect409r1", "409"},
                {"B-571", "sect571r1", "571"},
        };
        int verified = 0;
        for (String[] row : aliases)
        {
            String nistName = row[0];
            String secgName = row[1];
            int expectedBits = Integer.parseInt(row[2]);
            // Skip a name only if the loaded OpenSSL build doesn't
            // advertise the SECG underlying curve.
            if (!NISelector.ECServiceNI.curveSupported(secgName))
            {
                continue;
            }

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", JostleProvider.PROVIDER_NAME);
            kpg.initialize(new ECGenParameterSpec(nistName));
            KeyPair kp = kpg.generateKeyPair();
            ECPublicKey pub = (ECPublicKey) kp.getPublic();
            Assertions.assertEquals(expectedBits,
                    pub.getParams().getCurve().getField().getFieldSize(),
                    nistName + " did not resolve to a curve with the "
                            + "expected field size " + expectedBits);
            verified++;
        }
        Assertions.assertTrue(verified > 0,
                "No NIST K/B-curves were testable against this OpenSSL build");
    }

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
            if (!NISelector.ECServiceNI.curveSupported(curve))
            {
                continue;
            }

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
            if (!NISelector.ECServiceNI.curveSupported(curve))
            {
                continue;
            }

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
            if (!NISelector.ECServiceNI.curveSupported(curve))
            {
                continue;
            }

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
     * BC's EC KeyFactory is strict about the PKCS#8 structure — it
     * rejects the legacy SEC1 ECPrivateKey form that OpenSSL's
     * {@code i2d_PrivateKey_bio} would emit by default. Jostle's
     * encoder routes EC keys through {@code OSSL_ENCODER} with
     * {@code structure="PrivateKeyInfo"} to produce a properly-wrapped
     * PKCS#8 PrivateKeyInfo (with the SEC1 ECPrivateKey nested inside
     * the OCTET STRING). This test confirms the round-trip works in
     * both directions.
     */
    @Test
    public void testKeyEncoding_PKCS8_BCInterop() throws Exception
    {
        for (String curve : STANDARD_CURVES)
        {
            if (!NISelector.ECServiceNI.curveSupported(curve))
            {
                continue;
            }

            KeyPairGenerator joKpg = KeyPairGenerator.getInstance("EC", JostleProvider.PROVIDER_NAME);
            joKpg.initialize(new ECGenParameterSpec(curve));
            PrivateKey joPriv = joKpg.generateKeyPair().getPrivate();
            byte[] joEncoded = joPriv.getEncoded();

            // Sanity: the encoded form starts with PKCS#8 version 0,
            // not SEC1 version 1. Catches a regression in the encoder
            // path that would silently revert to legacy emission.
            // First three bytes: outer SEQUENCE tag + length (1 or 2
            // bytes) + INTEGER tag, so byte[3] holds the version
            // length and byte[4] the version itself when the SEQUENCE
            // length is short-form. For the 3-byte form (length 0x81 LL),
            // shift everything by one. We just check both possibilities.
            int verIdx = (joEncoded[1] & 0x80) != 0 ? 5 : 4;
            Assertions.assertEquals(0, joEncoded[verIdx],
                    curve + ": Jostle PKCS#8 didn't start with version 0 — "
                            + "SEC1 ECPrivateKey leaked through to getEncoded()");

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

    /**
     * Jostle EC keys implement {@code org.openssl.jostle.jcajce.interfaces.ECKey},
     * the project marker that lets callers handling keys from multiple
     * providers (SunEC, BC, Jostle) discriminate Jostle-typed keys via
     * {@code instanceof}. Sits parallel to the other Jostle marker
     * interfaces ({@code RSAKey}, {@code EdDSAKey}, etc.).
     */
    @Test
    public void testProvider_keysImplementJostleECKeyMarker() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", JostleProvider.PROVIDER_NAME);
        kpg.initialize(new ECGenParameterSpec("P-256"));
        KeyPair kp = kpg.generateKeyPair();

        Assertions.assertTrue(
                kp.getPublic() instanceof org.openssl.jostle.jcajce.interfaces.ECKey,
                "Jostle public EC key should implement Jostle's ECKey marker");
        Assertions.assertTrue(
                kp.getPrivate() instanceof org.openssl.jostle.jcajce.interfaces.ECKey,
                "Jostle private EC key should implement Jostle's ECKey marker");

        // The marker extends java.security.interfaces.ECKey too — sanity
        // check that's still true (would catch a refactor that dropped
        // the standard interface from the marker definition).
        Assertions.assertTrue(
                kp.getPublic() instanceof java.security.interfaces.ECKey);
        Assertions.assertTrue(
                kp.getPrivate() instanceof java.security.interfaces.ECKey);
    }

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
    // AlgorithmParameters("EC") — required by BC's TLS JceTlsECDomain
    // -----------------------------------------------------------------

    /**
     * {@code AlgorithmParameters.getInstance("EC", "JSL")} must resolve
     * and yield a usable {@link ECParameterSpec} for a named curve. This
     * is the call BouncyCastle's {@code JceTlsECDomain} makes (via
     * {@code helper.createAlgorithmParameters("EC")}) to obtain NIST-curve
     * domain parameters before a TLS group can be negotiated.
     */
    @Test
    public void testAlgorithmParameters_EC_resolvesNamedCurve() throws Exception
    {
        AlgorithmParameters ap = AlgorithmParameters.getInstance("EC", JostleProvider.PROVIDER_NAME);
        ap.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec spec = ap.getParameterSpec(ECParameterSpec.class);
        Assertions.assertEquals(256, spec.getCurve().getField().getFieldSize(),
                "AlgorithmParameters(\"EC\") did not yield P-256 parameters");
    }

    /**
     * Resolvable by the id-ecPublicKey OID too — callers that key off the
     * OID (e.g. ASN.1 decoders) must reach the same implementation.
     */
    @Test
    public void testAlgorithmParameters_EC_resolvesByOID() throws Exception
    {
        AlgorithmParameters ap = AlgorithmParameters.getInstance("1.2.840.10045.2.1",
                JostleProvider.PROVIDER_NAME);
        ap.init(new ECGenParameterSpec("P-384"));
        ECParameterSpec spec = ap.getParameterSpec(ECParameterSpec.class);
        Assertions.assertEquals(384, spec.getCurve().getField().getFieldSize());
    }

    /**
     * Encode → decode round-trip through the JSL AlgorithmParameters must
     * be byte-stable, proving the delegate's ASN.1 codec is wired through.
     */
    @Test
    public void testAlgorithmParameters_EC_encodeDecodeRoundTrip() throws Exception
    {
        AlgorithmParameters ap = AlgorithmParameters.getInstance("EC", JostleProvider.PROVIDER_NAME);
        ap.init(new ECGenParameterSpec("P-256"));
        byte[] encoded = ap.getEncoded();
        Assertions.assertNotNull(encoded);

        AlgorithmParameters ap2 = AlgorithmParameters.getInstance("EC", JostleProvider.PROVIDER_NAME);
        ap2.init(encoded);
        ECParameterSpec spec = ap2.getParameterSpec(ECParameterSpec.class);
        Assertions.assertEquals(256, spec.getCurve().getField().getFieldSize());
        Assertions.assertArrayEquals(encoded, ap2.getEncoded(),
                "EC AlgorithmParameters encode/decode round-trip changed bytes");
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
            if (!NISelector.ECServiceNI.curveSupported(curve))
            {
                continue;
            }

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
            if (!NISelector.ECServiceNI.curveSupported(curve))
            {
                continue;
            }

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
        SecureRandom sr = seededRandom("testKeyFactory_ECPublicKeySpec_VerifiesOriginalSignature");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", JostleProvider.PROVIDER_NAME);
        kpg.initialize(new ECGenParameterSpec("P-256"));
        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kf = KeyFactory.getInstance("EC", JostleProvider.PROVIDER_NAME);
        ECPublicKeySpec pubSpec = kf.getKeySpec(kp.getPublic(), ECPublicKeySpec.class);
        ECPublicKey rebuiltPub = (ECPublicKey) kf.generatePublic(pubSpec);

        Signature signer = Signature.getInstance(
                "SHA256withECDSA", JostleProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());
        // Random content AND random length (16..271 bytes) per CLAUDE.md
        // "Random message content AND length" — fixed strings hide bugs
        // in alignment-, length-, or value-specific code paths.
        byte[] msg = new byte[16 + sr.nextInt(256)];
        sr.nextBytes(msg);
        signer.update(msg);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance(
                "SHA256withECDSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(rebuiltPub);
        verifier.update(msg);
        Assertions.assertTrue(verifier.verify(sig),
                "rebuilt public key did not verify a signature from the original private key");

        // Negative: tampering the message must break verification — guards
        // against a stub verifier that returns true on every input.
        msg[0] ^= 1;
        Signature tamperedVerifier = Signature.getInstance(
                "SHA256withECDSA", JostleProvider.PROVIDER_NAME);
        tamperedVerifier.initVerify(rebuiltPub);
        tamperedVerifier.update(msg);
        Assertions.assertFalse(tamperedVerifier.verify(sig),
                "rebuilt public key verified a tampered message");
    }

    // -----------------------------------------------------------------
    // ECKeyFactorySpi rejection paths
    // -----------------------------------------------------------------

    /**
     * The SPI must reject foreign KeySpec types (e.g. an RSA
     * public-key spec passed to the EC factory) with
     * {@link InvalidKeySpecException}. Important for JCE provider-chain
     * fallback semantics.
     */
    @Test
    public void testKeyFactory_engineGeneratePublic_rejectsForeignSpec() throws Exception
    {
        KeyFactory kf = KeyFactory.getInstance("EC", JostleProvider.PROVIDER_NAME);
        RSAPublicKeySpec rsaSpec = new RSAPublicKeySpec(
                BigInteger.valueOf(0xC0FFEEL), BigInteger.valueOf(65537));
        try
        {
            kf.generatePublic(rsaSpec);
            Assertions.fail("expected InvalidKeySpecException for RSAPublicKeySpec");
        }
        catch (InvalidKeySpecException expected)
        {
            Assertions.assertNotNull(expected.getMessage());
            Assertions.assertTrue(
                    expected.getMessage().startsWith("unsupported key spec: "),
                    "unexpected message: " + expected.getMessage());
        }
    }

    @Test
    public void testKeyFactory_engineGeneratePrivate_rejectsForeignSpec() throws Exception
    {
        KeyFactory kf = KeyFactory.getInstance("EC", JostleProvider.PROVIDER_NAME);
        try
        {
            // Passing an X.509 public-key spec to generatePrivate is the
            // wrong kind of bytes — must surface as InvalidKeySpecException.
            kf.generatePrivate(new X509EncodedKeySpec(new byte[16]));
            Assertions.fail("expected InvalidKeySpecException");
        }
        catch (InvalidKeySpecException expected)
        {
            Assertions.assertNotNull(expected.getMessage());
            Assertions.assertTrue(
                    expected.getMessage().startsWith("unsupported key spec: "),
                    "unexpected message: " + expected.getMessage());
        }
    }

    /**
     * {@code engineGetKeySpec} with a class the SPI doesn't recognise
     * must throw {@link InvalidKeySpecException}, not silently return
     * {@code null} or a wrong-type cast.
     */
    @Test
    public void testKeyFactory_engineGetKeySpec_rejectsUnsupportedSpecClass() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", JostleProvider.PROVIDER_NAME);
        kpg.initialize(new ECGenParameterSpec("P-256"));
        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kf = KeyFactory.getInstance("EC", JostleProvider.PROVIDER_NAME);
        // KeySpec is the base interface and not a concrete spec class;
        // there's no built-in conversion from JOECPublicKey to that.
        // Use a custom KeySpec subtype to force the unsupported branch.
        class CustomSpec implements KeySpec {}
        try
        {
            kf.getKeySpec(kp.getPublic(), CustomSpec.class);
            Assertions.fail("expected InvalidKeySpecException for unsupported spec class");
        }
        catch (InvalidKeySpecException expected)
        {
            Assertions.assertNotNull(expected.getMessage());
            Assertions.assertTrue(
                    expected.getMessage().startsWith(
                            "unsupported key spec for EC public key: "),
                    "unexpected message: " + expected.getMessage());
        }

        try
        {
            kf.getKeySpec(kp.getPrivate(), CustomSpec.class);
            Assertions.fail("expected InvalidKeySpecException for unsupported spec class");
        }
        catch (InvalidKeySpecException expected)
        {
            Assertions.assertNotNull(expected.getMessage());
            Assertions.assertTrue(
                    expected.getMessage().startsWith(
                            "unsupported key spec for EC private key: "),
                    "unexpected message: " + expected.getMessage());
        }
    }

    /**
     * {@code engineGetKeySpec} with a key whose class the SPI doesn't
     * recognise (e.g. a BC EC key, or a foreign key wrapper) must
     * throw {@link InvalidKeySpecException}.
     */
    @Test
    public void testKeyFactory_engineGetKeySpec_rejectsForeignKey() throws Exception
    {
        // Generate an EC key with BC and ask Jostle's KeyFactory to
        // extract a spec from it. BC's ECPublicKey is not a JOECPublicKey,
        // so the SPI's instanceof checks fall through.
        KeyPairGenerator bcKpg = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        bcKpg.initialize(new ECGenParameterSpec("P-256"));
        KeyPair bcKp = bcKpg.generateKeyPair();

        KeyFactory joKf = KeyFactory.getInstance("EC", JostleProvider.PROVIDER_NAME);
        try
        {
            joKf.getKeySpec(bcKp.getPublic(), ECPublicKeySpec.class);
            Assertions.fail("expected InvalidKeySpecException for foreign EC key");
        }
        catch (InvalidKeySpecException expected)
        {
            Assertions.assertNotNull(expected.getMessage());
            Assertions.assertTrue(
                    expected.getMessage().startsWith("unrecognised key type: "),
                    "unexpected message: " + expected.getMessage());
        }
    }

    /**
     * {@code KeyFactory.translateKey} should accept a foreign-provider
     * EC key and return a Jostle-provider equivalent. Catches paths
     * where the engine round-trips the encoded form correctly.
     */
    @Test
    public void testKeyFactory_engineTranslateKey_foreignECKey() throws Exception
    {
        KeyPairGenerator bcKpg = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        bcKpg.initialize(new ECGenParameterSpec("P-256"));
        KeyPair bcKp = bcKpg.generateKeyPair();

        KeyFactory joKf = KeyFactory.getInstance("EC", JostleProvider.PROVIDER_NAME);

        // Public side: BC key → Jostle key, both should encode to the
        // same X.509 SPKI bytes since they describe the same point.
        java.security.Key joPub = joKf.translateKey(bcKp.getPublic());
        Assertions.assertTrue(joPub instanceof ECPublicKey,
                "translateKey result should be ECPublicKey");
        Assertions.assertArrayEquals(bcKp.getPublic().getEncoded(), joPub.getEncoded(),
                "translateKey must preserve the X.509 encoding");

        // A Jostle key passed to translateKey should come back as-is.
        KeyPairGenerator joKpg = KeyPairGenerator.getInstance("EC", JostleProvider.PROVIDER_NAME);
        joKpg.initialize(new ECGenParameterSpec("P-256"));
        KeyPair joKp = joKpg.generateKeyPair();
        Assertions.assertSame(joKp.getPublic(), joKf.translateKey(joKp.getPublic()),
                "translateKey on a Jostle key should return the same instance");
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
        SecureRandom sr = seededRandom("testKeyFactory_ECPrivateKeySpec_SignsForOriginalPublic");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", JostleProvider.PROVIDER_NAME);
        kpg.initialize(new ECGenParameterSpec("P-256"));
        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kf = KeyFactory.getInstance("EC", JostleProvider.PROVIDER_NAME);
        ECPrivateKeySpec privSpec = kf.getKeySpec(kp.getPrivate(), ECPrivateKeySpec.class);
        ECPrivateKey rebuiltPriv = (ECPrivateKey) kf.generatePrivate(privSpec);

        Signature signer = Signature.getInstance(
                "SHA256withECDSA", JostleProvider.PROVIDER_NAME);
        signer.initSign(rebuiltPriv);
        // Random content AND random length (16..271 bytes) per CLAUDE.md
        // "Random message content AND length" — fixed strings hide bugs
        // in alignment-, length-, or value-specific code paths.
        byte[] msg = new byte[16 + sr.nextInt(256)];
        sr.nextBytes(msg);
        signer.update(msg);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance(
                "SHA256withECDSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(kp.getPublic());
        verifier.update(msg);
        Assertions.assertTrue(verifier.verify(sig),
                "signature from rebuilt private key did not verify against the "
                        + "original public key (public-point re-derivation went wrong)");

        // Negative: tampering the message must break verification — guards
        // against a stub verifier that returns true on every input.
        msg[0] ^= 1;
        Signature tamperedVerifier = Signature.getInstance(
                "SHA256withECDSA", JostleProvider.PROVIDER_NAME);
        tamperedVerifier.initVerify(kp.getPublic());
        tamperedVerifier.update(msg);
        Assertions.assertFalse(tamperedVerifier.verify(sig),
                "original public key verified a tampered message signed by the rebuilt private key");
    }
}
