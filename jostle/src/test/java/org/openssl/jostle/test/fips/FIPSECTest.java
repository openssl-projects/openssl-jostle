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
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.util.Arrays;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * EC through the FIPS provider ("JSLFIPS"): keygen on the NIST curves,
 * ECDSA agreement with BouncyCastle both directions, ECDH shared secrets
 * matching BC, key encodings round-tripping, and the module's curve gate
 * (secp256k1 rejected). Gated on TEST_FIPS_LIB; skipped when unset.
 */
public class FIPSECTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final String FIPS = JostleFIPSProvider.PROVIDER_NAME;
    private static final String JSL = JostleProvider.PROVIDER_NAME;

    /**
     * ECDSA digest algorithms the FIPS provider registers, EXCLUDING
     * {@code SHA1withECDSA} — the MODULE refuses SHA-1 signature GENERATION
     * ({@code rsa_setup_md: digest not allowed}), so the transformation is
     * served but fails at init. Covered separately by
     * {@link FIPSSha1SignatureGateTest}.
     */
    private static final String[] DIGEST_ALGS = {
            "SHA224withECDSA",
            "SHA256withECDSA",
            "SHA384withECDSA",
            "SHA512withECDSA",
            "SHA3-224withECDSA",
            "SHA3-256withECDSA",
            "SHA3-384withECDSA",
            "SHA3-512withECDSA",
    };

    /**
     * Per-test seeded random; the seed is logged so a flaky failure can
     * be reproduced by re-running with the same seed (per CLAUDE.md).
     */
    private static SecureRandom seededRandom(String testName)
        throws Exception
    {
        long seed = RANDOM.nextLong();
        System.out.println(testName + " seed=" + seed);
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        return sr;
    }

    private static byte[] randomMessage(SecureRandom sr, int len)
    {
        byte[] m = new byte[len];
        sr.nextBytes(m);
        return m;
    }

    private static byte[] signOneShot(String alg, KeyPair kp, byte[] msg)
        throws Exception
    {
        Signature signer = Signature.getInstance(alg, FIPS);
        signer.initSign(kp.getPrivate());
        signer.update(msg);
        return signer.sign();
    }

    private static boolean verify(String alg, KeyPair kp, byte[] msg, byte[] sig)
        throws Exception
    {
        Signature verifier = Signature.getInstance(alg, FIPS);
        verifier.initVerify(kp.getPublic());
        verifier.update(msg);
        return verifier.verify(sig);
    }

    private static byte[] signWithChunking(String alg, KeyPair kp, byte[] msg, int chunk)
        throws Exception
    {
        Signature signer = Signature.getInstance(alg, FIPS);
        signer.initSign(kp.getPrivate());
        for (int off = 0; off < msg.length; off += chunk)
        {
            int len = Math.min(chunk, msg.length - off);
            signer.update(msg, off, len);
        }
        return signer.sign();
    }

    private static byte[] signWithRandomSplits(SecureRandom sr, String alg, KeyPair kp, byte[] msg)
        throws Exception
    {
        Signature signer = Signature.getInstance(alg, FIPS);
        signer.initSign(kp.getPrivate());
        int pos = 0;
        while (pos < msg.length)
        {
            int remaining = msg.length - pos;
            int chunk = 1 + sr.nextInt(Math.max(1, remaining));
            chunk = Math.min(chunk, remaining);
            signer.update(msg, pos, chunk);
            pos += chunk;
        }
        return signer.sign();
    }

    private static KeyPair generateRsa()
        throws Exception
    {
        KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA", FIPS);
        rsaKpg.initialize(2048);
        return rsaKpg.generateKeyPair();
    }

    /**
     * Class-level gate: the whole class skips when TEST_FIPS_LIB is unset.
     * Gating here rather than per test method fails closed, so a test added
     * later is gated automatically.
     */
    @BeforeAll
    static void before()
    {
        ensureProviders();
    }

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

    private static KeyPair generate(String curve)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", JostleFIPSProvider.PROVIDER_NAME);
        kpg.initialize(new ECGenParameterSpec(curve));
        return kpg.generateKeyPair();
    }

    @Test
    public void ecdsaAgreesWithBouncyCastle()
        throws Exception
    {
        for (String curve : new String[]{"secp256r1", "secp384r1", "secp521r1"})
        {
            KeyPair kp = generate(curve);
            byte[] message = new byte[1 + RANDOM.nextInt(512)];
            RANDOM.nextBytes(message);

            Signature signer = Signature.getInstance("SHA256withECDSA", JostleFIPSProvider.PROVIDER_NAME);
            signer.initSign(kp.getPrivate());
            signer.update(message);
            byte[] sig = signer.sign();

            Signature bcVerifier = Signature.getInstance("SHA256withECDSA", BouncyCastleProvider.PROVIDER_NAME);
            bcVerifier.initVerify(kp.getPublic());
            bcVerifier.update(message);
            Assertions.assertTrue(bcVerifier.verify(sig), curve + ": JSLFIPS sign -> BC verify");

            // Tamper: must not verify.
            byte[] tampered = message.clone();
            tampered[RANDOM.nextInt(tampered.length)] ^= 0x01;
            Signature fipsVerifier = Signature.getInstance("SHA256withECDSA", JostleFIPSProvider.PROVIDER_NAME);
            fipsVerifier.initVerify(kp.getPublic());
            fipsVerifier.update(tampered);
            Assertions.assertFalse(fipsVerifier.verify(sig), curve + ": tampered message verified");

            // BC sign -> JSLFIPS verify.
            Signature bcSigner = Signature.getInstance("SHA256withECDSA", BouncyCastleProvider.PROVIDER_NAME);
            bcSigner.initSign(kp.getPrivate());
            bcSigner.update(message);
            byte[] bcSig = bcSigner.sign();
            fipsVerifier.initVerify(kp.getPublic());
            fipsVerifier.update(message);
            Assertions.assertTrue(fipsVerifier.verify(bcSig), curve + ": BC sign -> JSLFIPS verify");
        }
    }

    @Test
    public void ecdhSharedSecretsMatchBouncyCastle()
        throws Exception
    {
        KeyPair alice = generate("secp256r1");
        KeyPair bob = generate("secp256r1");

        KeyAgreement fipsKa = KeyAgreement.getInstance("ECDH", JostleFIPSProvider.PROVIDER_NAME);
        fipsKa.init(alice.getPrivate());
        fipsKa.doPhase(bob.getPublic(), true);
        byte[] fipsSecret = fipsKa.generateSecret();

        KeyAgreement bcKa = KeyAgreement.getInstance("ECDH", BouncyCastleProvider.PROVIDER_NAME);
        bcKa.init(bob.getPrivate());
        bcKa.doPhase(alice.getPublic(), true);
        Assertions.assertArrayEquals(fipsSecret, bcKa.generateSecret(),
                "JSLFIPS(alice) and BC(bob) must derive the same secret");

        // Different peer -> different secret.
        KeyPair carol = generate("secp256r1");
        fipsKa.init(alice.getPrivate());
        fipsKa.doPhase(carol.getPublic(), true);
        Assertions.assertFalse(java.util.Arrays.equals(fipsSecret, fipsKa.generateSecret()),
                "different peer produced identical secret");
    }

    @Test
    public void keysRoundTripThroughBouncyCastleEncodings()
        throws Exception
    {
        KeyPair kp = generate("secp256r1");

        KeyFactory bcKf = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        PublicKey bcPub = bcKf.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));

        byte[] message = new byte[128];
        RANDOM.nextBytes(message);
        Signature signer = Signature.getInstance("SHA256withECDSA", JostleFIPSProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());
        signer.update(message);
        byte[] sig = signer.sign();
        Signature bcVer = Signature.getInstance("SHA256withECDSA", BouncyCastleProvider.PROVIDER_NAME);
        bcVer.initVerify(bcPub);
        bcVer.update(message);
        Assertions.assertTrue(bcVer.verify(sig), "BC-decoded public key verifies");

        // BC-encoded keys decode through the JSLFIPS KeyFactory and work.
        KeyFactory fipsKf = KeyFactory.getInstance("EC", JostleFIPSProvider.PROVIDER_NAME);
        PublicKey fipsPub = fipsKf.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
        PrivateKey fipsPriv = fipsKf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        Signature fipsSigner = Signature.getInstance("SHA256withECDSA", JostleFIPSProvider.PROVIDER_NAME);
        fipsSigner.initSign(fipsPriv);
        fipsSigner.update(message);
        byte[] sig2 = fipsSigner.sign();
        Signature fipsVer = Signature.getInstance("SHA256withECDSA", JostleFIPSProvider.PROVIDER_NAME);
        fipsVer.initVerify(fipsPub);
        fipsVer.update(message);
        Assertions.assertTrue(fipsVer.verify(sig2), "JSLFIPS-decoded keys round-trip");
    }

    @Test
    public void curveNotServedByModuleRejected()
        throws Exception
    {
        // secp256k1 is not served by the FIPS module: generation must fail
        // through JSLFIPS while JSL still serves it in the same JVM.
        KeyPairGenerator fipsKpg = KeyPairGenerator.getInstance("EC", JostleFIPSProvider.PROVIDER_NAME);
        Assertions.assertThrows(Exception.class, () ->
        {
            fipsKpg.initialize(new ECGenParameterSpec("secp256k1"));
            fipsKpg.generateKeyPair();
        }, "secp256k1 must be rejected by the FIPS module");

        KeyPairGenerator jslKpg = KeyPairGenerator.getInstance("EC", JostleProvider.PROVIDER_NAME);
        jslKpg.initialize(new ECGenParameterSpec("secp256k1"));
        Assertions.assertNotNull(jslKpg.generateKeyPair(), "JSL still serves secp256k1");
    }

    // -----------------------------------------------------------------
    // Approved-surface lock: every registered ECDSA digest signs+verifies
    // -----------------------------------------------------------------

    /**
     * Mirrors {@code ECDSATest.testEcdsa_AllCurvesAllDigests_roundTrip}
     * for the FIPS surface, minus SHA-1 (sign gated). Each registered
     * ECDSA digest must resolve, self-verify on P-256, and REJECT a
     * tampered message — locks that no approved digest silently drops
     * out of the FIPS provider.
     */
    @Test
    public void allRegisteredEcdsaDigestsRoundTrip()
        throws Exception
    {
        SecureRandom sr = seededRandom("allRegisteredEcdsaDigestsRoundTrip");
        KeyPair kp = generate("P-256");

        for (String alg : DIGEST_ALGS)
        {
            byte[] msg = randomMessage(sr, 128 + sr.nextInt(384));
            byte[] sig = signOneShot(alg, kp, msg);
            Assertions.assertTrue(verify(alg, kp, msg, sig), alg + ": failed self-verification");

            byte[] tampered = Arrays.clone(msg);
            tampered[tampered.length / 2] ^= 0x01;
            Assertions.assertFalse(verify(alg, kp, tampered, sig),
                    alg + ": tampered message verified");
        }
    }

    // -----------------------------------------------------------------
    // Foreign-key rejection (ECDSA sign/verify, ECDH init/doPhase)
    // -----------------------------------------------------------------

    @Test
    public void ecdsaRejectsForeignPublicKey()
        throws Exception
    {
        KeyPair rsa = generateRsa();

        Signature verifier = Signature.getInstance("SHA256withECDSA", FIPS);
        try
        {
            verifier.initVerify(rsa.getPublic());
            Assertions.fail("expected InvalidKeyException for RSA public key");
        }
        catch (InvalidKeyException expected)
        {
            Assertions.assertEquals(
                    "expected an ECPublicKey from the Jostle provider",
                    expected.getMessage());
        }
    }

    @Test
    public void ecdsaRejectsForeignPrivateKey()
        throws Exception
    {
        KeyPair rsa = generateRsa();

        Signature signer = Signature.getInstance("SHA256withECDSA", FIPS);
        try
        {
            signer.initSign(rsa.getPrivate());
            Assertions.fail("expected InvalidKeyException for RSA private key");
        }
        catch (InvalidKeyException expected)
        {
            Assertions.assertEquals(
                    "expected an ECPrivateKey from the Jostle provider",
                    expected.getMessage());
        }
    }

    @Test
    public void ecdhRejectsForeignPrivateKey()
        throws Exception
    {
        PrivateKey rsaPriv = generateRsa().getPrivate();

        KeyAgreement ka = KeyAgreement.getInstance("ECDH", FIPS);
        try
        {
            ka.init(rsaPriv);
            Assertions.fail("ECDH init with RSA private key must throw InvalidKeyException");
        }
        catch (InvalidKeyException expected)
        {
            Assertions.assertEquals("ECDH init: expected an ECPrivateKey",
                    expected.getMessage());
        }
    }

    @Test
    public void ecdhRejectsForeignPublicKey()
        throws Exception
    {
        KeyPair ec = generate("P-256");
        PublicKey rsaPub = generateRsa().getPublic();

        KeyAgreement ka = KeyAgreement.getInstance("ECDH", FIPS);
        ka.init(ec.getPrivate());
        try
        {
            ka.doPhase(rsaPub, true);
            Assertions.fail("ECDH doPhase with RSA public key must throw InvalidKeyException");
        }
        catch (InvalidKeyException expected)
        {
            Assertions.assertEquals("ECDH doPhase: expected an ECPublicKey",
                    expected.getMessage());
        }
    }

    // -----------------------------------------------------------------
    // State-machine guards
    // -----------------------------------------------------------------

    @Test
    public void ecdhStateMachineGuards()
        throws Exception
    {
        KeyPair alice = generate("P-256");
        KeyPair bob = generate("P-256");

        // doPhase before init.
        KeyAgreement ka1 = KeyAgreement.getInstance("ECDH", FIPS);
        try
        {
            ka1.doPhase(alice.getPublic(), true);
            Assertions.fail("doPhase before init must throw");
        }
        catch (IllegalStateException expected)
        {
            Assertions.assertEquals("ECDH KeyAgreement not initialised",
                    expected.getMessage());
        }

        // generateSecret before doPhase.
        KeyAgreement ka2 = KeyAgreement.getInstance("ECDH", FIPS);
        ka2.init(alice.getPrivate());
        try
        {
            ka2.generateSecret();
            Assertions.fail("generateSecret before doPhase must throw");
        }
        catch (IllegalStateException expected)
        {
            Assertions.assertEquals("ECDH: must call doPhase before generateSecret",
                    expected.getMessage());
        }

        // lastPhase=false.
        KeyAgreement ka3 = KeyAgreement.getInstance("ECDH", FIPS);
        ka3.init(alice.getPrivate());
        try
        {
            ka3.doPhase(bob.getPublic(), false);
            Assertions.fail("ECDH is single-phase; lastPhase=false must throw");
        }
        catch (IllegalStateException expected)
        {
            Assertions.assertEquals(
                    "ECDH is a single-phase protocol; lastPhase must be true",
                    expected.getMessage());
        }
    }

    @Test
    public void ecdsaStateMachineGuardsBeforeInit()
        throws Exception
    {
        // update before init.
        Signature s1 = Signature.getInstance("SHA256withECDSA", FIPS);
        try
        {
            s1.update(new byte[]{1, 2, 3});
            Assertions.fail("update before init must throw");
        }
        catch (SignatureException expected)
        {
            Assertions.assertNotNull(expected.getMessage());
            Assertions.assertTrue(expected.getMessage().contains("not initialized"),
                    "unexpected message: " + expected.getMessage());
        }

        // sign before init.
        Signature s2 = Signature.getInstance("SHA256withECDSA", FIPS);
        try
        {
            s2.sign();
            Assertions.fail("sign before init must throw");
        }
        catch (SignatureException expected)
        {
            Assertions.assertNotNull(expected.getMessage());
            Assertions.assertTrue(expected.getMessage().contains("not initialized"),
                    "unexpected message: " + expected.getMessage());
        }

        // verify before init.
        Signature s3 = Signature.getInstance("SHA256withECDSA", FIPS);
        try
        {
            s3.verify(new byte[]{1, 2, 3});
            Assertions.fail("verify before init must throw");
        }
        catch (SignatureException expected)
        {
            Assertions.assertNotNull(expected.getMessage());
            Assertions.assertTrue(expected.getMessage().contains("not initialized"),
                    "unexpected message: " + expected.getMessage());
        }
    }

    // -----------------------------------------------------------------
    // KeyPairGenerator bit-size / spec rejections
    // -----------------------------------------------------------------

    @Test
    public void keyPairGeneratorRejectsUnsupportedBitSizes()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", FIPS);
        for (int bad : new int[]{0, 1, 192, 224, 255, 257, 4096})
        {
            try
            {
                kpg.initialize(bad);
                Assertions.fail("should have rejected key size " + bad);
            }
            catch (InvalidParameterException expected)
            {
                Assertions.assertTrue(expected.getMessage().contains("is not supported"),
                        "expected 'is not supported' for key size " + bad
                                + ", got: " + expected.getMessage());
            }
        }
    }

    @Test
    public void keyPairGeneratorSpecRejections()
        throws Exception
    {
        // null spec.
        KeyPairGenerator kpg1 = KeyPairGenerator.getInstance("EC", FIPS);
        try
        {
            kpg1.initialize((AlgorithmParameterSpec) null);
            Assertions.fail("null spec must be rejected");
        }
        catch (InvalidAlgorithmParameterException expected)
        {
            Assertions.assertEquals("AlgorithmParameterSpec is null",
                    expected.getMessage());
        }

        // foreign anonymous spec.
        KeyPairGenerator kpg2 = KeyPairGenerator.getInstance("EC", FIPS);
        try
        {
            kpg2.initialize(new AlgorithmParameterSpec() {});
            Assertions.fail("foreign spec must be rejected");
        }
        catch (InvalidAlgorithmParameterException expected)
        {
            Assertions.assertTrue(expected.getMessage().contains("ECGenParameterSpec"),
                    "expected ECGenParameterSpec in message, got: " + expected.getMessage());
        }

        // unknown curve name.
        KeyPairGenerator kpg3 = KeyPairGenerator.getInstance("EC", FIPS);
        try
        {
            kpg3.initialize(new ECGenParameterSpec("definitely-not-a-curve"));
            Assertions.fail("unknown curve must be rejected");
        }
        catch (InvalidAlgorithmParameterException expected)
        {
            Assertions.assertTrue(expected.getMessage().contains("not supported"),
                    "expected 'not supported' in message, got: " + expected.getMessage());
        }
    }

    // -----------------------------------------------------------------
    // KeyFactory foreign-spec + raw-component round-trip
    // -----------------------------------------------------------------

    @Test
    public void keyFactoryRejectsForeignSpec()
        throws Exception
    {
        KeyFactory kf = KeyFactory.getInstance("EC", FIPS);

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
            Assertions.assertTrue(expected.getMessage().startsWith("unsupported key spec: "),
                    "unexpected message: " + expected.getMessage());
        }

        try
        {
            kf.generatePrivate(new X509EncodedKeySpec(new byte[16]));
            Assertions.fail("expected InvalidKeySpecException");
        }
        catch (InvalidKeySpecException expected)
        {
            Assertions.assertNotNull(expected.getMessage());
            Assertions.assertTrue(expected.getMessage().startsWith("unsupported key spec: "),
                    "unexpected message: " + expected.getMessage());
        }
    }

    /**
     * Mirrors {@code ECTest.testKeyFactory_ECPublicKeySpec_roundTrip} /
     * {@code _ECPrivateKeySpec_roundTrip} /
     * {@code _ECPublicKeySpec_VerifiesOriginalSignature} /
     * {@code _ECPrivateKeySpec_SignsForOriginalPublic}: raw affine-point
     * and scalar KeySpecs round-trip, and rebuilt halves sign/verify
     * against the original counterpart (exercises the FIPS module's
     * public-point re-derivation). Includes a tampered-message negative.
     */
    @Test
    public void keyFactoryRawComponentSpecRoundTrip()
        throws Exception
    {
        SecureRandom sr = seededRandom("keyFactoryRawComponentSpecRoundTrip");

        for (String curve : new String[]{"P-256", "P-384", "P-521"})
        {
            KeyPair kp = generate(curve);
            KeyFactory kf = KeyFactory.getInstance("EC", FIPS);

            // Public affine-point round-trip.
            ECPublicKey origPub = (ECPublicKey) kp.getPublic();
            ECPublicKeySpec pubSpec = kf.getKeySpec(origPub, ECPublicKeySpec.class);
            Assertions.assertEquals(origPub.getW().getAffineX(), pubSpec.getW().getAffineX(),
                    curve + ": affine X mismatch in extracted ECPublicKeySpec");
            Assertions.assertEquals(origPub.getW().getAffineY(), pubSpec.getW().getAffineY(),
                    curve + ": affine Y mismatch");
            ECPublicKey rebuiltPub = (ECPublicKey) kf.generatePublic(pubSpec);
            Assertions.assertEquals(origPub.getW().getAffineX(), rebuiltPub.getW().getAffineX(),
                    curve + ": affine X mismatch after spec round-trip");

            // Private scalar round-trip.
            ECPrivateKey origPriv = (ECPrivateKey) kp.getPrivate();
            ECPrivateKeySpec privSpec = kf.getKeySpec(origPriv, ECPrivateKeySpec.class);
            Assertions.assertEquals(origPriv.getS(), privSpec.getS(),
                    curve + ": private scalar mismatch in extracted ECPrivateKeySpec");
            ECPrivateKey rebuiltPriv = (ECPrivateKey) kf.generatePrivate(privSpec);
            Assertions.assertEquals(origPriv.getS(), rebuiltPriv.getS(),
                    curve + ": private scalar mismatch after spec round-trip");

            // Rebuilt public verifies a signature from the original private.
            byte[] msg = randomMessage(sr, 16 + sr.nextInt(256));
            Signature signer = Signature.getInstance("SHA256withECDSA", FIPS);
            signer.initSign(kp.getPrivate());
            signer.update(msg);
            byte[] sig = signer.sign();
            Signature verifier = Signature.getInstance("SHA256withECDSA", FIPS);
            verifier.initVerify(rebuiltPub);
            verifier.update(msg);
            Assertions.assertTrue(verifier.verify(sig),
                    curve + ": rebuilt public key did not verify original signature");

            // Rebuilt private signs verifiably against the original public.
            byte[] msg2 = randomMessage(sr, 16 + sr.nextInt(256));
            Signature signer2 = Signature.getInstance("SHA256withECDSA", FIPS);
            signer2.initSign(rebuiltPriv);
            signer2.update(msg2);
            byte[] sig2 = signer2.sign();
            Signature verifier2 = Signature.getInstance("SHA256withECDSA", FIPS);
            verifier2.initVerify(kp.getPublic());
            verifier2.update(msg2);
            Assertions.assertTrue(verifier2.verify(sig2),
                    curve + ": rebuilt private key signature did not verify against original public");

            // Negative: tampered message must not verify.
            byte[] tampered = Arrays.clone(msg2);
            tampered[0] ^= 0x01;
            Signature tv = Signature.getInstance("SHA256withECDSA", FIPS);
            tv.initVerify(kp.getPublic());
            tv.update(tampered);
            Assertions.assertFalse(tv.verify(sig2),
                    curve + ": original public verified a tampered message");
        }
    }

    /**
     * A private key built from {@link ECPrivateKeySpec} must carry a public
     * half under the FIPS provider too: {@code ec_make_private_from_components}
     * computes Q = d·G itself because {@code EVP_PKEY_fromdata} does not
     * derive it from the private scalar — spec-built keys previously had NO
     * public point, so {@code getEncoded()} failed with an i2d error while
     * signing still worked. Pins the fix at the JCE surface: non-null PKCS#8
     * encoding that re-decodes through both the FIPS KeyFactory and
     * BouncyCastle, and a sign/verify round-trip against the original public
     * key. Includes a tampered-message negative. Fresh random keypair per
     * curve trial.
     */
    @Test
    public void keyFactoryPrivateSpecKeyEncodesAndSigns()
        throws Exception
    {
        SecureRandom sr = seededRandom("keyFactoryPrivateSpecKeyEncodesAndSigns");

        for (String curve : new String[]{"P-256", "P-384", "P-521"})
        {
            KeyPair kp = generate(curve);
            KeyFactory kf = KeyFactory.getInstance("EC", FIPS);

            ECPrivateKey origPriv = (ECPrivateKey) kp.getPrivate();
            ECPrivateKeySpec privSpec = kf.getKeySpec(origPriv, ECPrivateKeySpec.class);
            ECPrivateKey specPriv = (ECPrivateKey) kf.generatePrivate(privSpec);

            // getEncoded() must produce a PKCS#8 encoding — this is exactly
            // what failed before the public half was derived.
            byte[] specEncoded = specPriv.getEncoded();
            Assertions.assertNotNull(specEncoded,
                    curve + ": spec-built private key getEncoded() returned null");
            Assertions.assertTrue(specEncoded.length > 0,
                    curve + ": spec-built private key getEncoded() returned empty");

            // Re-decodes through the FIPS KeyFactory with the same scalar...
            ECPrivateKey redecoded = (ECPrivateKey) kf.generatePrivate(
                    new PKCS8EncodedKeySpec(specEncoded));
            Assertions.assertEquals(origPriv.getS(), redecoded.getS(),
                    curve + ": scalar mismatch after PKCS#8 round-trip of spec-built key");

            // ...and through BouncyCastle (the sibling
            // keysRoundTripThroughBouncyCastleEncodings pattern).
            KeyFactory bcKf = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
            ECPrivateKey bcPriv = (ECPrivateKey) bcKf.generatePrivate(
                    new PKCS8EncodedKeySpec(specEncoded));
            Assertions.assertEquals(origPriv.getS(), bcPriv.getS(),
                    curve + ": BC-decoded scalar mismatch for spec-built key");

            // Sign with the spec-built key, verify with the original public —
            // proves the derived public point is d·G for the original scalar.
            byte[] msg = randomMessage(sr, 16 + sr.nextInt(256));
            Signature signer = Signature.getInstance("SHA256withECDSA", FIPS);
            signer.initSign(specPriv);
            signer.update(msg);
            byte[] sig = signer.sign();
            Signature verifier = Signature.getInstance("SHA256withECDSA", FIPS);
            verifier.initVerify(kp.getPublic());
            verifier.update(msg);
            Assertions.assertTrue(verifier.verify(sig),
                    curve + ": spec-built key signature did not verify against original public");

            // Negative: tampered message must not verify.
            byte[] tampered = Arrays.clone(msg);
            tampered[0] ^= 0x01;
            Signature tv = Signature.getInstance("SHA256withECDSA", FIPS);
            tv.initVerify(kp.getPublic());
            tv.update(tampered);
            Assertions.assertFalse(tv.verify(sig),
                    curve + ": original public verified a tampered message from spec-built key");
        }
    }

    // -----------------------------------------------------------------
    // ECDH curve mismatch
    // -----------------------------------------------------------------

    @Test
    public void ecdhCurveMismatchRejected()
        throws Exception
    {
        KeyPair alice = generate("P-256");
        KeyPair bob = generate("P-384");

        KeyAgreement ka = KeyAgreement.getInstance("ECDH", FIPS);
        ka.init(alice.getPrivate());
        try
        {
            ka.doPhase(bob.getPublic(), true);
            Assertions.fail("expected InvalidKeyException for curve mismatch");
        }
        catch (InvalidKeyException expected)
        {
            Assertions.assertEquals(
                    "ECDH doPhase: peer key rejected (curve mismatch?)",
                    expected.getMessage());
        }
    }

    // -----------------------------------------------------------------
    // ECDH generateSecret(byte[],int) buffer contract
    // -----------------------------------------------------------------

    @Test
    public void ecdhGenerateSecretIntoBufferValidation()
        throws Exception
    {
        SecureRandom sr = seededRandom("ecdhGenerateSecretIntoBufferValidation");
        KeyPair alice = generate("P-256");
        KeyPair bob = generate("P-256");

        // Reference secret + length.
        KeyAgreement probe = KeyAgreement.getInstance("ECDH", FIPS);
        probe.init(alice.getPrivate());
        probe.doPhase(bob.getPublic(), true);
        byte[] reference = probe.generateSecret();

        // Positive offset-write: derive into a random-filled oversized
        // buffer at a non-zero offset; prefix must be untouched and the
        // secret region must equal the reference.
        KeyAgreement kaWrite = KeyAgreement.getInstance("ECDH", FIPS);
        kaWrite.init(alice.getPrivate());
        kaWrite.doPhase(bob.getPublic(), true);
        int prefix = 5;
        byte[] big = new byte[reference.length + prefix];
        sr.nextBytes(big);
        byte[] expectedPrefix = new byte[prefix];
        System.arraycopy(big, 0, expectedPrefix, 0, prefix);
        int written = kaWrite.generateSecret(big, prefix);
        Assertions.assertEquals(reference.length, written);
        byte[] actualPrefix = new byte[prefix];
        System.arraycopy(big, 0, actualPrefix, 0, prefix);
        Assertions.assertArrayEquals(expectedPrefix, actualPrefix,
                "ECDH generateSecret(buf, off) modified bytes preceding offset");
        byte[] actualSecret = new byte[reference.length];
        System.arraycopy(big, prefix, actualSecret, 0, reference.length);
        Assertions.assertArrayEquals(reference, actualSecret,
                "ECDH generateSecret(buf, off) wrote a different secret");

        // Short buffer (31 < 32-byte P-256 secret).
        KeyAgreement kaShort = KeyAgreement.getInstance("ECDH", FIPS);
        kaShort.init(alice.getPrivate());
        kaShort.doPhase(bob.getPublic(), true);
        try
        {
            kaShort.generateSecret(new byte[31], 0);
            Assertions.fail("expected ShortBufferException");
        }
        catch (ShortBufferException expected)
        {
            Assertions.assertTrue(
                    expected.getMessage().startsWith("ECDH generateSecret: buffer needs "),
                    "unexpected message: " + expected.getMessage());
        }

        // Null buffer.
        KeyAgreement kaNull = KeyAgreement.getInstance("ECDH", FIPS);
        kaNull.init(alice.getPrivate());
        kaNull.doPhase(bob.getPublic(), true);
        try
        {
            kaNull.generateSecret(null, 0);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("output buffer is null", expected.getMessage());
        }

        // Negative offset.
        KeyAgreement kaNeg = KeyAgreement.getInstance("ECDH", FIPS);
        kaNeg.init(alice.getPrivate());
        kaNeg.doPhase(bob.getPublic(), true);
        try
        {
            kaNeg.generateSecret(new byte[64], -1);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("offset out of range", expected.getMessage());
        }

        // Offset past end (boundary+1: 65 into a 64-byte buffer).
        KeyAgreement kaPast = KeyAgreement.getInstance("ECDH", FIPS);
        kaPast.init(alice.getPrivate());
        kaPast.doPhase(bob.getPublic(), true);
        try
        {
            kaPast.generateSecret(new byte[64], 65);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("offset out of range", expected.getMessage());
        }
    }

    @Test
    public void ecdhGenerateSecretRejectsBlankAlgorithmName()
        throws Exception
    {
        KeyPair alice = generate("P-256");
        KeyPair bob = generate("P-256");

        for (String bad : new String[]{null, "", " ", "    ", "\t\n "})
        {
            KeyAgreement ka = KeyAgreement.getInstance("ECDH", FIPS);
            ka.init(alice.getPrivate());
            ka.doPhase(bob.getPublic(), true);
            try
            {
                ka.generateSecret(bad);
                Assertions.fail("expected NoSuchAlgorithmException for "
                        + (bad == null ? "null" : "\"" + bad + "\""));
            }
            catch (NoSuchAlgorithmException expected)
            {
                Assertions.assertEquals(
                        "algorithm name must be non-null and non-blank",
                        expected.getMessage());
            }
        }
    }

    @Test
    public void ecdhGenerateSecretAsAesKey()
        throws Exception
    {
        KeyPair alice = generate("P-256");
        KeyPair bob = generate("P-256");

        KeyAgreement ka = KeyAgreement.getInstance("ECDH", FIPS);
        ka.init(alice.getPrivate());
        ka.doPhase(bob.getPublic(), true);
        SecretKey key = ka.generateSecret("AES");
        Assertions.assertNotNull(key);
        Assertions.assertEquals("AES", key.getAlgorithm());
        Assertions.assertEquals(32, key.getEncoded().length,
                "P-256 ECDH secret should be 32 bytes");
    }

    @Test
    public void ecdhRejectsAlgorithmParameterSpec()
        throws Exception
    {
        KeyPair kp = generate("P-256");
        KeyAgreement ka = KeyAgreement.getInstance("ECDH", FIPS);
        try
        {
            ka.init(kp.getPrivate(), new AlgorithmParameterSpec() {}, null);
            Assertions.fail("ECDH does not accept AlgorithmParameterSpec");
        }
        catch (InvalidAlgorithmParameterException expected)
        {
            Assertions.assertTrue(
                    expected.getMessage().startsWith("no parameters accepted for ECDH"),
                    "unexpected message: " + expected.getMessage());
        }
    }

    // -----------------------------------------------------------------
    // ECDSA reset / reuse
    // -----------------------------------------------------------------

    @Test
    public void ecdsaSameMessageTwiceSignaturesDiffer()
        throws Exception
    {
        SecureRandom sr = seededRandom("ecdsaSameMessageTwiceSignaturesDiffer");
        KeyPair kp = generate("P-256");
        byte[] msg = randomMessage(sr, 64);

        Signature signer = Signature.getInstance("SHA256withECDSA", FIPS);
        signer.initSign(kp.getPrivate());
        signer.update(msg);
        byte[] sigA = signer.sign();
        signer.update(msg);
        byte[] sigB = signer.sign();

        Assertions.assertFalse(Arrays.areEqual(sigA, sigB),
                "two ECDSA signatures over the same message must differ "
                        + "(non-determinism) — equal output suggests cached k");
        Assertions.assertTrue(verify("SHA256withECDSA", kp, msg, sigA));
        Assertions.assertTrue(verify("SHA256withECDSA", kp, msg, sigB));
    }

    /**
     * Mirrors {@code ECDSATest} reset patterns 4/5/6: a failed verify
     * must not poison the instance; a prior pass must not echo into a
     * later tampered verify; and an initSign→sign→initVerify→verify→
     * initSign role-flip works on a single instance.
     */
    @Test
    public void ecdsaResetReuseSequences()
        throws Exception
    {
        SecureRandom sr = seededRandom("ecdsaResetReuseSequences");
        KeyPair kp = generate("P-256");

        // (1) Negative-then-positive: tampered verify then clean verify.
        byte[] msgA = randomMessage(sr, 64);
        byte[] msgB = randomMessage(sr, 96);
        Signature signer = Signature.getInstance("SHA256withECDSA", FIPS);
        signer.initSign(kp.getPrivate());
        signer.update(msgB);
        byte[] sigB = signer.sign();
        byte[] sigBTampered = Arrays.clone(sigB);
        sigBTampered[sigBTampered.length - 1] ^= 0x01;

        Signature verifier = Signature.getInstance("SHA256withECDSA", FIPS);
        verifier.initVerify(kp.getPublic());
        verifier.update(msgB);
        boolean firstVerify;
        try
        {
            firstVerify = verifier.verify(sigBTampered);
        }
        catch (SignatureException expected)
        {
            firstVerify = false;
        }
        Assertions.assertFalse(firstVerify, "tampered signature must not verify");

        verifier.update(msgB);
        Assertions.assertTrue(verifier.verify(sigB),
                "good signature must verify after a previous-fail verify");

        signer.update(msgA);
        byte[] sigA = signer.sign();
        verifier.update(msgA);
        Assertions.assertTrue(verifier.verify(sigA));

        // (2) Positive-then-negative: a prior pass must not leak.
        byte[] msg = randomMessage(sr, 64);
        Signature s2 = Signature.getInstance("SHA256withECDSA", FIPS);
        s2.initSign(kp.getPrivate());
        s2.update(msg);
        byte[] sig = s2.sign();
        byte[] tampered = Arrays.clone(sig);
        tampered[tampered.length - 1] ^= 0x01;

        Signature v2 = Signature.getInstance("SHA256withECDSA", FIPS);
        v2.initVerify(kp.getPublic());
        v2.update(msg);
        Assertions.assertTrue(v2.verify(sig), "first verify should pass");
        v2.update(msg);
        boolean cached;
        try
        {
            cached = v2.verify(tampered);
        }
        catch (SignatureException expected)
        {
            cached = false;
        }
        Assertions.assertFalse(cached, "previous-pass result leaked into next call");

        // (3) Role-flip on a single instance.
        byte[] msgC = randomMessage(sr, 48);
        Signature roleFlip = Signature.getInstance("SHA256withECDSA", FIPS);
        roleFlip.initSign(kp.getPrivate());
        roleFlip.update(msgC);
        byte[] rf = roleFlip.sign();
        roleFlip.initVerify(kp.getPublic());
        roleFlip.update(msgC);
        Assertions.assertTrue(roleFlip.verify(rf),
                "verify on a Signature previously used to sign must succeed");
        roleFlip.initSign(kp.getPrivate());
        roleFlip.update(msgC);
        byte[] rf2 = roleFlip.sign();
        Assertions.assertFalse(Arrays.areEqual(rf, rf2),
                "fresh ECDSA sign on the same instance must produce a different signature");
        roleFlip.initVerify(kp.getPublic());
        roleFlip.update(msgC);
        Assertions.assertTrue(roleFlip.verify(rf2));
    }

    // -----------------------------------------------------------------
    // ECDSA JCE-level offset-write
    // -----------------------------------------------------------------

    @Test
    public void ecdsaSignWritesAtOffsetWithoutClobberingPrefix_jce()
        throws Exception
    {
        SecureRandom sr = seededRandom("ecdsaSignWritesAtOffsetWithoutClobberingPrefix_jce");
        KeyPair kp = generate("P-256");
        byte[] msg = randomMessage(sr, 64);

        // Probe the upper-bound length first.
        Signature probe = Signature.getInstance("SHA256withECDSA", FIPS);
        probe.initSign(kp.getPrivate());
        probe.update(msg);
        int upperBound = probe.sign().length;

        int prefix = 7;
        int capacity = upperBound + 8;
        byte[] big = new byte[prefix + capacity];
        sr.nextBytes(big);
        byte[] expectedPrefix = new byte[prefix];
        System.arraycopy(big, 0, expectedPrefix, 0, prefix);

        Signature signer = Signature.getInstance("SHA256withECDSA", FIPS);
        signer.initSign(kp.getPrivate());
        signer.update(msg);
        int written = signer.sign(big, prefix, capacity);

        // (1) Prefix untouched.
        byte[] actualPrefix = new byte[prefix];
        System.arraycopy(big, 0, actualPrefix, 0, prefix);
        Assertions.assertArrayEquals(expectedPrefix, actualPrefix,
                "prefix bytes were modified by Signature.sign(out, offset, len)");

        // (2) The written window verifies against the original message.
        byte[] sigFromBig = new byte[written];
        System.arraycopy(big, prefix, sigFromBig, 0, written);
        Signature verifier = Signature.getInstance("SHA256withECDSA", FIPS);
        verifier.initVerify(kp.getPublic());
        verifier.update(msg);
        Assertions.assertTrue(verifier.verify(sigFromBig),
                "signature at offset " + prefix + " did not verify against the original message");

        // (3) A window shifted one byte earlier must NOT verify.
        byte[] shiftedSig = new byte[written];
        System.arraycopy(big, prefix - 1, shiftedSig, 0, written);
        verifier.initVerify(kp.getPublic());
        verifier.update(msg);
        boolean shiftedVerified;
        try
        {
            shiftedVerified = verifier.verify(shiftedSig);
        }
        catch (SignatureException expected)
        {
            shiftedVerified = false;
        }
        catch (RuntimeException expected)
        {
            // OpenSSL surfaces structural DER-parse errors as
            // OpenSSLException (a RuntimeException); also a correct rejection.
            shiftedVerified = false;
        }
        Assertions.assertFalse(shiftedVerified,
                "signature window shifted by 1 byte INTO the prefix verified successfully "
                        + "— sign() wrote at outOff-1 instead of at outOff=" + prefix);
    }

    // -----------------------------------------------------------------
    // ECDSA chunking parity
    // -----------------------------------------------------------------

    @Test
    public void ecdsaChunkingMatrixAllVerify()
        throws Exception
    {
        SecureRandom sr = seededRandom("ecdsaChunkingMatrixAllVerify");
        KeyPair kp = generate("P-256");
        byte[] msg = randomMessage(sr, 1024);

        Assertions.assertTrue(verify("SHA256withECDSA", kp, msg,
                signOneShot("SHA256withECDSA", kp, msg)), "one-shot signature did not verify");

        Assertions.assertTrue(verify("SHA256withECDSA", kp, msg,
                signWithChunking("SHA256withECDSA", kp, msg, 1)), "byte-by-byte did not verify");

        for (int chunk : new int[]{63, 64, 65, 127, 128, 129})
        {
            Assertions.assertTrue(
                    verify("SHA256withECDSA", kp, msg,
                            signWithChunking("SHA256withECDSA", kp, msg, chunk)),
                    "chunk=" + chunk + ": chunked-signed signature did not verify");
        }

        for (int trial = 0; trial < 5; trial++)
        {
            Assertions.assertTrue(
                    verify("SHA256withECDSA", kp, msg,
                            signWithRandomSplits(sr, "SHA256withECDSA", kp, msg)),
                    "random-split signed signature did not verify");
        }
    }

    // -----------------------------------------------------------------
    // OID resolution
    // -----------------------------------------------------------------

    /**
     * The registered ECDSA and EC-key OIDs must resolve through JSLFIPS.
     * Cross-verifies an OID-obtained signer against the named-alg
     * verifier. ProvFIPSEC registers no OID alias for ECDH or
     * AlgorithmParameters, so those are deliberately not exercised here.
     */
    @Test
    public void resolvesByRegisteredOids()
        throws Exception
    {
        SecureRandom sr = seededRandom("resolvesByRegisteredOids");
        KeyPair kp = generate("P-256");
        byte[] msg = randomMessage(sr, 64);

        // ecdsa-with-SHA256 = 1.2.840.10045.4.3.2.
        Signature s256 = Signature.getInstance("1.2.840.10045.4.3.2", FIPS);
        s256.initSign(kp.getPrivate());
        s256.update(msg);
        Assertions.assertTrue(verify("SHA256withECDSA", kp, msg, s256.sign()),
                "OID-obtained SHA-256 signer did not cross-verify against the named alg");

        // ecdsa-with-SHA3-256 = 2.16.840.1.101.3.4.3.10.
        Signature s3 = Signature.getInstance("2.16.840.1.101.3.4.3.10", FIPS);
        s3.initSign(kp.getPrivate());
        s3.update(msg);
        Assertions.assertTrue(verify("SHA3-256withECDSA", kp, msg, s3.sign()),
                "OID-obtained SHA3-256 signer did not cross-verify against the named alg");

        // id-ecPublicKey = 1.2.840.10045.2.1.
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("1.2.840.10045.2.1", FIPS);
        kpg.initialize(new ECGenParameterSpec("P-256"));
        Assertions.assertTrue(kpg.generateKeyPair().getPublic() instanceof ECPublicKey);
        Assertions.assertNotNull(KeyFactory.getInstance("1.2.840.10045.2.1", FIPS));
    }

    // -----------------------------------------------------------------
    // AlgorithmParameters("EC")
    // -----------------------------------------------------------------

    @Test
    public void algorithmParametersEcResolvesAndRoundTrips()
        throws Exception
    {
        AlgorithmParameters ap = AlgorithmParameters.getInstance("EC", FIPS);
        ap.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec spec = ap.getParameterSpec(ECParameterSpec.class);
        Assertions.assertEquals(256, spec.getCurve().getField().getFieldSize(),
                "AlgorithmParameters(\"EC\") did not yield P-256 parameters");

        byte[] encoded = ap.getEncoded();
        Assertions.assertNotNull(encoded);
        AlgorithmParameters ap2 = AlgorithmParameters.getInstance("EC", FIPS);
        ap2.init(encoded);
        ECParameterSpec spec2 = ap2.getParameterSpec(ECParameterSpec.class);
        Assertions.assertEquals(256, spec2.getCurve().getField().getFieldSize());
        Assertions.assertArrayEquals(encoded, ap2.getEncoded(),
                "EC AlgorithmParameters encode/decode round-trip changed bytes");
    }

    // -----------------------------------------------------------------
    // Tampered signature
    // -----------------------------------------------------------------

    @Test
    public void ecdsaTamperedSignatureDoesNotVerify()
        throws Exception
    {
        SecureRandom sr = seededRandom("ecdsaTamperedSignatureDoesNotVerify");
        KeyPair kp = generate("P-256");
        byte[] msg = randomMessage(sr, 256);

        byte[] sig = signOneShot("SHA256withECDSA", kp, msg);
        byte[] tampered = Arrays.clone(sig);
        tampered[tampered.length - 1] ^= 0x01;

        Signature verifier = Signature.getInstance("SHA256withECDSA", FIPS);
        verifier.initVerify(kp.getPublic());
        verifier.update(msg);
        boolean verified;
        try
        {
            verified = verifier.verify(tampered);
        }
        catch (SignatureException expected)
        {
            verified = false;
        }
        Assertions.assertFalse(verified, "tampered signature must not verify");
    }

    // -----------------------------------------------------------------
    // ECDSA parameter overloads unsupported
    // -----------------------------------------------------------------

    @Test
    public void ecdsaParameterOverloadsUnsupported()
        throws Exception
    {
        Signature s1 = Signature.getInstance("SHA256withECDSA", FIPS);
        try
        {
            s1.setParameter("anything", new Object());
            Assertions.fail("expected UnsupportedOperationException");
        }
        catch (UnsupportedOperationException expected)
        {
            Assertions.assertNull(expected.getMessage());
        }
        catch (InvalidParameterException expected)
        {
            // Defensive backup: a JCE that wraps the SPI's UOE in an IPE.
            Assertions.assertNotNull(expected);
        }

        Signature s2 = Signature.getInstance("SHA256withECDSA", FIPS);
        try
        {
            s2.getParameter("anything");
            Assertions.fail("expected UnsupportedOperationException");
        }
        catch (UnsupportedOperationException expected)
        {
            Assertions.assertNull(expected.getMessage());
        }
        catch (InvalidParameterException expected)
        {
            Assertions.assertNotNull(expected);
        }
    }

    // -----------------------------------------------------------------
    // Unapproved-curve rejection (tightened, typed + message-pinned)
    // -----------------------------------------------------------------

    /**
     * Tightened companion to {@link #curveNotServedByModuleRejected()}: the
     * secp256k1 rejection through JSLFIPS must be the specific typed
     * exception the module refusal produces — {@link InvalidAlgorithmParameterException}
     * at {@code initialize()}, whose message names the unavailable curve —
     * proving the gate is the FIPS module (the curve is not present in the
     * FIPS {@code OSSL_LIB_CTX}) and not an incidental throwable. Keeps the
     * JSL-still-serves-secp256k1 counter-assert.
     */
    @Test
    public void curveNotServedByModule_typedAndMessagePinned()
        throws Exception
    {
        // secp256k1 is not an approved curve and is absent from the FIPS
        // lib ctx: the refusal surfaces at initialize() as a typed
        // InvalidAlgorithmParameterException naming the curve.
        KeyPairGenerator fipsKpg = KeyPairGenerator.getInstance("EC", FIPS);
        InvalidAlgorithmParameterException ex = Assertions.assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> fipsKpg.initialize(new ECGenParameterSpec("secp256k1")),
                "secp256k1 must be rejected by the FIPS module at initialize");
        String msg = String.valueOf(ex.getMessage());
        Assertions.assertTrue(msg.contains("secp256k1") && msg.contains("not supported"),
                "expected a curve-not-supported rejection naming secp256k1, got: " + msg);

        // JSL still serves secp256k1 in the same JVM.
        KeyPairGenerator jslKpg = KeyPairGenerator.getInstance("EC", JSL);
        jslKpg.initialize(new ECGenParameterSpec("secp256k1"));
        Assertions.assertNotNull(jslKpg.generateKeyPair(), "JSL still serves secp256k1");
    }

    /**
     * The ECDH and ECDHwithSHAnnnKDF KeyAgreements must resolve by their scheme
     * OID through JSLFIPS (the CMS/PKIX KeyAgreeRecipientInfo path), not just by
     * name — mirroring the non-FIPS ProvEC surface. Regression lock for the
     * ProvFIPSEC OID-alias fix (the by-name agreement tests do not exercise the
     * OID lookup, so this is the guard that catches a dropped alias).
     */
    @Test
    public void ecdhAgreementOidAliasesResolve()
        throws Exception
    {
        String[][] nameToOid = {
                {"ECDH", "1.3.132.1.12"},
                {"ECDHWITHSHA1KDF", "1.3.133.16.840.63.0.2"},
                {"ECDHWITHSHA224KDF", "1.3.132.1.11.0"},
                {"ECDHWITHSHA256KDF", "1.3.132.1.11.1"},
                {"ECDHWITHSHA384KDF", "1.3.132.1.11.2"},
                {"ECDHWITHSHA512KDF", "1.3.132.1.11.3"},
        };
        for (String[] no : nameToOid)
        {
            // Both the name and the OID must resolve to a JSLFIPS service.
            Assertions.assertNotNull(KeyAgreement.getInstance(no[0], FIPS),
                    no[0] + " must resolve by name");
            Assertions.assertNotNull(KeyAgreement.getInstance(no[1], FIPS),
                    no[0] + " must resolve by OID " + no[1]);
        }
    }

    /**
     * NoneWithECDSA is served by JSLFIPS in BOTH directions, and signs the
     * caller-supplied digest directly.
     *
     * <p>Cross-checking against SHA256withECDSA is what proves no extra hashing
     * happens: a raw signature over H = SHA-256(m) must verify under the full
     * verifier on m, and vice versa. A roundtrip alone would pass even if the
     * engine re-hashed.
     *
     * <p>Both directions are served because the module performs both. Cert #4985
     * approves the SigGen Component and lists the SigVer Component as
     * non-approved (Table 8, §4.4 Table 13); that is a compliance determination
     * for the operator, not a capability this provider withholds.
     */
    @Test
    public void noneWithECDSA_servedBothDirectionsOverSuppliedDigest() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", FIPS);
        kpg.initialize(new ECGenParameterSpec("P-256"));
        KeyPair kp = kpg.generateKeyPair();

        SecureRandom sr = seededRandom("noneWithECDSA_servedBothDirectionsOverSuppliedDigest");
        byte[] msg = new byte[1 + sr.nextInt(512)];
        sr.nextBytes(msg);
        byte[] hash = java.security.MessageDigest.getInstance("SHA-256", FIPS).digest(msg);

        Signature none = Signature.getInstance("NoneWithECDSA", FIPS);
        none.initSign(kp.getPrivate());
        none.update(hash);
        byte[] rawSig = none.sign();

        // raw-sign(H) verifies under the hashed verifier on m
        Signature full = Signature.getInstance("SHA256withECDSA", FIPS);
        full.initVerify(kp.getPublic());
        full.update(msg);
        Assertions.assertTrue(full.verify(rawSig),
                "SHA256withECDSA did not verify a NoneWithECDSA signature over SHA-256(m)");

        // and raw VERIFY works — the direction previously withheld
        Signature rawVerify = Signature.getInstance("NoneWithECDSA", FIPS);
        rawVerify.initVerify(kp.getPublic());
        rawVerify.update(hash);
        Assertions.assertTrue(rawVerify.verify(rawSig), "raw ECDSA verification must be served");

        // Negative: a tampered digest must not verify through the raw path.
        byte[] tampered = Arrays.clone(hash);
        tampered[0] ^= 0x01;
        Signature bad = Signature.getInstance("NoneWithECDSA", FIPS);
        bad.initVerify(kp.getPublic());
        bad.update(tampered);
        Assertions.assertFalse(bad.verify(rawSig), "tampered digest must not verify");

        // Cross-provider: a JSLFIPS raw signature verifies on JSL.
        Signature jslVerify = Signature.getInstance("NoneWithECDSA", JostleProvider.PROVIDER_NAME);
        jslVerify.initVerify(kp.getPublic());
        jslVerify.update(hash);
        Assertions.assertTrue(jslVerify.verify(rawSig), "JSL did not verify a JSLFIPS raw signature");
    }
}
