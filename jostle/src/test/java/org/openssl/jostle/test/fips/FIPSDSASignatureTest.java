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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.util.Arrays;

import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Behaviour-lock tests for the DSA Signature / KeyPairGenerator / KeyFactory
 * surface through the FIPS provider ("JSLFIPS").
 *
 * <p>The DSA SPI classes are SHARED between the base ("JSL") and FIPS
 * providers ({@code DSASignatureSpi}, {@code DSAKeyPairGenerator},
 * {@code DSAKeyFactorySpi}), so the JCE-contract behaviours mirrored here
 * (foreign-key rejection, pre-init state guards, reset/reuse, KPG size
 * rejection, KeyFactory foreign/malformed rejection, OID/alias resolution)
 * surface with the same exception types and messages as the non-FIPS
 * {@code DSASignatureTest} / {@code DSATest}; only the provider name and the
 * key origin change. Keys used for operational tests are generated through the
 * FIPS provider (JSLFIPS and JSL private keys are provider-isolated).
 *
 * <p>The one FIPS-unique lock is {@code NoneWithDSA}: the raw signature path
 * is registered, and this test pins whichever behaviour the module currently
 * exhibits (functional round-trip, or a typed {@link OpenSSLException}
 * refusal) so a future drift is caught.
 *
 * <p>Gated on {@code TEST_FIPS_LIB}; skipped when unset.
 */
public class FIPSDSASignatureTest
{
    private static final String FIPS = JostleFIPSProvider.PROVIDER_NAME;

    private static final SecureRandom RANDOM = new SecureRandom();

    private static SecureRandom seededRandom(String testName) throws Exception
    {
        long seed = RANDOM.nextLong();
        System.out.println(testName + " seed=" + seed);
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        return sr;
    }

    private static KeyPair generateDsaKeyPair() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA", FIPS);
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private static KeyPair generateRsaKeyPair() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", FIPS);
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private static byte[] randomMessage(SecureRandom sr, int len)
    {
        byte[] msg = new byte[len];
        sr.nextBytes(msg);
        return msg;
    }

    private static byte[] signOneShot(String alg, KeyPair kp, byte[] msg) throws Exception
    {
        Signature signer = Signature.getInstance(alg, FIPS);
        signer.initSign(kp.getPrivate());
        signer.update(msg);
        return signer.sign();
    }

    private static boolean verify(String alg, KeyPair kp, byte[] msg, byte[] sig) throws Exception
    {
        Signature verifier = Signature.getInstance(alg, FIPS);
        verifier.initVerify(kp.getPublic());
        verifier.update(msg);
        return verifier.verify(sig);
    }


    // -----------------------------------------------------------------
    // Foreign-key rejection (provider-fallback contract)
    // -----------------------------------------------------------------

    /**
     * Class-level gate: the whole class skips when TEST_FIPS_LIB is unset.
     * Gating here rather than per test method fails closed, so a test added
     * later is gated automatically.
     */
    @BeforeAll
    static void before()
    {
        FIPSTestUtil.assumeFipsProvider();
    }

    /**
     * An RSA key handed to a DSA Signature on JSLFIPS must be rejected with
     * {@link InvalidKeyException} — the type JCE relies on for provider-chain
     * fallback. Mirrors {@code DSASignatureTest.testDsa_RejectsForeignPublicKey}
     * / {@code _RejectsForeignPrivateKey}. Shared SPI, so the messages match.
     */
    @Test
    public void dsaSignatureRejectsForeignKey_throwsInvalidKeyException() throws Exception
    {
        KeyPair rsa = generateRsaKeyPair();

        Signature verifier = Signature.getInstance("SHA256withDSA", FIPS);
        try
        {
            verifier.initVerify(rsa.getPublic());
            Assertions.fail("expected InvalidKeyException for RSA public key");
        }
        catch (InvalidKeyException expected)
        {
            Assertions.assertEquals(
                    "expected a DSAPublicKey from the Jostle provider",
                    expected.getMessage());
        }

        Signature signer = Signature.getInstance("SHA256withDSA", FIPS);
        try
        {
            signer.initSign(rsa.getPrivate());
            Assertions.fail("expected InvalidKeyException for RSA private key");
        }
        catch (InvalidKeyException expected)
        {
            Assertions.assertEquals(
                    "expected a DSAPrivateKey from the Jostle provider",
                    expected.getMessage());
        }
    }


    // -----------------------------------------------------------------
    // SPI state-machine guards (update/sign/verify before init)
    // -----------------------------------------------------------------

    /**
     * update / sign / verify before init must throw {@link java.security.SignatureException}
     * whose message contains "not initialized". Mirrors
     * {@code DSASignatureTest.testDsa_UpdateBeforeInit_isIllegalState} /
     * {@code _SignBeforeInit} / {@code _VerifyBeforeInit}. No keypair needed.
     */
    @Test
    public void dsaSignatureBeforeInit_throwsSignatureException() throws Exception
    {
        Signature updater = Signature.getInstance("SHA256withDSA", FIPS);
        try
        {
            updater.update(new byte[]{1, 2, 3});
            Assertions.fail("update before init must throw");
        }
        catch (java.security.SignatureException expected)
        {
            Assertions.assertNotNull(expected.getMessage());
            Assertions.assertTrue(
                    expected.getMessage().contains("not initialized"),
                    "unexpected message: " + expected.getMessage());
        }

        Signature signer = Signature.getInstance("SHA256withDSA", FIPS);
        try
        {
            signer.sign();
            Assertions.fail("sign before init must throw");
        }
        catch (java.security.SignatureException expected)
        {
            Assertions.assertNotNull(expected.getMessage());
            Assertions.assertTrue(
                    expected.getMessage().contains("not initialized"),
                    "unexpected message: " + expected.getMessage());
        }

        Signature verifier = Signature.getInstance("SHA256withDSA", FIPS);
        try
        {
            verifier.verify(new byte[]{1, 2, 3});
            Assertions.fail("verify before init must throw");
        }
        catch (java.security.SignatureException expected)
        {
            Assertions.assertNotNull(expected.getMessage());
            Assertions.assertTrue(
                    expected.getMessage().contains("not initialized"),
                    "unexpected message: " + expected.getMessage());
        }
    }


    // -----------------------------------------------------------------
    // Reset / reuse (non-determinism, neg-then-pos, pos-then-neg, role-flip)
    // -----------------------------------------------------------------

    /**
     * One JSLFIPS Signature instance driven through the reInit-after-terminal
     * path: two signs over the same message differ (fresh k), a failed verify
     * does not poison a following good verify, a passed verify does not leak
     * into a following tampered verify, and initSign -> sign -> initVerify ->
     * verify -> initSign all succeed. Mirrors
     * {@code DSASignatureTest.testDsa_SameMessageTwice_signaturesDiffer} /
     * {@code _NegativeThenPositive} / {@code _PositiveThenNegative} /
     * {@code _RoleFlip}.
     */
    @Test
    public void dsaSignatureResetReuse_sameMessageDiffers_and_failureDoesNotPoisonState() throws Exception
    {
        SecureRandom sr = seededRandom(
                "dsaSignatureResetReuse_sameMessageDiffers_and_failureDoesNotPoisonState");
        KeyPair kp = generateDsaKeyPair();
        byte[] msg = randomMessage(sr, 64);

        // (2) Same message twice on one instance -> DSA non-determinism.
        Signature signer = Signature.getInstance("SHA256withDSA", FIPS);
        signer.initSign(kp.getPrivate());
        signer.update(msg);
        byte[] sigA = signer.sign();
        signer.update(msg);
        byte[] sigB = signer.sign();
        Assertions.assertFalse(Arrays.areEqual(sigA, sigB),
                "two DSA signatures over the same message must differ "
                        + "(non-determinism) — equal output suggests cached k");
        Assertions.assertTrue(verify("SHA256withDSA", kp, msg, sigA), "sigA must verify");
        Assertions.assertTrue(verify("SHA256withDSA", kp, msg, sigB), "sigB must verify");

        // (4) Negative-then-positive: a failed verify must not poison state.
        byte[] tampered = Arrays.clone(sigA);
        tampered[tampered.length - 1] ^= 0x01;
        Signature verifier = Signature.getInstance("SHA256withDSA", FIPS);
        verifier.initVerify(kp.getPublic());
        verifier.update(msg);
        boolean firstVerify;
        try
        {
            firstVerify = verifier.verify(tampered);
        }
        catch (java.security.SignatureException expected)
        {
            firstVerify = false;
        }
        Assertions.assertFalse(firstVerify, "tampered signature must not verify");
        verifier.update(msg);
        Assertions.assertTrue(verifier.verify(sigA),
                "good signature must verify after a previous-fail verify "
                        + "(reInit must clear residual state)");

        // (5) Positive-then-negative: a prior pass must not leak into the next call.
        verifier.update(msg);
        Assertions.assertTrue(verifier.verify(sigB), "clean verify should pass");
        verifier.update(msg);
        boolean cached;
        try
        {
            cached = verifier.verify(tampered);
        }
        catch (java.security.SignatureException expected)
        {
            cached = false;
        }
        Assertions.assertFalse(cached, "previous-pass result leaked into next call");

        // (6) Role-flip on a single instance: sign -> verify -> sign.
        Signature flip = Signature.getInstance("SHA256withDSA", FIPS);
        flip.initSign(kp.getPrivate());
        flip.update(msg);
        byte[] s = flip.sign();
        flip.initVerify(kp.getPublic());
        flip.update(msg);
        Assertions.assertTrue(flip.verify(s),
                "verify on a Signature previously used to sign must succeed");
        flip.initSign(kp.getPrivate());
        flip.update(msg);
        byte[] s2 = flip.sign();
        Assertions.assertFalse(Arrays.areEqual(s, s2),
                "fresh DSA sign on the same instance must produce a different signature");
        flip.initVerify(kp.getPublic());
        flip.update(msg);
        Assertions.assertTrue(flip.verify(s2));
    }


    // -----------------------------------------------------------------
    // KeyPairGenerator size rejection
    // -----------------------------------------------------------------

    /**
     * {@code KeyPairGenerator.getInstance("DSA", JSLFIPS).initialize(size)}
     * rejects sizes outside the supported set with {@link InvalidParameterException}
     * at the JCE boundary. Mirrors {@code DSATest.testKeyPairGen_invalidSize_rejected}.
     * The shared {@code DSAKeyPairGenerator} accepts {1024, 2048, 3072}; 1024 is
     * deliberately excluded from the reject probes.
     */
    @Test
    public void dsaKeyPairGeneratorRejectsInvalidSize() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA", FIPS);
        for (int size : new int[]{0, 512, 1023, 1025, 2047, 2049, 3071, 3073, 4096})
        {
            try
            {
                kpg.initialize(size);
                Assertions.fail("expected InvalidParameterException for size " + size);
            }
            catch (InvalidParameterException expected)
            {
                Assertions.assertTrue(
                        expected.getMessage().contains("DSA key size " + size),
                        "unexpected message: " + expected.getMessage());
            }
        }
    }


    // -----------------------------------------------------------------
    // KeyFactory foreign-algorithm / malformed-DER rejection
    // -----------------------------------------------------------------

    /**
     * An RSA SPKI handed to the JSLFIPS DSA KeyFactory throws
     * {@link InvalidKeySpecException} naming the mismatch; garbage / truncated
     * DER throws {@link InvalidKeySpecException} (not an unchecked
     * {@code OpenSSLException}). Mirrors
     * {@code DSATest.testKeyFactory_rejectsForeignAlgorithmEncoding} /
     * {@code _malformedDer_rejected}. RSA key origin is JSLFIPS.
     */
    @Test
    public void keyFactoryRejectsForeignAlgorithmAndMalformedDer() throws Exception
    {
        SecureRandom sr = seededRandom("keyFactoryRejectsForeignAlgorithmAndMalformedDer");
        KeyFactory kf = KeyFactory.getInstance("DSA", FIPS);

        // Foreign algorithm: RSA SPKI.
        KeyPair rsa = generateRsaKeyPair();
        try
        {
            kf.generatePublic(new X509EncodedKeySpec(rsa.getPublic().getEncoded()));
            Assertions.fail("expected InvalidKeySpecException");
        }
        catch (InvalidKeySpecException expected)
        {
            Assertions.assertEquals("expected DSA key but got RSA", expected.getMessage());
        }

        // Malformed DER: garbage + a SEQUENCE header claiming 1024 bytes.
        byte[] garbage = new byte[40];
        sr.nextBytes(garbage);
        byte[] truncated = {0x30, (byte) 0x82, 0x04, 0x00, 0x02, 0x01, 0x00};

        for (byte[] bad : new byte[][]{garbage, truncated})
        {
            InvalidKeySpecException pub = Assertions.assertThrows(InvalidKeySpecException.class,
                    () -> kf.generatePublic(new X509EncodedKeySpec(bad)),
                    "malformed SPKI must throw InvalidKeySpecException");
            Assertions.assertTrue(pub.getMessage().startsWith("unable to decode DSA public key"),
                    "unexpected message: " + pub.getMessage());

            InvalidKeySpecException priv = Assertions.assertThrows(InvalidKeySpecException.class,
                    () -> kf.generatePrivate(new PKCS8EncodedKeySpec(bad)),
                    "malformed PKCS#8 must throw InvalidKeySpecException");
            Assertions.assertTrue(priv.getMessage().startsWith("unable to decode DSA private key"),
                    "unexpected message: " + priv.getMessage());
        }
    }


    // -----------------------------------------------------------------
    // NoneWithDSA raw-signature surface — current-behaviour lock
    // -----------------------------------------------------------------

    /**
     * {@code ProvFIPSDSA} registers {@code NoneWithDSA}. Unlike the RSA raw
     * path (which fetches an absent {@code NONE} digest and is refused — see
     * {@code FIPSRSANoneWithRSASignatureTest}), the DSA raw path drives
     * {@code EVP_PKEY_sign} / {@code EVP_PKEY_verify} directly with no digest
     * fetch, so whether the FIPS module services it is not determinable from
     * the Java side. This test <b>detects and locks whichever behaviour the
     * module currently exhibits</b>:
     * <ol>
     *   <li>functional — the raw signature over a SHA-256 digest verifies, and
     *       a tampered digest does not (round-trip + tamper differentiator);</li>
     *   <li>refused — a typed {@link OpenSSLException} whose message reports a
     *       module error.</li>
     * </ol>
     * Mirrors {@code DSANoneWithDSASignatureTest.testNoneWithDsa_signRaw_verifyWithDigestAlgorithm}
     * / {@code _TamperedDigest_doesNotVerify} on the functional branch.
     */
    @Test
    public void noneWithDsaRawSignature_currentBehaviorLocked() throws Exception
    {
        SecureRandom sr = seededRandom("noneWithDsaRawSignature_currentBehaviorLocked");
        KeyPair kp = generateDsaKeyPair();

        byte[] msg = randomMessage(sr, 200 + sr.nextInt(300));
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(msg);

        // Registered: resolution must succeed regardless of module policy.
        Signature rawSigner = Signature.getInstance("NoneWithDSA", FIPS);
        Assertions.assertNotNull(rawSigner, "NoneWithDSA must remain registered in JSLFIPS");

        byte[] sig;
        try
        {
            rawSigner.initSign(kp.getPrivate());
            rawSigner.update(digest);
            sig = rawSigner.sign();
        }
        catch (OpenSSLException refused)
        {
            // Refusal branch: the module declined the raw operation. Lock the
            // typed rejection (same shape as the SHA-1 / NoneWithRSA gates).
            String rm = String.valueOf(refused.getMessage());
            Assertions.assertTrue(rm.startsWith("OpenSSL Error:"),
                    "expected an OpenSSL module rejection, got: " + rm);
            return;
        }

        // Functional branch: raw signature must verify over the same digest...
        Signature rawVerifier = Signature.getInstance("NoneWithDSA", FIPS);
        rawVerifier.initVerify(kp.getPublic());
        rawVerifier.update(digest);
        Assertions.assertTrue(rawVerifier.verify(sig),
                "NoneWithDSA raw signature must verify over the signed digest");

        // ...and a tampered digest must NOT verify (negative-path differentiator).
        byte[] tampered = Arrays.clone(digest);
        tampered[tampered.length / 2] ^= 0x01;
        Signature tamperVerifier = Signature.getInstance("NoneWithDSA", FIPS);
        tamperVerifier.initVerify(kp.getPublic());
        tamperVerifier.update(tampered);
        Assertions.assertFalse(tamperVerifier.verify(sig),
                "tampered digest must not verify");
    }


    // -----------------------------------------------------------------
    // OID / alias resolution through JSLFIPS
    // -----------------------------------------------------------------

    /**
     * The registered DSA OIDs/aliases resolve through JSLFIPS: id-dsa
     * (1.2.840.10040.4.1) for KeyFactory / KeyPairGenerator / AlgorithmParameters,
     * and the Signature OIDs dsa-with-sha256 (2.16.840.1.101.3.4.3.2) and
     * id-dsa-with-sha1 (1.2.840.10040.4.3). The SHA-256 OID is exercised with a
     * sign/verify round-trip; the SHA-1 OID is resolution-only (SHA-1 signature
     * generation is gated by the module — see {@code FIPSSha1SignatureGateTest}).
     * Mirrors {@code DSATest.testGetInstanceByOID_keyFactoryAndKpg} and
     * {@code DSASignatureTest.testDsa_GetInstanceByOID_*}.
     */
    @Test
    public void dsaOidAliasesResolveThroughJslfips() throws Exception
    {
        SecureRandom sr = seededRandom("dsaOidAliasesResolveThroughJslfips");

        // id-dsa key infrastructure OID.
        Assertions.assertNotNull(KeyFactory.getInstance("1.2.840.10040.4.1", FIPS));
        Assertions.assertNotNull(KeyPairGenerator.getInstance("1.2.840.10040.4.1", FIPS));
        Assertions.assertNotNull(AlgorithmParameters.getInstance("1.2.840.10040.4.1", FIPS));

        // dsa-with-sha1 Signature OID: resolution only (SHA-1 signing gated).
        Assertions.assertNotNull(Signature.getInstance("1.2.840.10040.4.3", FIPS));

        // dsa-with-sha256 Signature OID: full sign/verify round-trip.
        KeyPair kp = generateDsaKeyPair();
        byte[] msg = randomMessage(sr, 64);
        byte[] sig = signOneShot("2.16.840.1.101.3.4.3.2", kp, msg);
        Assertions.assertTrue(verify("SHA256withDSA", kp, msg, sig),
                "signature by dsa-with-sha256 OID must verify via SHA256withDSA");
    }
}
