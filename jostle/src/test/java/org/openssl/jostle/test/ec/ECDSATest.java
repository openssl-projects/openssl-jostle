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
import org.openssl.jostle.util.Arrays;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * JCE-level tests for the ECDSA Signature SPI.
 *
 * <p>Covers the full digest matrix (SHA-1/2/3 family) on the curves the
 * loaded OpenSSL build advertises. Includes:
 * <ol>
 *   <li>round-trip per (curve × digest) combination,</li>
 *   <li>BouncyCastle agreement (Jostle ↔ BC) — verifies wire-compatible
 *       DER-encoded signatures,</li>
 *   <li>negative tests — tampered message and tampered signature must
 *       not verify,</li>
 *   <li>streaming-chunking parity — byte-by-byte / random splits /
 *       adversarial offsets must produce a verifiable signature
 *       (ECDSA is not deterministic so signatures differ between calls;
 *       what matters is that each independently verifies),</li>
 *   <li>pre-init state guard — IllegalStateException before init,</li>
 *   <li>reset/reuse — sign-twice, verify-twice, role-flip,</li>
 *   <li>provider plumbing — getInstance by name + OID, foreign-key
 *       rejection.</li>
 * </ol>
 *
 * <p>Tests use {@link Assumptions#assumeTrue} so a curve missing from
 * the OpenSSL build skips cleanly rather than failing.
 */
public class ECDSATest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final String[] STANDARD_CURVES = {"P-256", "P-384", "P-521", "secp256k1"};

    /**
     * Digest names accepted by the JCE Signature lookup. Must match
     * the inner-class registrations in
     * {@link org.openssl.jostle.jcajce.provider.ProvEC}.
     */
    private static final String[] DIGEST_ALGS = {
            "SHA1withECDSA",
            "SHA224withECDSA",
            "SHA256withECDSA",
            "SHA384withECDSA",
            "SHA512withECDSA",
            "SHA3-224withECDSA",
            "SHA3-256withECDSA",
            "SHA3-384withECDSA",
            "SHA3-512withECDSA",
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
    // Round-trip per (curve × digest)
    // -----------------------------------------------------------------

    @Test
    public void testEcdsa_AllCurvesAllDigests_roundTrip() throws Exception
    {
        int trials = 0;
        for (String curve : STANDARD_CURVES)
        {
            if (!NISelector.ECServiceNI.curveSupported(curve)) continue;
            KeyPair kp = generateKeyPair(curve);

            for (String alg : DIGEST_ALGS)
            {
                byte[] msg = randomMessage(128 + RANDOM.nextInt(384));
                signVerify(alg, kp, msg);
                trials++;
            }
        }
        Assertions.assertTrue(trials > 0, "no curves were testable; OpenSSL build looks broken");
    }


    // -----------------------------------------------------------------
    // Negative — tampered message / tampered signature
    // -----------------------------------------------------------------

    @Test
    public void testEcdsa_TamperedMessage_doesNotVerify() throws Exception
    {
        KeyPair kp = generateKeyPair("P-256");
        byte[] msg = randomMessage(256);

        Signature signer = Signature.getInstance("SHA256withECDSA", JostleProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());
        signer.update(msg);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance("SHA256withECDSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(kp.getPublic());
        // Flip a bit somewhere in the middle of the message.
        byte[] tampered = Arrays.clone(msg);
        tampered[tampered.length / 2] ^= 0x01;
        verifier.update(tampered);
        Assertions.assertFalse(verifier.verify(sig),
                "tampered message must not verify against original signature");
    }

    @Test
    public void testEcdsa_TamperedSignature_doesNotVerify() throws Exception
    {
        KeyPair kp = generateKeyPair("P-256");
        byte[] msg = randomMessage(256);

        Signature signer = Signature.getInstance("SHA256withECDSA", JostleProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());
        signer.update(msg);
        byte[] sig = signer.sign();
        byte[] tampered = Arrays.clone(sig);
        // Flip a bit deep inside the DER (not in the SEQUENCE/INTEGER
        // header — those are structural rejections, which are also
        // valid but not what this test wants).
        tampered[tampered.length - 1] ^= 0x01;

        Signature verifier = Signature.getInstance("SHA256withECDSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(kp.getPublic());
        verifier.update(msg);
        boolean verified;
        try
        {
            verified = verifier.verify(tampered);
        }
        catch (java.security.SignatureException expected)
        {
            // OpenSSL may surface DER-decode failures as exceptions —
            // also a correct rejection.
            verified = false;
        }
        Assertions.assertFalse(verified, "tampered signature must not verify");
    }


    // -----------------------------------------------------------------
    // Streaming / chunking parity
    // -----------------------------------------------------------------

    /**
     * ECDSA is non-deterministic (each sign uses a fresh random scalar
     * k), so we can't compare bytes. Instead, sign each chunking pattern
     * independently and assert the result verifies — what we're actually
     * checking is that the streaming digest produces the same hash as
     * the one-shot digest, observed transitively via signature validity.
     */
    @Test
    public void testEcdsa_ChunkingMatrix_allVerify() throws Exception
    {
        KeyPair kp = generateKeyPair("P-256");
        byte[] msg = randomMessage(1024);

        // Reference: one-shot verification path proves the signing path is sane.
        Assertions.assertTrue(verify("SHA256withECDSA", kp, msg, signOneShot("SHA256withECDSA", kp, msg)));

        // Byte-by-byte.
        Assertions.assertTrue(verify("SHA256withECDSA", kp, msg,
                signWithChunking("SHA256withECDSA", kp, msg, 1)));

        // Adversarial chunks around SHA-256 block size (64).
        for (int chunk : new int[]{63, 64, 65, 127, 128, 129})
        {
            Assertions.assertTrue(
                    verify("SHA256withECDSA", kp, msg,
                            signWithChunking("SHA256withECDSA", kp, msg, chunk)),
                    "chunk=" + chunk + ": chunked-signed signature did not verify");
        }

        // Random splits.
        for (int trial = 0; trial < 5; trial++)
        {
            Assertions.assertTrue(
                    verify("SHA256withECDSA", kp, msg,
                            signWithRandomSplits("SHA256withECDSA", kp, msg)),
                    "random-split signed signature did not verify");
        }
    }

    /**
     * Verify-side chunking: signature is fixed, only the verifier's
     * update path varies. If the streaming and bulk verify paths
     * disagree, this test catches it.
     */
    @Test
    public void testEcdsa_VerifyChunkingMatrix() throws Exception
    {
        KeyPair kp = generateKeyPair("P-384");
        byte[] msg = randomMessage(900);

        Signature signer = Signature.getInstance("SHA384withECDSA", JostleProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());
        signer.update(msg);
        byte[] sig = signer.sign();

        Assertions.assertTrue(verifyWithChunking("SHA384withECDSA", kp, msg, sig, msg.length));
        Assertions.assertTrue(verifyWithChunking("SHA384withECDSA", kp, msg, sig, 1));
        for (int chunk : new int[]{31, 32, 33, 127, 128, 129})
        {
            Assertions.assertTrue(verifyWithChunking("SHA384withECDSA", kp, msg, sig, chunk),
                    "chunk=" + chunk + ": verify diverged from one-shot");
        }
    }


    // -----------------------------------------------------------------
    // BouncyCastle agreement
    // -----------------------------------------------------------------

    @Test
    public void testEcdsa_BCAgreement_signJostleVerifyBC() throws Exception
    {
        for (String curve : STANDARD_CURVES)
        {
            if (!NISelector.ECServiceNI.curveSupported(curve)) continue;
            KeyPair joKp = generateKeyPair(curve);

            // BC needs a key it can decode — round-trip the public X.509
            // through BC's KeyFactory.
            KeyFactory bcKf = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
            PublicKey bcPub = bcKf.generatePublic(
                    new X509EncodedKeySpec(joKp.getPublic().getEncoded()));

            for (String alg : DIGEST_ALGS)
            {
                byte[] msg = randomMessage(64 + RANDOM.nextInt(512));

                Signature joSigner = Signature.getInstance(alg, JostleProvider.PROVIDER_NAME);
                joSigner.initSign(joKp.getPrivate());
                joSigner.update(msg);
                byte[] sig = joSigner.sign();

                Signature bcVerifier = Signature.getInstance(alg, BouncyCastleProvider.PROVIDER_NAME);
                bcVerifier.initVerify(bcPub);
                bcVerifier.update(msg);
                Assertions.assertTrue(bcVerifier.verify(sig),
                        curve + " / " + alg + ": Jostle-signed signature failed BC verify");
            }
        }
    }

    @Test
    public void testEcdsa_BCAgreement_signBCVerifyJostle() throws Exception
    {
        for (String curve : STANDARD_CURVES)
        {
            if (!NISelector.ECServiceNI.curveSupported(curve)) continue;

            // BC generates the key so we know BC owns the private side.
            KeyPairGenerator bcKpg = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
            bcKpg.initialize(new ECGenParameterSpec(curve));
            KeyPair bcKp = bcKpg.generateKeyPair();

            // Re-import BC's public key into Jostle.
            KeyFactory joKf = KeyFactory.getInstance("EC", JostleProvider.PROVIDER_NAME);
            PublicKey joPub = joKf.generatePublic(
                    new X509EncodedKeySpec(bcKp.getPublic().getEncoded()));

            for (String alg : DIGEST_ALGS)
            {
                byte[] msg = randomMessage(64 + RANDOM.nextInt(512));

                Signature bcSigner = Signature.getInstance(alg, BouncyCastleProvider.PROVIDER_NAME);
                bcSigner.initSign(bcKp.getPrivate());
                bcSigner.update(msg);
                byte[] sig = bcSigner.sign();

                Signature joVerifier = Signature.getInstance(alg, JostleProvider.PROVIDER_NAME);
                joVerifier.initVerify(joPub);
                joVerifier.update(msg);
                Assertions.assertTrue(joVerifier.verify(sig),
                        curve + " / " + alg + ": BC-signed signature failed Jostle verify");
            }
        }
    }


    // -----------------------------------------------------------------
    // SPI state-machine guards
    // -----------------------------------------------------------------

    @Test
    public void testEcdsa_UpdateBeforeInit_isIllegalState() throws Exception
    {
        Signature signer = Signature.getInstance("SHA256withECDSA", JostleProvider.PROVIDER_NAME);
        try
        {
            signer.update(new byte[]{1, 2, 3});
            Assertions.fail("update before init must throw");
        }
        catch (java.security.SignatureException expected)
        {
            // The JCE wraps the SPI's IllegalStateException in a
            // SignatureException with message "object not initialized
            // for signing/verification".
        }
    }

    @Test
    public void testEcdsa_SignBeforeInit_isIllegalState() throws Exception
    {
        Signature signer = Signature.getInstance("SHA256withECDSA", JostleProvider.PROVIDER_NAME);
        try
        {
            signer.sign();
            Assertions.fail("sign before init must throw");
        }
        catch (java.security.SignatureException expected) {}
    }

    @Test
    public void testEcdsa_VerifyBeforeInit_isIllegalState() throws Exception
    {
        Signature verifier = Signature.getInstance("SHA256withECDSA", JostleProvider.PROVIDER_NAME);
        try
        {
            verifier.verify(new byte[]{1, 2, 3});
            Assertions.fail("verify before init must throw");
        }
        catch (java.security.SignatureException expected) {}
    }


    // -----------------------------------------------------------------
    // Reset / reuse
    // -----------------------------------------------------------------

    @Test
    public void testEcdsa_TwoSignsOnSameInstance_bothVerify() throws Exception
    {
        KeyPair kp = generateKeyPair("P-256");
        Signature signer = Signature.getInstance("SHA256withECDSA", JostleProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());

        byte[] msgA = randomMessage(64);
        byte[] msgB = randomMessage(96);

        signer.update(msgA);
        byte[] sigA = signer.sign();

        // No re-init — same instance, fresh update; reInit() inside
        // engineSign() is what makes this legal.
        signer.update(msgB);
        byte[] sigB = signer.sign();

        Signature verifier = Signature.getInstance("SHA256withECDSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(kp.getPublic());
        verifier.update(msgA);
        Assertions.assertTrue(verifier.verify(sigA), "sigA must verify");

        verifier.initVerify(kp.getPublic());
        verifier.update(msgB);
        Assertions.assertTrue(verifier.verify(sigB), "sigB must verify");
    }

    /**
     * ECDSA is non-deterministic. Two signatures over the same message
     * with the same key MUST differ — a stale internal state caching
     * the prior k or the prior signature would produce equal output.
     */
    @Test
    public void testEcdsa_SameMessageTwice_signaturesDiffer() throws Exception
    {
        KeyPair kp = generateKeyPair("P-256");
        byte[] msg = randomMessage(64);

        Signature signer = Signature.getInstance("SHA256withECDSA", JostleProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());
        signer.update(msg);
        byte[] sigA = signer.sign();
        signer.update(msg);
        byte[] sigB = signer.sign();

        Assertions.assertFalse(java.util.Arrays.equals(sigA, sigB),
                "two ECDSA signatures over the same message must differ "
                        + "(non-determinism) — equal output suggests cached k");
        // But both must verify.
        Assertions.assertTrue(verify("SHA256withECDSA", kp, msg, sigA));
        Assertions.assertTrue(verify("SHA256withECDSA", kp, msg, sigB));
    }

    @Test
    public void testEcdsa_NegativeThenPositive_failureDoesNotPoisonState() throws Exception
    {
        // Drive a verify failure, then a verify success on the same
        // instance — the failure path must not leave residual state.
        KeyPair kp = generateKeyPair("P-256");
        byte[] msgA = randomMessage(64);
        byte[] msgB = randomMessage(96);

        Signature signer = Signature.getInstance("SHA256withECDSA", JostleProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());
        signer.update(msgB);
        byte[] sigB = signer.sign();
        byte[] sigBTampered = Arrays.clone(sigB);
        sigBTampered[sigBTampered.length - 1] ^= 0x01;

        Signature verifier = Signature.getInstance("SHA256withECDSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(kp.getPublic());
        verifier.update(msgB);
        boolean firstVerify;
        try
        {
            firstVerify = verifier.verify(sigBTampered);
        }
        catch (java.security.SignatureException expected)
        {
            firstVerify = false;
        }
        Assertions.assertFalse(firstVerify,
                "tampered signature must not verify");

        // The failure must not poison the instance — a clean second
        // pass on the same verifier must succeed.
        verifier.update(msgB);
        Assertions.assertTrue(verifier.verify(sigB),
                "good signature must verify after a previous-fail verify "
                        + "(reInit must clear residual state)");

        // And a third with a different message and signature.
        signer.update(msgA);
        byte[] sigA = signer.sign();
        verifier.update(msgA);
        Assertions.assertTrue(verifier.verify(sigA));
    }

    @Test
    public void testEcdsa_PositiveThenNegative_priorPassDoesNotLeak() throws Exception
    {
        // Inverse of the above: a previous-pass verify must not echo
        // its "true" result on a subsequent fail.
        KeyPair kp = generateKeyPair("P-256");
        byte[] msg = randomMessage(64);

        Signature signer = Signature.getInstance("SHA256withECDSA", JostleProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());
        signer.update(msg);
        byte[] sig = signer.sign();
        byte[] tampered = Arrays.clone(sig);
        tampered[tampered.length - 1] ^= 0x01;

        Signature verifier = Signature.getInstance("SHA256withECDSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(kp.getPublic());
        verifier.update(msg);
        Assertions.assertTrue(verifier.verify(sig), "first verify should pass");

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
        Assertions.assertFalse(cached,
                "previous-pass result leaked into next call");
    }

    @Test
    public void testEcdsa_RoleFlip_SignThenVerifyOnSameInstance() throws Exception
    {
        // initSign → sign → initVerify on the SAME instance → verify.
        // lastKey must replace cleanly when the role flips.
        KeyPair kp = generateKeyPair("P-256");
        byte[] msg = randomMessage(48);

        Signature sig = Signature.getInstance("SHA256withECDSA", JostleProvider.PROVIDER_NAME);
        sig.initSign(kp.getPrivate());
        sig.update(msg);
        byte[] s = sig.sign();

        sig.initVerify(kp.getPublic());
        sig.update(msg);
        Assertions.assertTrue(sig.verify(s),
                "verify on a Signature previously used to sign must succeed");

        sig.initSign(kp.getPrivate());
        sig.update(msg);
        byte[] s2 = sig.sign();
        // ECDSA non-determinism — s2 must NOT equal s but must still
        // verify.
        Assertions.assertFalse(java.util.Arrays.equals(s, s2),
                "fresh ECDSA sign on the same instance must produce a "
                        + "different signature");
        sig.initVerify(kp.getPublic());
        sig.update(msg);
        Assertions.assertTrue(sig.verify(s2));
    }


    // -----------------------------------------------------------------
    // Provider plumbing
    // -----------------------------------------------------------------

    @Test
    public void testEcdsa_GetInstanceByOID_SHA256() throws Exception
    {
        // ecdsa-with-SHA256 OID = 1.2.840.10045.4.3.2.
        KeyPair kp = generateKeyPair("P-256");
        byte[] msg = randomMessage(64);

        Signature signer = Signature.getInstance("1.2.840.10045.4.3.2",
                JostleProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());
        signer.update(msg);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance("SHA256withECDSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(kp.getPublic());
        verifier.update(msg);
        Assertions.assertTrue(verifier.verify(sig));
    }

    @Test
    public void testEcdsa_GetInstanceByOID_SHA3_256() throws Exception
    {
        // ecdsa-with-SHA3-256 OID = 2.16.840.1.101.3.4.3.10.
        KeyPair kp = generateKeyPair("P-256");
        byte[] msg = randomMessage(64);

        Signature signer = Signature.getInstance("2.16.840.1.101.3.4.3.10",
                JostleProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());
        signer.update(msg);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance("SHA3-256withECDSA",
                JostleProvider.PROVIDER_NAME);
        verifier.initVerify(kp.getPublic());
        verifier.update(msg);
        Assertions.assertTrue(verifier.verify(sig));
    }

    @Test
    public void testEcdsa_RejectsForeignPublicKey() throws Exception
    {
        // An RSA public key handed to an ECDSA Signature must be
        // rejected with InvalidKeyException — JCE depends on this for
        // provider fallback.
        KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA",
                JostleProvider.PROVIDER_NAME);
        rsaKpg.initialize(2048);
        KeyPair rsa = rsaKpg.generateKeyPair();

        Signature verifier = Signature.getInstance("SHA256withECDSA",
                JostleProvider.PROVIDER_NAME);
        try
        {
            verifier.initVerify(rsa.getPublic());
            Assertions.fail("expected InvalidKeyException for RSA public key");
        }
        catch (InvalidKeyException expected) {}
    }

    @Test
    public void testEcdsa_RejectsForeignPrivateKey() throws Exception
    {
        KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA",
                JostleProvider.PROVIDER_NAME);
        rsaKpg.initialize(2048);
        KeyPair rsa = rsaKpg.generateKeyPair();

        Signature signer = Signature.getInstance("SHA256withECDSA",
                JostleProvider.PROVIDER_NAME);
        try
        {
            signer.initSign(rsa.getPrivate());
            Assertions.fail("expected InvalidKeyException for RSA private key");
        }
        catch (InvalidKeyException expected) {}
    }


    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private static KeyPair generateKeyPair(String curve) throws Exception
    {
        Assumptions.assumeTrue(NISelector.ECServiceNI.curveSupported(curve),
                curve + " not supported by the loaded OpenSSL build");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", JostleProvider.PROVIDER_NAME);
        kpg.initialize(new ECGenParameterSpec(curve));
        return kpg.generateKeyPair();
    }

    private static void signVerify(String alg, KeyPair kp, byte[] msg) throws Exception
    {
        byte[] sig = signOneShot(alg, kp, msg);
        Assertions.assertTrue(verify(alg, kp, msg, sig),
                alg + ": failed self-verification");
    }

    private static byte[] signOneShot(String alg, KeyPair kp, byte[] msg) throws Exception
    {
        Signature signer = Signature.getInstance(alg, JostleProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());
        signer.update(msg);
        return signer.sign();
    }

    private static boolean verify(String alg, KeyPair kp, byte[] msg, byte[] sig) throws Exception
    {
        Signature verifier = Signature.getInstance(alg, JostleProvider.PROVIDER_NAME);
        verifier.initVerify(kp.getPublic());
        verifier.update(msg);
        return verifier.verify(sig);
    }

    private static byte[] signWithChunking(String alg, KeyPair kp, byte[] msg, int chunk) throws Exception
    {
        Signature signer = Signature.getInstance(alg, JostleProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());
        for (int off = 0; off < msg.length; off += chunk)
        {
            int len = Math.min(chunk, msg.length - off);
            signer.update(msg, off, len);
        }
        return signer.sign();
    }

    private static byte[] signWithRandomSplits(String alg, KeyPair kp, byte[] msg) throws Exception
    {
        Signature signer = Signature.getInstance(alg, JostleProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());
        int pos = 0;
        while (pos < msg.length)
        {
            int remaining = msg.length - pos;
            int chunk = 1 + RANDOM.nextInt(Math.max(1, remaining));
            chunk = Math.min(chunk, remaining);
            signer.update(msg, pos, chunk);
            pos += chunk;
        }
        return signer.sign();
    }

    private static boolean verifyWithChunking(String alg, KeyPair kp, byte[] msg, byte[] sig, int chunk)
            throws Exception
    {
        Signature verifier = Signature.getInstance(alg, JostleProvider.PROVIDER_NAME);
        verifier.initVerify(kp.getPublic());
        for (int off = 0; off < msg.length; off += chunk)
        {
            int len = Math.min(chunk, msg.length - off);
            verifier.update(msg, off, len);
        }
        return verifier.verify(sig);
    }

    private static byte[] randomMessage(int len)
    {
        byte[] m = new byte[len];
        RANDOM.nextBytes(m);
        return m;
    }
}
