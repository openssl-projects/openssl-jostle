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

package org.openssl.jostle.test.dsa;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAParameterSpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * JCE-level tests for the DSA Signature SPI.
 *
 * <p>Covers the full digest matrix (SHA-1/2/3 family). Includes:
 * <ol>
 *   <li>round-trip per digest,</li>
 *   <li>BouncyCastle agreement (Jostle ↔ BC) — verifies wire-compatible
 *       DER-encoded signatures,</li>
 *   <li>negative tests — tampered message and tampered signature must
 *       not verify,</li>
 *   <li>streaming-chunking parity,</li>
 *   <li>pre-init state guard — IllegalStateException before init,</li>
 *   <li>reset/reuse — sign-twice, same-message non-determinism,
 *       negative-then-positive, positive-then-negative, role-flip,</li>
 *   <li>provider plumbing — getInstance by OID, foreign-key rejection.</li>
 * </ol>
 */
public class DSASignatureTest
{
    /**
     * Class-level seeding random — used to derive each test's local
     * SHA1PRNG seed.
     */
    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * Per-test seeded random. The seed is logged on every call so a
     * flaky failure can be reproduced by re-running with the same seed.
     */
    private static SecureRandom seededRandom(String testName) throws Exception
    {
        long seed = RANDOM.nextLong();
        System.out.println(testName + " seed=" + seed);
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        return sr;
    }

    /**
     * Digest names accepted by the JCE Signature lookup. Must match
     * the inner-class registrations in
     * {@link org.openssl.jostle.jcajce.provider.ProvDSA}.
     */
    private static final String[] DIGEST_ALGS = {
            "SHA1withDSA",
            "SHA224withDSA",
            "SHA256withDSA",
            "SHA384withDSA",
            "SHA512withDSA",
            "SHA3-224withDSA",
            "SHA3-256withDSA",
            "SHA3-384withDSA",
            "SHA3-512withDSA",
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

    private static KeyPair generateKeyPair() throws Exception
    {
        // 1024-bit parameters are cached per JVM by the KPG, so each
        // call after the first is just an x/y generation.
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA", JostleProvider.PROVIDER_NAME);
        kpg.initialize(1024);
        return kpg.generateKeyPair();
    }

    private static byte[] randomMessage(SecureRandom sr, int len)
    {
        byte[] msg = new byte[len];
        sr.nextBytes(msg);
        return msg;
    }

    private static void signVerify(String alg, KeyPair kp, byte[] msg) throws Exception
    {
        Signature signer = Signature.getInstance(alg, JostleProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());
        signer.update(msg);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance(alg, JostleProvider.PROVIDER_NAME);
        verifier.initVerify(kp.getPublic());
        verifier.update(msg);
        Assertions.assertTrue(verifier.verify(sig), alg + ": round-trip failed");
    }

    private static boolean verify(String alg, KeyPair kp, byte[] msg, byte[] sig) throws Exception
    {
        Signature verifier = Signature.getInstance(alg, JostleProvider.PROVIDER_NAME);
        verifier.initVerify(kp.getPublic());
        verifier.update(msg);
        return verifier.verify(sig);
    }

    private static byte[] signOneShot(String alg, KeyPair kp, byte[] msg) throws Exception
    {
        Signature signer = Signature.getInstance(alg, JostleProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());
        signer.update(msg);
        return signer.sign();
    }

    private static byte[] signWithChunking(String alg, KeyPair kp, byte[] msg, int chunk) throws Exception
    {
        Signature signer = Signature.getInstance(alg, JostleProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());
        for (int off = 0; off < msg.length; off += chunk)
        {
            signer.update(msg, off, Math.min(chunk, msg.length - off));
        }
        return signer.sign();
    }

    private static byte[] signWithRandomSplits(SecureRandom sr, String alg, KeyPair kp, byte[] msg) throws Exception
    {
        Signature signer = Signature.getInstance(alg, JostleProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());
        int off = 0;
        while (off < msg.length)
        {
            int n = 1 + sr.nextInt(msg.length - off);
            signer.update(msg, off, n);
            off += n;
        }
        return signer.sign();
    }

    private static boolean verifyWithChunking(String alg, KeyPair kp, byte[] msg, byte[] sig, int chunk) throws Exception
    {
        Signature verifier = Signature.getInstance(alg, JostleProvider.PROVIDER_NAME);
        verifier.initVerify(kp.getPublic());
        for (int off = 0; off < msg.length; off += chunk)
        {
            verifier.update(msg, off, Math.min(chunk, msg.length - off));
        }
        return verifier.verify(sig);
    }


    // -----------------------------------------------------------------
    // Round-trip per digest
    // -----------------------------------------------------------------

    @Test
    public void testDsa_AllDigests_roundTrip() throws Exception
    {
        SecureRandom sr = seededRandom("testDsa_AllDigests_roundTrip");
        KeyPair kp = generateKeyPair();
        for (String alg : DIGEST_ALGS)
        {
            byte[] msg = randomMessage(sr, 128 + sr.nextInt(384));
            signVerify(alg, kp, msg);
        }
    }


    // -----------------------------------------------------------------
    // Negative — tampered message / tampered signature
    // -----------------------------------------------------------------

    @Test
    public void testDsa_TamperedMessage_doesNotVerify() throws Exception
    {
        SecureRandom sr = seededRandom("testDsa_TamperedMessage_doesNotVerify");
        KeyPair kp = generateKeyPair();
        byte[] msg = randomMessage(sr, 256);

        byte[] sig = signOneShot("SHA256withDSA", kp, msg);

        Signature verifier = Signature.getInstance("SHA256withDSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(kp.getPublic());
        byte[] tampered = Arrays.clone(msg);
        tampered[tampered.length / 2] ^= 0x01;
        verifier.update(tampered);
        Assertions.assertFalse(verifier.verify(sig),
                "tampered message must not verify against original signature");
    }

    @Test
    public void testDsa_TamperedSignature_doesNotVerify() throws Exception
    {
        SecureRandom sr = seededRandom("testDsa_TamperedSignature_doesNotVerify");
        KeyPair kp = generateKeyPair();
        byte[] msg = randomMessage(sr, 256);

        byte[] sig = signOneShot("SHA256withDSA", kp, msg);
        byte[] tampered = Arrays.clone(sig);
        // Flip a bit deep inside the DER (not in the SEQUENCE/INTEGER
        // header — those are structural rejections, which are also
        // valid but not what this test wants).
        tampered[tampered.length - 1] ^= 0x01;

        Signature verifier = Signature.getInstance("SHA256withDSA", JostleProvider.PROVIDER_NAME);
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

    @Test
    public void testDsa_WrongKey_doesNotVerify() throws Exception
    {
        SecureRandom sr = seededRandom("testDsa_WrongKey_doesNotVerify");
        KeyPair kpA = generateKeyPair();
        KeyPair kpB = generateKeyPair();
        byte[] msg = randomMessage(sr, 128);

        byte[] sig = signOneShot("SHA256withDSA", kpA, msg);

        Signature verifier = Signature.getInstance("SHA256withDSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(kpB.getPublic());
        verifier.update(msg);
        Assertions.assertFalse(verifier.verify(sig),
                "signature must not verify under a different key");
    }


    // -----------------------------------------------------------------
    // Streaming / chunking parity
    // -----------------------------------------------------------------

    /**
     * DSA is non-deterministic (each sign uses a fresh random nonce k),
     * so we can't compare bytes. Instead, sign each chunking pattern
     * independently and assert the result verifies — what we're actually
     * checking is that the streaming digest produces the same hash as
     * the one-shot digest, observed transitively via signature validity.
     */
    @Test
    public void testDsa_ChunkingMatrix_allVerify() throws Exception
    {
        SecureRandom sr = seededRandom("testDsa_ChunkingMatrix_allVerify");
        KeyPair kp = generateKeyPair();
        byte[] msg = randomMessage(sr, 1024);

        // Reference: one-shot.
        Assertions.assertTrue(verify("SHA256withDSA", kp, msg, signOneShot("SHA256withDSA", kp, msg)));

        // Byte-by-byte.
        Assertions.assertTrue(verify("SHA256withDSA", kp, msg,
                signWithChunking("SHA256withDSA", kp, msg, 1)));

        // Adversarial chunks around SHA-256 block size (64).
        for (int chunk : new int[]{63, 64, 65, 127, 128, 129})
        {
            Assertions.assertTrue(
                    verify("SHA256withDSA", kp, msg,
                            signWithChunking("SHA256withDSA", kp, msg, chunk)),
                    "chunk=" + chunk + ": chunked-signed signature did not verify");
        }

        // Random splits.
        for (int trial = 0; trial < 5; trial++)
        {
            Assertions.assertTrue(
                    verify("SHA256withDSA", kp, msg,
                            signWithRandomSplits(sr, "SHA256withDSA", kp, msg)),
                    "random-split signed signature did not verify");
        }
    }

    /**
     * Verify-side chunking: signature is fixed, only the verifier's
     * update path varies.
     */
    @Test
    public void testDsa_VerifyChunkingMatrix() throws Exception
    {
        SecureRandom sr = seededRandom("testDsa_VerifyChunkingMatrix");
        KeyPair kp = generateKeyPair();
        byte[] msg = randomMessage(sr, 900);

        byte[] sig = signOneShot("SHA384withDSA", kp, msg);

        Assertions.assertTrue(verifyWithChunking("SHA384withDSA", kp, msg, sig, msg.length));
        Assertions.assertTrue(verifyWithChunking("SHA384withDSA", kp, msg, sig, 1));
        for (int chunk : new int[]{31, 32, 33, 127, 128, 129})
        {
            Assertions.assertTrue(verifyWithChunking("SHA384withDSA", kp, msg, sig, chunk),
                    "chunk=" + chunk + ": verify diverged from one-shot");
        }
    }


    // -----------------------------------------------------------------
    // BouncyCastle agreement
    // -----------------------------------------------------------------

    @Test
    public void testDsa_BCAgreement_signJostleVerifyBC() throws Exception
    {
        SecureRandom sr = seededRandom("testDsa_BCAgreement_signJostleVerifyBC");
        KeyPair joKp = generateKeyPair();

        // BC needs a key it can decode — round-trip the public X.509
        // through BC's KeyFactory.
        KeyFactory bcKf = KeyFactory.getInstance("DSA", BouncyCastleProvider.PROVIDER_NAME);
        PublicKey bcPub = bcKf.generatePublic(
                new X509EncodedKeySpec(joKp.getPublic().getEncoded()));

        for (String alg : DIGEST_ALGS)
        {
            byte[] msg = randomMessage(sr, 64 + sr.nextInt(512));

            Signature joSigner = Signature.getInstance(alg, JostleProvider.PROVIDER_NAME);
            joSigner.initSign(joKp.getPrivate());
            joSigner.update(msg);
            byte[] sig = joSigner.sign();

            Signature bcVerifier = Signature.getInstance(alg, BouncyCastleProvider.PROVIDER_NAME);
            bcVerifier.initVerify(bcPub);
            bcVerifier.update(msg);
            Assertions.assertTrue(bcVerifier.verify(sig),
                    alg + ": Jostle-signed signature failed BC verify");
        }
    }

    @Test
    public void testDsa_BCAgreement_signBCVerifyJostle() throws Exception
    {
        SecureRandom sr = seededRandom("testDsa_BCAgreement_signBCVerifyJostle");

        // BC generates the keypair on Jostle-produced parameters (fast,
        // avoids BC's own multi-second paramgen).
        KeyPair seedKp = generateKeyPair();
        DSAParams params = ((DSAPublicKey) seedKp.getPublic()).getParams();
        KeyPairGenerator bcKpg = KeyPairGenerator.getInstance("DSA", BouncyCastleProvider.PROVIDER_NAME);
        bcKpg.initialize(new DSAParameterSpec(params.getP(), params.getQ(), params.getG()));
        KeyPair bcKp = bcKpg.generateKeyPair();

        // Re-import BC's public key into Jostle.
        KeyFactory joKf = KeyFactory.getInstance("DSA", JostleProvider.PROVIDER_NAME);
        PublicKey joPub = joKf.generatePublic(
                new X509EncodedKeySpec(bcKp.getPublic().getEncoded()));

        for (String alg : DIGEST_ALGS)
        {
            byte[] msg = randomMessage(sr, 64 + sr.nextInt(512));

            Signature bcSigner = Signature.getInstance(alg, BouncyCastleProvider.PROVIDER_NAME);
            bcSigner.initSign(bcKp.getPrivate());
            bcSigner.update(msg);
            byte[] sig = bcSigner.sign();

            Signature joVerifier = Signature.getInstance(alg, JostleProvider.PROVIDER_NAME);
            joVerifier.initVerify(joPub);
            joVerifier.update(msg);
            Assertions.assertTrue(joVerifier.verify(sig),
                    alg + ": BC-signed signature failed Jostle verify");
        }
    }


    // -----------------------------------------------------------------
    // SPI state-machine guards
    // -----------------------------------------------------------------

    @Test
    public void testDsa_UpdateBeforeInit_isIllegalState() throws Exception
    {
        Signature signer = Signature.getInstance("SHA256withDSA", JostleProvider.PROVIDER_NAME);
        try
        {
            signer.update(new byte[]{1, 2, 3});
            Assertions.fail("update before init must throw");
        }
        catch (java.security.SignatureException expected)
        {
            Assertions.assertNotNull(expected.getMessage());
            Assertions.assertTrue(
                    expected.getMessage().contains("not initialized"),
                    "unexpected message: " + expected.getMessage());
        }
    }

    @Test
    public void testDsa_SignBeforeInit_isIllegalState() throws Exception
    {
        Signature signer = Signature.getInstance("SHA256withDSA", JostleProvider.PROVIDER_NAME);
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
    }

    @Test
    public void testDsa_VerifyBeforeInit_isIllegalState() throws Exception
    {
        Signature verifier = Signature.getInstance("SHA256withDSA", JostleProvider.PROVIDER_NAME);
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
    // Reset / reuse
    // -----------------------------------------------------------------

    @Test
    public void testDsa_TwoSignsOnSameInstance_bothVerify() throws Exception
    {
        SecureRandom sr = seededRandom("testDsa_TwoSignsOnSameInstance_bothVerify");
        KeyPair kp = generateKeyPair();
        Signature signer = Signature.getInstance("SHA256withDSA", JostleProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());

        byte[] msgA = randomMessage(sr, 64);
        byte[] msgB = randomMessage(sr, 96);

        signer.update(msgA);
        byte[] sigA = signer.sign();

        // No re-init — same instance, fresh update; reInit() inside
        // engineSign() is what makes this legal.
        signer.update(msgB);
        byte[] sigB = signer.sign();

        Assertions.assertTrue(verify("SHA256withDSA", kp, msgA, sigA), "sigA must verify");
        Assertions.assertTrue(verify("SHA256withDSA", kp, msgB, sigB), "sigB must verify");
    }

    /**
     * DSA is non-deterministic. Two signatures over the same message
     * with the same key MUST differ — a stale internal state caching
     * the prior k or the prior signature would produce equal output.
     */
    @Test
    public void testDsa_SameMessageTwice_signaturesDiffer() throws Exception
    {
        SecureRandom sr = seededRandom("testDsa_SameMessageTwice_signaturesDiffer");
        KeyPair kp = generateKeyPair();
        byte[] msg = randomMessage(sr, 64);

        Signature signer = Signature.getInstance("SHA256withDSA", JostleProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());
        signer.update(msg);
        byte[] sigA = signer.sign();
        signer.update(msg);
        byte[] sigB = signer.sign();

        Assertions.assertFalse(Arrays.areEqual(sigA, sigB),
                "two DSA signatures over the same message must differ "
                        + "(non-determinism) — equal output suggests cached k");
        // But both must verify.
        Assertions.assertTrue(verify("SHA256withDSA", kp, msg, sigA));
        Assertions.assertTrue(verify("SHA256withDSA", kp, msg, sigB));
    }

    @Test
    public void testDsa_NegativeThenPositive_failureDoesNotPoisonState() throws Exception
    {
        SecureRandom sr = seededRandom("testDsa_NegativeThenPositive_failureDoesNotPoisonState");
        KeyPair kp = generateKeyPair();
        byte[] msgA = randomMessage(sr, 64);
        byte[] msgB = randomMessage(sr, 96);

        Signature signer = Signature.getInstance("SHA256withDSA", JostleProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());
        signer.update(msgB);
        byte[] sigB = signer.sign();
        byte[] sigBTampered = Arrays.clone(sigB);
        sigBTampered[sigBTampered.length - 1] ^= 0x01;

        Signature verifier = Signature.getInstance("SHA256withDSA", JostleProvider.PROVIDER_NAME);
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
        Assertions.assertFalse(firstVerify, "tampered signature must not verify");

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
    public void testDsa_PositiveThenNegative_priorPassDoesNotLeak() throws Exception
    {
        SecureRandom sr = seededRandom("testDsa_PositiveThenNegative_priorPassDoesNotLeak");
        KeyPair kp = generateKeyPair();
        byte[] msg = randomMessage(sr, 64);

        byte[] sig = signOneShot("SHA256withDSA", kp, msg);
        byte[] tampered = Arrays.clone(sig);
        tampered[tampered.length - 1] ^= 0x01;

        Signature verifier = Signature.getInstance("SHA256withDSA", JostleProvider.PROVIDER_NAME);
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
        Assertions.assertFalse(cached, "previous-pass result leaked into next call");
    }

    @Test
    public void testDsa_RoleFlip_SignThenVerifyOnSameInstance() throws Exception
    {
        SecureRandom sr = seededRandom("testDsa_RoleFlip_SignThenVerifyOnSameInstance");
        KeyPair kp = generateKeyPair();
        byte[] msg = randomMessage(sr, 48);

        Signature sig = Signature.getInstance("SHA256withDSA", JostleProvider.PROVIDER_NAME);
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
        // DSA non-determinism — s2 must NOT equal s but must still verify.
        Assertions.assertFalse(Arrays.areEqual(s, s2),
                "fresh DSA sign on the same instance must produce a "
                        + "different signature");
        sig.initVerify(kp.getPublic());
        sig.update(msg);
        Assertions.assertTrue(sig.verify(s2));
    }


    // -----------------------------------------------------------------
    // Provider plumbing
    // -----------------------------------------------------------------

    @Test
    public void testDsa_GetInstanceByOID_SHA1() throws Exception
    {
        SecureRandom sr = seededRandom("testDsa_GetInstanceByOID_SHA1");
        // id-dsa-with-sha1 OID = 1.2.840.10040.4.3.
        KeyPair kp = generateKeyPair();
        byte[] msg = randomMessage(sr, 64);

        Signature signer = Signature.getInstance("1.2.840.10040.4.3",
                JostleProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());
        signer.update(msg);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance("SHA1withDSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(kp.getPublic());
        verifier.update(msg);
        Assertions.assertTrue(verifier.verify(sig));
    }

    @Test
    public void testDsa_GetInstanceByOID_SHA256() throws Exception
    {
        SecureRandom sr = seededRandom("testDsa_GetInstanceByOID_SHA256");
        // dsa-with-sha256 OID = 2.16.840.1.101.3.4.3.2.
        KeyPair kp = generateKeyPair();
        byte[] msg = randomMessage(sr, 64);

        Signature signer = Signature.getInstance("2.16.840.1.101.3.4.3.2",
                JostleProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());
        signer.update(msg);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance("SHA256withDSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(kp.getPublic());
        verifier.update(msg);
        Assertions.assertTrue(verifier.verify(sig));
    }

    @Test
    public void testDsa_GetInstanceByOID_SHA3_256() throws Exception
    {
        SecureRandom sr = seededRandom("testDsa_GetInstanceByOID_SHA3_256");
        // id-dsa-with-sha3-256 OID = 2.16.840.1.101.3.4.3.6.
        KeyPair kp = generateKeyPair();
        byte[] msg = randomMessage(sr, 64);

        Signature signer = Signature.getInstance("2.16.840.1.101.3.4.3.6",
                JostleProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());
        signer.update(msg);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance("SHA3-256withDSA",
                JostleProvider.PROVIDER_NAME);
        verifier.initVerify(kp.getPublic());
        verifier.update(msg);
        Assertions.assertTrue(verifier.verify(sig));
    }

    @Test
    public void testDsa_RejectsForeignPublicKey() throws Exception
    {
        // An RSA public key handed to a DSA Signature must be rejected
        // with InvalidKeyException — JCE depends on this for provider
        // fallback.
        KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA",
                JostleProvider.PROVIDER_NAME);
        rsaKpg.initialize(2048);
        KeyPair rsa = rsaKpg.generateKeyPair();

        Signature verifier = Signature.getInstance("SHA256withDSA",
                JostleProvider.PROVIDER_NAME);
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
    }

    @Test
    public void testDsa_RejectsForeignPrivateKey() throws Exception
    {
        KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA",
                JostleProvider.PROVIDER_NAME);
        rsaKpg.initialize(2048);
        KeyPair rsa = rsaKpg.generateKeyPair();

        Signature signer = Signature.getInstance("SHA256withDSA",
                JostleProvider.PROVIDER_NAME);
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

    /**
     * A foreign (SUN-provider) DSA key must be accepted via the
     * translate-on-init path — this is what CMS/PKIX verifiers rely on
     * when they hand the SPI a certificate-parsed key.
     */
    @Test
    public void testDsa_AcceptsForeignDSAKey_viaTranslate() throws Exception
    {
        SecureRandom sr = seededRandom("testDsa_AcceptsForeignDSAKey_viaTranslate");
        KeyPairGenerator sunKpg = KeyPairGenerator.getInstance("DSA", "SUN");
        sunKpg.initialize(1024);
        KeyPair sunKp = sunKpg.generateKeyPair();
        byte[] msg = randomMessage(sr, 64);

        Signature signer = Signature.getInstance("SHA256withDSA", JostleProvider.PROVIDER_NAME);
        signer.initSign(sunKp.getPrivate());
        signer.update(msg);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance("SHA256withDSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(sunKp.getPublic());
        verifier.update(msg);
        Assertions.assertTrue(verifier.verify(sig),
                "SUN-provider DSA keys must work via the translate path");
    }

    /**
     * Direct test of {@code engineUpdate(byte)}: feed a message one
     * byte at a time via {@link Signature#update(byte)} and assert the
     * resulting signature verifies.
     */
    @Test
    public void testDsa_SingleByteUpdate_verifies() throws Exception
    {
        SecureRandom sr = seededRandom("testDsa_SingleByteUpdate_verifies");
        KeyPair kp = generateKeyPair();
        byte[] msg = randomMessage(sr, 100);

        Signature signer = Signature.getInstance("SHA256withDSA", JostleProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());
        for (byte b : msg)
        {
            signer.update(b);
        }
        byte[] sig = signer.sign();

        Assertions.assertTrue(verify("SHA256withDSA", kp, msg, sig),
                "byte-at-a-time signed message must verify");
    }
}
