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

package org.openssl.jostle.test.rsa;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.interfaces.RSAPrivateCrtKey;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * JCE-level tests for the RSA Signature, KeyPairGenerator, and KeyFactory
 * implementations. Combines round-trip tests, BouncyCastle cross-validation,
 * negative tests, and CRT-component contracts.
 */
public class RSATest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    /** Reused across all tests to keep wall-clock time reasonable. */
    private static KeyPair sharedKeyPair;

    @BeforeAll
    static void before() throws Exception
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", JostleProvider.PROVIDER_NAME);
        kpg.initialize(2048);
        sharedKeyPair = kpg.generateKeyPair();
    }


    // -----------------------------------------------------------------
    // KeyPairGenerator
    // -----------------------------------------------------------------

    @Test
    public void testKeyPairGenerator_default2048() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", JostleProvider.PROVIDER_NAME);
        KeyPair kp = kpg.generateKeyPair();

        RSAPublicKey pub = (RSAPublicKey) kp.getPublic();
        Assertions.assertEquals(2048, pub.getModulus().bitLength());
        Assertions.assertEquals(BigInteger.valueOf(65537), pub.getPublicExponent());
    }

    @Test
    public void testKeyPairGenerator_explicitKeySize() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", JostleProvider.PROVIDER_NAME);
        kpg.initialize(3072);
        KeyPair kp = kpg.generateKeyPair();
        Assertions.assertEquals(3072, ((RSAPublicKey) kp.getPublic()).getModulus().bitLength());
    }

    @Test
    public void testKeyPairGenerator_RSAKeyGenParameterSpec_F4() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", JostleProvider.PROVIDER_NAME);
        kpg.initialize(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4));
        KeyPair kp = kpg.generateKeyPair();
        Assertions.assertEquals(BigInteger.valueOf(65537),
                ((RSAPublicKey) kp.getPublic()).getPublicExponent());
    }

    @Test
    public void testKeyPairGenerator_RSAKeyGenParameterSpec_customExponent() throws Exception
    {
        // 3 is the smallest accepted exponent (per v1 design decision).
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", JostleProvider.PROVIDER_NAME);
        kpg.initialize(new RSAKeyGenParameterSpec(2048, BigInteger.valueOf(3)));
        KeyPair kp = kpg.generateKeyPair();
        Assertions.assertEquals(BigInteger.valueOf(3),
                ((RSAPublicKey) kp.getPublic()).getPublicExponent());
    }

    @Test
    public void testKeyPairGenerator_rejectsExponentBelow3() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", JostleProvider.PROVIDER_NAME);
        for (BigInteger bad : new BigInteger[]{
                BigInteger.ZERO,
                BigInteger.ONE,
                BigInteger.valueOf(2),
                BigInteger.valueOf(-1)})
        {
            try
            {
                kpg.initialize(new RSAKeyGenParameterSpec(2048, bad));
                Assertions.fail("should have rejected exponent " + bad);
            }
            catch (InvalidAlgorithmParameterException e)
            {
                Assertions.assertEquals("public exponent must be >= 3", e.getMessage());
            }
        }
    }

    @Test
    public void testKeyPairGenerator_rejectsForeignParameterSpec() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", JostleProvider.PROVIDER_NAME);
        try
        {
            kpg.initialize(new AlgorithmParameterSpec() {});
            Assertions.fail();
        }
        catch (InvalidAlgorithmParameterException e)
        {
            Assertions.assertEquals("expected instance of RSAKeyGenParameterSpec", e.getMessage());
        }
    }

    /**
     * Modulus size below the project floor (1024 bits) is rejected on
     * both the int-only and AlgorithmParameterSpec init surfaces. The
     * floor exists because RSA-768 was factored in 2010 and RSA-829 in
     * 2020 — anything below 1024 bits is broken cryptographically.
     */
    @Test
    public void testKeyPairGenerator_rejectsKeySizeBelowMin() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", JostleProvider.PROVIDER_NAME);
        for (int badSize : new int[]{0, 1, 511, 512, 768, 1023})
        {
            try
            {
                kpg.initialize(badSize);
                Assertions.fail("should have rejected key size " + badSize);
            }
            catch (java.security.InvalidParameterException expected) {}

            try
            {
                kpg.initialize(new RSAKeyGenParameterSpec(badSize, RSAKeyGenParameterSpec.F4));
                Assertions.fail("should have rejected key size " + badSize + " via spec");
            }
            catch (InvalidAlgorithmParameterException expected) {}
        }
    }

    /**
     * Modulus size above the project ceiling (16384 bits) is rejected.
     * The ceiling exists because RSA keygen runtime is O(bits<sup>3</sup>);
     * a request for, say, 1,000,000 bits would never complete and could
     * exhaust memory. Provides DoS protection at the JCA boundary.
     */
    @Test
    public void testKeyPairGenerator_rejectsKeySizeAboveMax() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", JostleProvider.PROVIDER_NAME);
        for (int badSize : new int[]{16385, 32768, 100_000, Integer.MAX_VALUE})
        {
            try
            {
                kpg.initialize(badSize);
                Assertions.fail("should have rejected key size " + badSize);
            }
            catch (java.security.InvalidParameterException expected) {}

            try
            {
                kpg.initialize(new RSAKeyGenParameterSpec(badSize, RSAKeyGenParameterSpec.F4));
                Assertions.fail("should have rejected key size " + badSize + " via spec");
            }
            catch (InvalidAlgorithmParameterException expected) {}
        }
    }

    /**
     * Modulus size at the exact bounds is accepted. Sanity-check that
     * the boundary check is inclusive on both ends. (We don't actually
     * run keygen for 16384 bits — that's slow — but we DO run keygen
     * at 1024 to confirm the lower bound works end-to-end.)
     */
    @Test
    public void testKeyPairGenerator_acceptsBoundaryKeySizes() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", JostleProvider.PROVIDER_NAME);

        // Lower bound — exercise full keygen.
        kpg.initialize(1024);
        Assertions.assertNotNull(kpg.generateKeyPair());

        // Upper bound — initialize only (skip keygen for runtime).
        Assertions.assertDoesNotThrow(() ->
                kpg.initialize(new RSAKeyGenParameterSpec(16384, RSAKeyGenParameterSpec.F4)));
    }

    /**
     * Even public exponent is rejected. Per RSA, e must be coprime to
     * phi(n); for any RSA modulus phi(n) is even, so any even e shares
     * the factor 2 and produces a structurally broken key. Surface as
     * a typed exception with a clear message rather than letting it
     * propagate to OpenSSL.
     */
    @Test
    public void testKeyPairGenerator_rejectsEvenPublicExponent() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", JostleProvider.PROVIDER_NAME);
        for (BigInteger evenE : new BigInteger[]{
                BigInteger.valueOf(4),
                BigInteger.valueOf(6),
                BigInteger.valueOf(65536)})
        {
            try
            {
                kpg.initialize(new RSAKeyGenParameterSpec(2048, evenE));
                Assertions.fail("should have rejected even exponent " + evenE);
            }
            catch (InvalidAlgorithmParameterException e)
            {
                Assertions.assertTrue(e.getMessage().contains("must be odd"),
                        "expected 'must be odd' in message, got: " + e.getMessage());
            }
        }
    }


    // -----------------------------------------------------------------
    // PKCS#1 v1.5 signature round-trips
    // -----------------------------------------------------------------

    @Test
    public void testPkcs1_SHA256_roundTrip() throws Exception
    {
        signVerifyRoundTrip("SHA256withRSA", sharedKeyPair, randomMessage(1024));
    }

    @Test
    public void testPkcs1_AllRegisteredDigests_roundTrip() throws Exception
    {
        // Walk every PKCS#1 v1.5 digest variant the provider registers.
        // Each must produce a self-verifiable signature. MD5 is registered
        // for legacy interop only.
        String[] algs = {
                "MD5withRSA",
                "SHA1withRSA",
                "SHA224withRSA",
                "SHA256withRSA",
                "SHA384withRSA",
                "SHA512withRSA",
                "SHA3-224withRSA",
                "SHA3-256withRSA",
                "SHA3-384withRSA",
                "SHA3-512withRSA"
        };
        byte[] msg = randomMessage(256);
        for (String alg : algs)
        {
            signVerifyRoundTrip(alg, sharedKeyPair, msg);
        }
    }

    @Test
    public void testPkcs1_MD5withRSA_BCParity() throws Exception
    {
        // MD5 is registered for legacy interop. Sign with Jostle, verify
        // with BC, and the reverse, to confirm wire-compatible signatures.
        byte[] msg = randomMessage(256);

        Signature joSigner = Signature.getInstance("MD5withRSA", JostleProvider.PROVIDER_NAME);
        joSigner.initSign(sharedKeyPair.getPrivate());
        joSigner.update(msg);
        byte[] joSig = joSigner.sign();

        Signature bcVerifier = Signature.getInstance("MD5withRSA", BouncyCastleProvider.PROVIDER_NAME);
        bcVerifier.initVerify(sharedKeyPair.getPublic());
        bcVerifier.update(msg);
        Assertions.assertTrue(bcVerifier.verify(joSig));

        Signature bcSigner = Signature.getInstance("MD5withRSA", BouncyCastleProvider.PROVIDER_NAME);
        bcSigner.initSign(sharedKeyPair.getPrivate());
        bcSigner.update(msg);
        byte[] bcSig = bcSigner.sign();

        Signature joVerifier = Signature.getInstance("MD5withRSA", JostleProvider.PROVIDER_NAME);
        joVerifier.initVerify(sharedKeyPair.getPublic());
        joVerifier.update(msg);
        Assertions.assertTrue(joVerifier.verify(bcSig));
    }

    @Test
    public void testPkcs1_VandalisedMessageFails() throws Exception
    {
        byte[] msg = randomMessage(256);
        Signature signer = Signature.getInstance("SHA256withRSA", JostleProvider.PROVIDER_NAME);
        signer.initSign(sharedKeyPair.getPrivate());
        signer.update(msg);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance("SHA256withRSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(sharedKeyPair.getPublic());
        msg[0] ^= 1;
        verifier.update(msg);
        Assertions.assertFalse(verifier.verify(sig));
    }

    /**
     * Vandalism check across every registered PKCS#1 v1.5 digest variant.
     * A flipped byte in the message must cause verification to fail for
     * every digest — guards against a digest path that stub-returns a
     * fixed-length zero buffer or one that hashes only a prefix of the
     * input.
     */
    @Test
    public void testPkcs1_AllDigests_VandalisedMessage_rejected() throws Exception
    {
        String[] algs = {
                "MD5withRSA",
                "SHA1withRSA",
                "SHA224withRSA",
                "SHA256withRSA",
                "SHA384withRSA",
                "SHA512withRSA",
                "SHA3-224withRSA",
                "SHA3-256withRSA",
                "SHA3-384withRSA",
                "SHA3-512withRSA"
        };
        byte[] msg = randomMessage(256);
        for (String alg : algs)
        {
            Signature signer = Signature.getInstance(alg, JostleProvider.PROVIDER_NAME);
            signer.initSign(sharedKeyPair.getPrivate());
            signer.update(msg);
            byte[] sig = signer.sign();

            byte[] tampered = Arrays.clone(msg);
            tampered[42] ^= 1;

            Signature verifier = Signature.getInstance(alg, JostleProvider.PROVIDER_NAME);
            verifier.initVerify(sharedKeyPair.getPublic());
            verifier.update(tampered);
            Assertions.assertFalse(verifier.verify(sig),
                    alg + ": tampered message must not verify");
        }
    }

    /**
     * Streaming chunking matrix per CLAUDE.md: the same logical message
     * fed via different update patterns must produce byte-identical
     * signatures (PKCS#1 v1.5 is deterministic). Catches buffering bugs
     * where the partial-block path and the bulk path diverge.
     */
    @Test
    public void testPkcs1_SHA256_ChunkingMatrix_byteIdentical() throws Exception
    {
        byte[] msg = randomMessage(1024);
        byte[] reference = signWithChunking(msg, msg.length);

        // byte-by-byte
        byte[] byByte = signWithChunking(msg, 1);
        Assertions.assertArrayEquals(reference, byByte,
                "byte-by-byte signature diverged from one-shot");

        // Adversarial offsets around the SHA-256 block size (64 bytes).
        for (int chunk : new int[]{63, 64, 65})
        {
            byte[] chunked = signWithChunking(msg, chunk);
            Assertions.assertArrayEquals(reference, chunked,
                    "chunk=" + chunk + ": signature diverged from one-shot");
        }

        // Random splits: partition at unaligned offsets several times.
        for (int trial = 0; trial < 5; trial++)
        {
            byte[] randomChunked = signWithRandomSplits(msg);
            Assertions.assertArrayEquals(reference, randomChunked,
                    "random-split signature diverged from one-shot");
        }
    }

    private byte[] signWithChunking(byte[] msg, int chunk) throws Exception
    {
        Signature signer = Signature.getInstance("SHA256withRSA", JostleProvider.PROVIDER_NAME);
        signer.initSign(sharedKeyPair.getPrivate());
        for (int off = 0; off < msg.length; off += chunk)
        {
            int len = Math.min(chunk, msg.length - off);
            signer.update(msg, off, len);
        }
        return signer.sign();
    }

    private byte[] signWithRandomSplits(byte[] msg) throws Exception
    {
        Signature signer = Signature.getInstance("SHA256withRSA", JostleProvider.PROVIDER_NAME);
        signer.initSign(sharedKeyPair.getPrivate());
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

    @Test
    public void testPkcs1_VandalisedSignatureFails() throws Exception
    {
        byte[] msg = randomMessage(256);
        Signature signer = Signature.getInstance("SHA256withRSA", JostleProvider.PROVIDER_NAME);
        signer.initSign(sharedKeyPair.getPrivate());
        signer.update(msg);
        byte[] sig = signer.sign();
        sig[0] ^= 1;

        Signature verifier = Signature.getInstance("SHA256withRSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(sharedKeyPair.getPublic());
        verifier.update(msg);
        Assertions.assertFalse(verifier.verify(sig));
    }

    @Test
    public void testPkcs1_SignerResetAfterSign() throws Exception
    {
        byte[] msg = randomMessage(256);
        Signature signer = Signature.getInstance("SHA256withRSA", JostleProvider.PROVIDER_NAME);
        signer.initSign(sharedKeyPair.getPrivate());

        signer.update(msg);
        byte[] first = signer.sign();
        signer.update(msg);
        byte[] second = signer.sign();

        // Both signatures must verify. PKCS#1 v1.5 is deterministic so
        // they are also bit-equal — verify that too.
        Signature verifier = Signature.getInstance("SHA256withRSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(sharedKeyPair.getPublic());
        verifier.update(msg);
        Assertions.assertTrue(verifier.verify(first));

        verifier.initVerify(sharedKeyPair.getPublic());
        verifier.update(msg);
        Assertions.assertTrue(verifier.verify(second));

        Assertions.assertArrayEquals(first, second,
                "PKCS#1 v1.5 signatures over the same message must be deterministic");
    }


    /**
     * High-level (JCE Signature API) variant of the offset-write test
     * that lives in {@link RSALimitTest} at the NI layer. Validates the
     * full SPI path:
     * <ol>
     *   <li>fill the output buffer with random bytes (representing
     *       arbitrary caller state, not a chosen sentinel);</li>
     *   <li>sign into the buffer at {@code outOff = prefix} via
     *       {@link Signature#sign(byte[], int, int)};</li>
     *   <li>compare the prefix region against a saved-aside copy to
     *       confirm the bridge didn't write before {@code outOff};</li>
     *   <li>extract the signature from {@code big[prefix..prefix+sigLen]}
     *       and verify it succeeds against the original message;</li>
     *   <li>extract a 256-byte window starting ONE BYTE EARLIER (one
     *       byte INTO the random prefix) and verify it does NOT
     *       succeed — this proves the signature wrote at exactly
     *       {@code outOff}, not {@code outOff - 1}.</li>
     * </ol>
     */
    @Test
    public void testPkcs1_signWritesAtOffsetWithoutClobberingPrefix_jce() throws Exception
    {
        byte[] msg = randomMessage(64);

        Signature signer = Signature.getInstance("SHA256withRSA", JostleProvider.PROVIDER_NAME);
        signer.initSign(sharedKeyPair.getPrivate());
        signer.update(msg);

        // Sign once with a fresh signer to learn the signature length.
        byte[] firstSig = signer.sign();
        int sigLen = firstSig.length;
        Assertions.assertEquals(256, sigLen, "2048-bit modulus → 256-byte signature");

        // Re-init for the offset-write call.
        signer.initSign(sharedKeyPair.getPrivate());
        signer.update(msg);

        int prefix = 7;
        byte[] big = new byte[sigLen + prefix];
        new SecureRandom().nextBytes(big);
        byte[] expectedPrefix = new byte[prefix];
        System.arraycopy(big, 0, expectedPrefix, 0, prefix);

        // JCE offset-aware sign: writes the signature into big starting
        // at position `prefix`, returning the byte count written.
        int written = signer.sign(big, prefix, sigLen);
        Assertions.assertEquals(sigLen, written);

        // (1) Bridge contract: prefix bytes preceding outOff must be
        //     untouched.
        byte[] actualPrefix = new byte[prefix];
        System.arraycopy(big, 0, actualPrefix, 0, prefix);
        Assertions.assertArrayEquals(expectedPrefix, actualPrefix,
                "prefix bytes were modified by the JCE sign(out, offset, len) call");

        // (2) Positive functional check: the signature at
        //     big[prefix..prefix+sigLen] verifies against the original
        //     message. PKCS#1 v1.5 is deterministic so it also matches
        //     the firstSig we computed earlier.
        byte[] sigFromBig = new byte[sigLen];
        System.arraycopy(big, prefix, sigFromBig, 0, sigLen);
        Assertions.assertArrayEquals(firstSig, sigFromBig,
                "signature at offset " + prefix + " differs from the same "
                        + "message signed without an offset (PKCS#1 v1.5 must "
                        + "be deterministic)");

        Signature verifier = Signature.getInstance("SHA256withRSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(sharedKeyPair.getPublic());
        verifier.update(msg);
        Assertions.assertTrue(verifier.verify(sigFromBig),
                "signature at offset " + prefix + " did not verify against "
                        + "the original message");

        // (3) Negative boundary check: a sigLen-byte window starting ONE
        //     BYTE EARLIER (one byte INTO the random prefix) must NOT
        //     verify. Probability that 256 random bytes are a valid
        //     signature for the given message is ~2^-2048.
        byte[] shiftedSig = new byte[sigLen];
        System.arraycopy(big, prefix - 1, shiftedSig, 0, sigLen);

        verifier.initVerify(sharedKeyPair.getPublic());
        verifier.update(msg);
        boolean shiftedVerified;
        try
        {
            shiftedVerified = verifier.verify(shiftedSig);
        }
        catch (java.security.SignatureException expected)
        {
            // OpenSSL may surface structural errors (e.g. the BER
            // decode fails) as an exception via the verify wrapper —
            // that's also a correct rejection.
            shiftedVerified = false;
        }
        Assertions.assertFalse(shiftedVerified,
                "signature window shifted by 1 byte INTO the prefix "
                        + "verified successfully — sign() wrote at outOff-1 "
                        + "instead of at outOff=" + prefix);
    }


    // -----------------------------------------------------------------
    // RSASSA-PSS
    // -----------------------------------------------------------------

    @Test
    public void testPss_DefaultParameters_roundTrip() throws Exception
    {
        // Without setParameter PSS uses our default (SHA-256 / MGF1-SHA-256
        // / salt = digest length). Round-trip must succeed.
        byte[] msg = randomMessage(256);
        Signature signer = Signature.getInstance("RSASSA-PSS", JostleProvider.PROVIDER_NAME);
        signer.initSign(sharedKeyPair.getPrivate());
        signer.update(msg);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance("RSASSA-PSS", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(sharedKeyPair.getPublic());
        verifier.update(msg);
        Assertions.assertTrue(verifier.verify(sig));
    }

    @Test
    public void testPss_SHA384_explicitParams_roundTrip() throws Exception
    {
        byte[] msg = randomMessage(256);
        PSSParameterSpec params = new PSSParameterSpec(
                "SHA-384", "MGF1", new MGF1ParameterSpec("SHA-384"), 48, 1);

        Signature signer = Signature.getInstance("RSASSA-PSS", JostleProvider.PROVIDER_NAME);
        signer.setParameter(params);
        signer.initSign(sharedKeyPair.getPrivate());
        signer.update(msg);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance("RSASSA-PSS", JostleProvider.PROVIDER_NAME);
        verifier.setParameter(params);
        verifier.initVerify(sharedKeyPair.getPublic());
        verifier.update(msg);
        Assertions.assertTrue(verifier.verify(sig));
    }

    /**
     * Streaming chunking matrix per CLAUDE.md — PSS edition. PSS is
     * randomized (each call uses a fresh salt), so we cannot byte-compare
     * signatures. Instead, sign each chunking pattern and verify each
     * resulting signature with the one-shot verify path; then sign once
     * and verify the SAME signature through every chunking strategy.
     * SHA-256 block size = 64 bytes.
     */
    @Test
    public void testPss_SHA256_ChunkingMatrix_allVerify() throws Exception
    {
        SecureRandom sr = seededRandom("testPss_SHA256_ChunkingMatrix_allVerify");
        PSSParameterSpec params = new PSSParameterSpec(
                "SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), 32, 1);
        byte[] msg = randomMessage(sr, 1024);

        // Sign-side: prove every chunking pattern produces a signature
        // that verifies against the one-shot verify path.
        int[] chunks = {1, 63, 64, 65, 127, 128, 129, msg.length};
        for (int chunk : chunks)
        {
            byte[] sig = signWithChunking_PSS(params, msg, chunk);
            Assertions.assertTrue(verifyOneShot_PSS(params, msg, sig),
                    "sign-chunk=" + chunk + ": chunked-signed signature did not verify");
        }
        for (int trial = 0; trial < 5; trial++)
        {
            byte[] sig = signWithRandomSplits_PSS(params, sr, msg);
            Assertions.assertTrue(verifyOneShot_PSS(params, msg, sig),
                    "random-split trial=" + trial + ": signature did not verify");
        }

        // Verify-side: pin one signature, then verify it through every
        // chunking strategy. Catches divergence between bulk and
        // partial-block verify paths independent of the sign-side path.
        byte[] oneSig = signOneShot_PSS(params, msg);
        for (int chunk : chunks)
        {
            Assertions.assertTrue(verifyWithChunking_PSS(params, msg, oneSig, chunk),
                    "verify-chunk=" + chunk + ": chunked verify diverged from one-shot");
        }
        for (int trial = 0; trial < 5; trial++)
        {
            Assertions.assertTrue(verifyWithRandomSplits_PSS(params, sr, msg, oneSig),
                    "random-split verify trial=" + trial + ": verify diverged");
        }
    }

    private byte[] signOneShot_PSS(PSSParameterSpec params, byte[] msg) throws Exception
    {
        Signature signer = Signature.getInstance("RSASSA-PSS", JostleProvider.PROVIDER_NAME);
        signer.setParameter(params);
        signer.initSign(sharedKeyPair.getPrivate());
        signer.update(msg);
        return signer.sign();
    }

    private byte[] signWithChunking_PSS(PSSParameterSpec params, byte[] msg, int chunk) throws Exception
    {
        Signature signer = Signature.getInstance("RSASSA-PSS", JostleProvider.PROVIDER_NAME);
        signer.setParameter(params);
        signer.initSign(sharedKeyPair.getPrivate());
        for (int off = 0; off < msg.length; off += chunk)
        {
            int len = Math.min(chunk, msg.length - off);
            signer.update(msg, off, len);
        }
        return signer.sign();
    }

    private byte[] signWithRandomSplits_PSS(PSSParameterSpec params, SecureRandom sr, byte[] msg) throws Exception
    {
        Signature signer = Signature.getInstance("RSASSA-PSS", JostleProvider.PROVIDER_NAME);
        signer.setParameter(params);
        signer.initSign(sharedKeyPair.getPrivate());
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

    private boolean verifyOneShot_PSS(PSSParameterSpec params, byte[] msg, byte[] sig) throws Exception
    {
        Signature verifier = Signature.getInstance("RSASSA-PSS", JostleProvider.PROVIDER_NAME);
        verifier.setParameter(params);
        verifier.initVerify(sharedKeyPair.getPublic());
        verifier.update(msg);
        return verifier.verify(sig);
    }

    private boolean verifyWithChunking_PSS(PSSParameterSpec params, byte[] msg, byte[] sig, int chunk)
            throws Exception
    {
        Signature verifier = Signature.getInstance("RSASSA-PSS", JostleProvider.PROVIDER_NAME);
        verifier.setParameter(params);
        verifier.initVerify(sharedKeyPair.getPublic());
        for (int off = 0; off < msg.length; off += chunk)
        {
            int len = Math.min(chunk, msg.length - off);
            verifier.update(msg, off, len);
        }
        return verifier.verify(sig);
    }

    private boolean verifyWithRandomSplits_PSS(PSSParameterSpec params, SecureRandom sr, byte[] msg, byte[] sig)
            throws Exception
    {
        Signature verifier = Signature.getInstance("RSASSA-PSS", JostleProvider.PROVIDER_NAME);
        verifier.setParameter(params);
        verifier.initVerify(sharedKeyPair.getPublic());
        int pos = 0;
        while (pos < msg.length)
        {
            int remaining = msg.length - pos;
            int chunk = 1 + sr.nextInt(Math.max(1, remaining));
            chunk = Math.min(chunk, remaining);
            verifier.update(msg, pos, chunk);
            pos += chunk;
        }
        return verifier.verify(sig);
    }

    @Test
    public void testPkcs1_VerifierReuseAfterVerify() throws Exception
    {
        // Bind one signer, two messages, two signatures. Reuse a single
        // verifier instance across both verify() calls without
        // re-initVerify; reInit() inside the SPI must rebind the key
        // cleanly each time. Mix a known-bad signature in the middle to
        // prove the second-pass good signature still surfaces correctly
        // (catches a stale digest_ctx that would echo the previous result).
        byte[] msgA = randomMessage(64);
        byte[] msgB = randomMessage(96);

        Signature signer = Signature.getInstance("SHA256withRSA", JostleProvider.PROVIDER_NAME);
        signer.initSign(sharedKeyPair.getPrivate());
        signer.update(msgA);
        byte[] sigA = signer.sign();
        signer.update(msgB);
        byte[] sigB = signer.sign();

        Signature verifier = Signature.getInstance("SHA256withRSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(sharedKeyPair.getPublic());

        verifier.update(msgA);
        Assertions.assertTrue(verifier.verify(sigA), "first verify should pass");

        // Bad sig over msgB: ensure the SPI's reInit() clears state so
        // a previously-cached "true" cannot leak across calls.
        byte[] tampered = Arrays.clone(sigB);
        tampered[0] ^= 0x01;
        verifier.update(msgB);
        Assertions.assertFalse(verifier.verify(tampered),
                "tampered signature must fail even after a previous-pass verify");

        // Then a clean second verify with the real sigB.
        verifier.update(msgB);
        Assertions.assertTrue(verifier.verify(sigB),
                "good signature must verify even after a previous-fail verify");
    }

    @Test
    public void testPkcs1_RoleFlip_SignThenVerifyOnSameInstance() throws Exception
    {
        // Sign with private, then immediately initVerify(public) on the
        // SAME Signature instance and verify the result. Exercises the
        // RSASignatureSpiBase reInit-after-sign followed by an explicit
        // user re-init that flips the role. lastKey must be replaced
        // and not leak the prior private-key role.
        byte[] msg = randomMessage(48);
        Signature sig = Signature.getInstance("SHA256withRSA", JostleProvider.PROVIDER_NAME);

        sig.initSign(sharedKeyPair.getPrivate());
        sig.update(msg);
        byte[] s = sig.sign();

        sig.initVerify(sharedKeyPair.getPublic());
        sig.update(msg);
        Assertions.assertTrue(sig.verify(s),
                "verify on a Signature previously used to sign must succeed");

        // And the reverse: switch back to sign mode and produce a fresh
        // signature; confirm role change is bidirectional.
        sig.initSign(sharedKeyPair.getPrivate());
        sig.update(msg);
        byte[] s2 = sig.sign();
        Assertions.assertArrayEquals(s, s2,
                "PKCS#1 v1.5 is deterministic — round-trip on same instance must agree");
    }

    @Test
    public void testPss_NonRandomBetweenSignatures() throws Exception
    {
        // PSS uses random salt; two signatures over the same message
        // must differ (probability of collision is 2^-256 for 32-byte salt).
        byte[] msg = randomMessage(64);
        Signature signer = Signature.getInstance("RSASSA-PSS", JostleProvider.PROVIDER_NAME);
        signer.initSign(sharedKeyPair.getPrivate());

        signer.update(msg);
        byte[] first = signer.sign();
        signer.update(msg);
        byte[] second = signer.sign();

        Assertions.assertFalse(java.util.Arrays.equals(first, second),
                "PSS signatures must differ across calls (random salt)");
    }

    @Test
    public void testPss_RejectsForeignAlgorithmParameterSpec() throws Exception
    {
        Signature signer = Signature.getInstance("RSASSA-PSS", JostleProvider.PROVIDER_NAME);
        try
        {
            signer.setParameter(new AlgorithmParameterSpec() {});
            Assertions.fail();
        }
        catch (InvalidAlgorithmParameterException e)
        {
            Assertions.assertEquals("expected PSSParameterSpec", e.getMessage());
        }
    }

    @Test
    public void testPss_RejectsNonMGF1() throws Exception
    {
        Signature signer = Signature.getInstance("RSASSA-PSS", JostleProvider.PROVIDER_NAME);
        // PSSParameterSpec ctor accepts arbitrary MGF strings — that's how
        // we trigger our explicit MGF1 check.
        PSSParameterSpec bad = new PSSParameterSpec(
                "SHA-256", "MGF2", new MGF1ParameterSpec("SHA-256"), 32, 1);
        try
        {
            signer.setParameter(bad);
            Assertions.fail();
        }
        catch (InvalidAlgorithmParameterException e)
        {
            Assertions.assertTrue(e.getMessage().contains("MGF1"),
                    "expected MGF1 rejection, got: " + e.getMessage());
        }
    }

    @Test
    public void testPss_RejectsTrailerOtherThan1() throws Exception
    {
        Signature signer = Signature.getInstance("RSASSA-PSS", JostleProvider.PROVIDER_NAME);
        PSSParameterSpec bad = new PSSParameterSpec(
                "SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), 32, 7);
        try
        {
            signer.setParameter(bad);
            Assertions.fail();
        }
        catch (InvalidAlgorithmParameterException e)
        {
            Assertions.assertEquals("trailer field must be 1 (got 7)", e.getMessage());
        }
    }

    @Test
    public void testPss_VandalisedSignatureFails() throws Exception
    {
        byte[] msg = randomMessage(256);
        Signature signer = Signature.getInstance("RSASSA-PSS", JostleProvider.PROVIDER_NAME);
        signer.initSign(sharedKeyPair.getPrivate());
        signer.update(msg);
        byte[] sig = signer.sign();
        sig[0] ^= 1;

        Signature verifier = Signature.getInstance("RSASSA-PSS", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(sharedKeyPair.getPublic());
        verifier.update(msg);
        Assertions.assertFalse(verifier.verify(sig));
    }

    /**
     * Distinct from {@link #testPss_VandalisedSignatureFails} —
     * exercises the message-input path rather than the signature path.
     * A correctly-formed PSS signature over a different message must
     * not verify.
     */
    @Test
    public void testPss_VandalisedMessageFails() throws Exception
    {
        byte[] msg = randomMessage(256);
        Signature signer = Signature.getInstance("RSASSA-PSS", JostleProvider.PROVIDER_NAME);
        signer.initSign(sharedKeyPair.getPrivate());
        signer.update(msg);
        byte[] sig = signer.sign();

        msg[100] ^= 1;
        Signature verifier = Signature.getInstance("RSASSA-PSS", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(sharedKeyPair.getPublic());
        verifier.update(msg);
        Assertions.assertFalse(verifier.verify(sig));
    }


    // -----------------------------------------------------------------
    // BC ↔ Jostle cross-validation (PKCS#1 v1.5)
    // -----------------------------------------------------------------

    @Test
    public void testBC_to_Jostle_pkcs1_SHA256() throws Exception
    {
        byte[] msg = randomMessage(256);
        Signature bcSigner = Signature.getInstance("SHA256withRSA", BouncyCastleProvider.PROVIDER_NAME);
        bcSigner.initSign(sharedKeyPair.getPrivate());
        bcSigner.update(msg);
        byte[] sig = bcSigner.sign();

        Signature joVerifier = Signature.getInstance("SHA256withRSA", JostleProvider.PROVIDER_NAME);
        joVerifier.initVerify(sharedKeyPair.getPublic());
        joVerifier.update(msg);
        Assertions.assertTrue(joVerifier.verify(sig));
    }

    @Test
    public void testJostle_to_BC_pkcs1_SHA256() throws Exception
    {
        byte[] msg = randomMessage(256);
        Signature joSigner = Signature.getInstance("SHA256withRSA", JostleProvider.PROVIDER_NAME);
        joSigner.initSign(sharedKeyPair.getPrivate());
        joSigner.update(msg);
        byte[] sig = joSigner.sign();

        Signature bcVerifier = Signature.getInstance("SHA256withRSA", BouncyCastleProvider.PROVIDER_NAME);
        bcVerifier.initVerify(sharedKeyPair.getPublic());
        bcVerifier.update(msg);
        Assertions.assertTrue(bcVerifier.verify(sig));
    }

    @Test
    public void testJostle_to_BC_pkcs1_SHA512() throws Exception
    {
        byte[] msg = randomMessage(256);
        Signature joSigner = Signature.getInstance("SHA512withRSA", JostleProvider.PROVIDER_NAME);
        joSigner.initSign(sharedKeyPair.getPrivate());
        joSigner.update(msg);
        byte[] sig = joSigner.sign();

        Signature bcVerifier = Signature.getInstance("SHA512withRSA", BouncyCastleProvider.PROVIDER_NAME);
        bcVerifier.initVerify(sharedKeyPair.getPublic());
        bcVerifier.update(msg);
        Assertions.assertTrue(bcVerifier.verify(sig));
    }


    // -----------------------------------------------------------------
    // BC ↔ Jostle cross-validation (PSS)
    // -----------------------------------------------------------------

    @Test
    public void testBC_to_Jostle_PSS_SHA256() throws Exception
    {
        byte[] msg = randomMessage(256);
        PSSParameterSpec params = new PSSParameterSpec(
                "SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), 32, 1);

        Signature bcSigner = Signature.getInstance("RSASSA-PSS", BouncyCastleProvider.PROVIDER_NAME);
        bcSigner.setParameter(params);
        bcSigner.initSign(sharedKeyPair.getPrivate());
        bcSigner.update(msg);
        byte[] sig = bcSigner.sign();

        Signature joVerifier = Signature.getInstance("RSASSA-PSS", JostleProvider.PROVIDER_NAME);
        joVerifier.setParameter(params);
        joVerifier.initVerify(sharedKeyPair.getPublic());
        joVerifier.update(msg);
        Assertions.assertTrue(joVerifier.verify(sig));
    }

    @Test
    public void testJostle_to_BC_PSS_SHA256() throws Exception
    {
        byte[] msg = randomMessage(256);
        PSSParameterSpec params = new PSSParameterSpec(
                "SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), 32, 1);

        Signature joSigner = Signature.getInstance("RSASSA-PSS", JostleProvider.PROVIDER_NAME);
        joSigner.setParameter(params);
        joSigner.initSign(sharedKeyPair.getPrivate());
        joSigner.update(msg);
        byte[] sig = joSigner.sign();

        Signature bcVerifier = Signature.getInstance("RSASSA-PSS", BouncyCastleProvider.PROVIDER_NAME);
        bcVerifier.setParameter(params);
        bcVerifier.initVerify(sharedKeyPair.getPublic());
        bcVerifier.update(msg);
        Assertions.assertTrue(bcVerifier.verify(sig));
    }


    // -----------------------------------------------------------------
    // Multi-trial agreement tests (CLAUDE.md "Run agreement tests
    // against BouncyCastle, with random inputs")
    // -----------------------------------------------------------------

    /**
     * Per-trial fresh keypair, random message length, both directions,
     * every PKCS#1 v1.5 digest variant. Covers the gap that previous
     * single-trial BC-parity tests using the shared keypair leave —
     * a key-bit-pattern-dependent bug or a finalisation off-by-one
     * that only fires at certain message lengths.
     */
    @Test
    public void testPkcs1_AgreementWithBC_AllDigests_MultiTrial() throws Exception
    {
        SecureRandom sr = seededRandom("testPkcs1_AgreementWithBC_AllDigests_MultiTrial");
        String[] algs = {
                "MD5withRSA", "SHA1withRSA",
                "SHA224withRSA", "SHA256withRSA", "SHA384withRSA", "SHA512withRSA",
                "SHA3-224withRSA", "SHA3-256withRSA", "SHA3-384withRSA", "SHA3-512withRSA"
        };

        for (int trial = 0; trial < 10; trial++)
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", JostleProvider.PROVIDER_NAME);
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();

            int msgLen = 1 + sr.nextInt(2048);
            byte[] msg = new byte[msgLen];
            sr.nextBytes(msg);

            for (String alg : algs)
            {
                // Jostle sign → BC verify
                Signature joSign = Signature.getInstance(alg, JostleProvider.PROVIDER_NAME);
                joSign.initSign(kp.getPrivate());
                joSign.update(msg);
                byte[] joSig = joSign.sign();

                Signature bcVer = Signature.getInstance(alg, BouncyCastleProvider.PROVIDER_NAME);
                bcVer.initVerify(kp.getPublic());
                bcVer.update(msg);
                Assertions.assertTrue(bcVer.verify(joSig),
                        "trial=" + trial + " " + alg + ": BC failed to verify Jostle's signature");

                // BC sign → Jostle verify
                Signature bcSign = Signature.getInstance(alg, BouncyCastleProvider.PROVIDER_NAME);
                bcSign.initSign(kp.getPrivate());
                bcSign.update(msg);
                byte[] bcSig = bcSign.sign();

                Signature joVer = Signature.getInstance(alg, JostleProvider.PROVIDER_NAME);
                joVer.initVerify(kp.getPublic());
                joVer.update(msg);
                Assertions.assertTrue(joVer.verify(bcSig),
                        "trial=" + trial + " " + alg + ": Jostle failed to verify BC's signature");
            }
        }
    }

    /**
     * Multi-trial PSS agreement with varied (digest, salt length)
     * tuples per trial. Note: BC's {@code PSSSignatureSpi} rejects
     * asymmetric digest/MGF1 combinations ("digest algorithm for MGF
     * should be the same as for PSS parameters") even though RFC 8017
     * permits them — so MGF1 digest is forced to match the PSS digest
     * here. Asymmetric combinations are still exercised against BC's
     * OAEP cipher (which doesn't enforce that restriction); see
     * {@code testOAEP_SHA384_MGF1SHA256_BCDecrypt_Cross}.
     */
    @Test
    public void testPss_AgreementWithBC_VariedParams_MultiTrial() throws Exception
    {
        SecureRandom sr = seededRandom("testPss_AgreementWithBC_VariedParams_MultiTrial");
        String[] digests = {"SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-512"};

        for (int trial = 0; trial < 10; trial++)
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", JostleProvider.PROVIDER_NAME);
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();

            String digest = digests[sr.nextInt(digests.length)];
            int hashLen = digestOutputBytes(digest);
            int saltLen = sr.nextInt(hashLen + 1); // 0..hashLen

            PSSParameterSpec params = new PSSParameterSpec(
                    digest, "MGF1", new MGF1ParameterSpec(digest), saltLen, 1);

            int msgLen = 1 + sr.nextInt(2048);
            byte[] msg = new byte[msgLen];
            sr.nextBytes(msg);

            // Jostle sign → BC verify
            Signature joSign = Signature.getInstance("RSASSA-PSS", JostleProvider.PROVIDER_NAME);
            joSign.setParameter(params);
            joSign.initSign(kp.getPrivate());
            joSign.update(msg);
            byte[] joSig = joSign.sign();

            Signature bcVer = Signature.getInstance("RSASSA-PSS", BouncyCastleProvider.PROVIDER_NAME);
            bcVer.setParameter(params);
            bcVer.initVerify(kp.getPublic());
            bcVer.update(msg);
            Assertions.assertTrue(bcVer.verify(joSig),
                    "trial=" + trial + " digest=" + digest
                            + " salt=" + saltLen + " msgLen=" + msgLen
                            + ": BC failed to verify Jostle's PSS signature");

            // BC sign → Jostle verify
            Signature bcSign = Signature.getInstance("RSASSA-PSS", BouncyCastleProvider.PROVIDER_NAME);
            bcSign.setParameter(params);
            bcSign.initSign(kp.getPrivate());
            bcSign.update(msg);
            byte[] bcSig = bcSign.sign();

            Signature joVer = Signature.getInstance("RSASSA-PSS", JostleProvider.PROVIDER_NAME);
            joVer.setParameter(params);
            joVer.initVerify(kp.getPublic());
            joVer.update(msg);
            Assertions.assertTrue(joVer.verify(bcSig),
                    "trial=" + trial + " digest=" + digest
                            + " salt=" + saltLen + ": Jostle failed to verify BC's PSS signature");
        }
    }


    // -----------------------------------------------------------------
    // Cross-provider key encoding interop (CLAUDE.md "every key type
    // must round-trip through BouncyCastle's encoding")
    // -----------------------------------------------------------------

    /**
     * Public-key X.509 encoding: encode with Jostle, decode with BC,
     * use to verify a signature; AND encode with BC, decode with Jostle,
     * use to verify. Surfaces wrong-OID emission, mis-encoded
     * parameters, and asymmetric encode/decode acceptance bugs.
     */
    @Test
    public void testKeyEncoding_X509_BCAndJostleInterop_MultiTrial() throws Exception
    {
        SecureRandom sr = seededRandom("testKeyEncoding_X509_BCAndJostleInterop_MultiTrial");

        for (int trial = 0; trial < 10; trial++)
        {
            byte[] msg = new byte[1 + sr.nextInt(512)];
            sr.nextBytes(msg);

            // (1) Jostle generates → encode → BC decodes → BC verifies a Jostle sig.
            KeyPairGenerator joKpg = KeyPairGenerator.getInstance("RSA", JostleProvider.PROVIDER_NAME);
            joKpg.initialize(2048);
            KeyPair joKp = joKpg.generateKeyPair();
            byte[] joPubX509 = joKp.getPublic().getEncoded();
            Assertions.assertNotNull(joPubX509, "trial=" + trial + ": Jostle pub.getEncoded() returned null");

            KeyFactory bcKf = KeyFactory.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
            PublicKey bcViewOfJostlePub = bcKf.generatePublic(new X509EncodedKeySpec(joPubX509));
            Assertions.assertEquals("RSA", bcViewOfJostlePub.getAlgorithm());

            Signature joSign = Signature.getInstance("SHA256withRSA", JostleProvider.PROVIDER_NAME);
            joSign.initSign(joKp.getPrivate());
            joSign.update(msg);
            byte[] sig = joSign.sign();

            Signature bcVer = Signature.getInstance("SHA256withRSA", BouncyCastleProvider.PROVIDER_NAME);
            bcVer.initVerify(bcViewOfJostlePub);
            bcVer.update(msg);
            Assertions.assertTrue(bcVer.verify(sig),
                    "trial=" + trial + ": BC could not verify with Jostle-encoded pub key");

            // (2) BC generates → encode → Jostle decodes → Jostle verifies a BC sig.
            KeyPairGenerator bcKpg = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
            bcKpg.initialize(2048);
            KeyPair bcKp = bcKpg.generateKeyPair();
            byte[] bcPubX509 = bcKp.getPublic().getEncoded();

            KeyFactory joKf = KeyFactory.getInstance("RSA", JostleProvider.PROVIDER_NAME);
            PublicKey joViewOfBcPub = joKf.generatePublic(new X509EncodedKeySpec(bcPubX509));
            Assertions.assertEquals("RSA", joViewOfBcPub.getAlgorithm());

            Signature bcSign = Signature.getInstance("SHA256withRSA", BouncyCastleProvider.PROVIDER_NAME);
            bcSign.initSign(bcKp.getPrivate());
            bcSign.update(msg);
            byte[] sig2 = bcSign.sign();

            Signature joVer = Signature.getInstance("SHA256withRSA", JostleProvider.PROVIDER_NAME);
            joVer.initVerify(joViewOfBcPub);
            joVer.update(msg);
            Assertions.assertTrue(joVer.verify(sig2),
                    "trial=" + trial + ": Jostle could not verify with BC-encoded pub key");
        }
    }

    /**
     * Private-key PKCS#8 encoding: encode with Jostle, decode with BC,
     * use to sign; AND encode with BC, decode with Jostle, use to sign.
     * The CRT components must survive the round-trip in both directions.
     */
    @Test
    public void testKeyEncoding_PKCS8_BCAndJostleInterop_MultiTrial() throws Exception
    {
        SecureRandom sr = seededRandom("testKeyEncoding_PKCS8_BCAndJostleInterop_MultiTrial");

        for (int trial = 0; trial < 10; trial++)
        {
            byte[] msg = new byte[1 + sr.nextInt(512)];
            sr.nextBytes(msg);

            // (1) Jostle priv → encode → BC decodes → BC signs → Jostle verifies (with same Jostle pub).
            KeyPairGenerator joKpg = KeyPairGenerator.getInstance("RSA", JostleProvider.PROVIDER_NAME);
            joKpg.initialize(2048);
            KeyPair joKp = joKpg.generateKeyPair();
            byte[] joPrivPkcs8 = joKp.getPrivate().getEncoded();
            Assertions.assertNotNull(joPrivPkcs8, "trial=" + trial + ": Jostle priv.getEncoded() returned null");

            KeyFactory bcKf = KeyFactory.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
            PrivateKey bcViewOfJostlePriv = bcKf.generatePrivate(new PKCS8EncodedKeySpec(joPrivPkcs8));

            Signature bcSign = Signature.getInstance("SHA256withRSA", BouncyCastleProvider.PROVIDER_NAME);
            bcSign.initSign(bcViewOfJostlePriv);
            bcSign.update(msg);
            byte[] sig = bcSign.sign();

            Signature joVer = Signature.getInstance("SHA256withRSA", JostleProvider.PROVIDER_NAME);
            joVer.initVerify(joKp.getPublic());
            joVer.update(msg);
            Assertions.assertTrue(joVer.verify(sig),
                    "trial=" + trial + ": Jostle pub could not verify a signature made with BC using Jostle-encoded priv");

            // (2) BC priv → encode → Jostle decodes → Jostle signs → BC verifies (with same BC pub).
            KeyPairGenerator bcKpg = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
            bcKpg.initialize(2048);
            KeyPair bcKp = bcKpg.generateKeyPair();
            byte[] bcPrivPkcs8 = bcKp.getPrivate().getEncoded();

            KeyFactory joKf = KeyFactory.getInstance("RSA", JostleProvider.PROVIDER_NAME);
            PrivateKey joViewOfBcPriv = joKf.generatePrivate(new PKCS8EncodedKeySpec(bcPrivPkcs8));

            Signature joSign = Signature.getInstance("SHA256withRSA", JostleProvider.PROVIDER_NAME);
            joSign.initSign(joViewOfBcPriv);
            joSign.update(msg);
            byte[] sig2 = joSign.sign();

            Signature bcVer = Signature.getInstance("SHA256withRSA", BouncyCastleProvider.PROVIDER_NAME);
            bcVer.initVerify(bcKp.getPublic());
            bcVer.update(msg);
            Assertions.assertTrue(bcVer.verify(sig2),
                    "trial=" + trial + ": BC pub could not verify a signature made with Jostle using BC-encoded priv");
        }
    }


    // -----------------------------------------------------------------
    // KeyFactory: encoded-form round-trip
    // -----------------------------------------------------------------

    @Test
    public void testKeyFactory_X509_PKCS8_roundTrip() throws Exception
    {
        KeyFactory kf = KeyFactory.getInstance("RSA", JostleProvider.PROVIDER_NAME);

        byte[] pubEnc = sharedKeyPair.getPublic().getEncoded();
        byte[] privEnc = sharedKeyPair.getPrivate().getEncoded();
        Assertions.assertNotNull(pubEnc);
        Assertions.assertNotNull(privEnc);

        PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(pubEnc));
        PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(privEnc));

        byte[] msg = randomMessage(256);
        Signature signer = Signature.getInstance("SHA256withRSA", JostleProvider.PROVIDER_NAME);
        signer.initSign(priv);
        signer.update(msg);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance("SHA256withRSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(pub);
        verifier.update(msg);
        Assertions.assertTrue(verifier.verify(sig));
    }


    // -----------------------------------------------------------------
    // KeyFactory: component specs
    // -----------------------------------------------------------------

    @Test
    public void testKeyFactory_RSAPublicKeySpec_roundTrip() throws Exception
    {
        KeyFactory kf = KeyFactory.getInstance("RSA", JostleProvider.PROVIDER_NAME);
        RSAPublicKey original = (RSAPublicKey) sharedKeyPair.getPublic();

        PublicKey reborn = kf.generatePublic(new RSAPublicKeySpec(
                original.getModulus(), original.getPublicExponent()));

        Assertions.assertEquals(original.getModulus(),
                ((RSAPublicKey) reborn).getModulus());
        Assertions.assertEquals(original.getPublicExponent(),
                ((RSAPublicKey) reborn).getPublicExponent());

        // Use the reborn key to verify a signature made with the original.
        byte[] msg = randomMessage(64);
        Signature signer = Signature.getInstance("SHA256withRSA", JostleProvider.PROVIDER_NAME);
        signer.initSign(sharedKeyPair.getPrivate());
        signer.update(msg);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance("SHA256withRSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(reborn);
        verifier.update(msg);
        Assertions.assertTrue(verifier.verify(sig));
    }

    @Test
    public void testKeyFactory_RSAPrivateCrtKeySpec_roundTrip() throws Exception
    {
        KeyFactory kf = KeyFactory.getInstance("RSA", JostleProvider.PROVIDER_NAME);

        // Round-trip our own private key through RSAPrivateCrtKeySpec.
        // engineGetKeySpec→RSAPrivateCrtKeySpec must yield non-null CRT
        // components on a Jostle-generated keypair (always CRT).
        RSAPrivateCrtKeySpec crtSpec = kf.getKeySpec(sharedKeyPair.getPrivate(),
                RSAPrivateCrtKeySpec.class);

        Assertions.assertNotNull(crtSpec.getPrimeP());
        Assertions.assertNotNull(crtSpec.getPrimeQ());
        Assertions.assertNotNull(crtSpec.getCrtCoefficient());

        PrivateKey reborn = kf.generatePrivate(crtSpec);

        // Sign with reborn, verify with original.
        byte[] msg = randomMessage(64);
        Signature signer = Signature.getInstance("SHA256withRSA", JostleProvider.PROVIDER_NAME);
        signer.initSign(reborn);
        signer.update(msg);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance("SHA256withRSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(sharedKeyPair.getPublic());
        verifier.update(msg);
        Assertions.assertTrue(verifier.verify(sig));
    }

    @Test
    public void testKeyFactory_RSAPrivateKeySpec_isRejected() throws Exception
    {
        KeyFactory kf = KeyFactory.getInstance("RSA", JostleProvider.PROVIDER_NAME);
        // We can pull a non-CRT spec from the key (it just discards CRT data),
        // but generating from one must fail.
        RSAPrivateKeySpec basic = kf.getKeySpec(sharedKeyPair.getPrivate(),
                RSAPrivateKeySpec.class);
        try
        {
            kf.generatePrivate(basic);
            Assertions.fail();
        }
        catch (InvalidKeySpecException e)
        {
            Assertions.assertTrue(e.getMessage().contains("RSAPrivateKeySpec"),
                    "expected RSAPrivateKeySpec rejection: " + e.getMessage());
        }
    }


    // -----------------------------------------------------------------
    // CRT components — Jostle private keys must expose them
    // -----------------------------------------------------------------

    @Test
    public void testCrtComponents_present() throws Exception
    {
        // The KeyPairGenerator only ever produces CRT-form private keys,
        // so all CRT getters must return non-null.
        Assertions.assertTrue(sharedKeyPair.getPrivate() instanceof RSAPrivateCrtKey);
        RSAPrivateCrtKey priv = (RSAPrivateCrtKey) sharedKeyPair.getPrivate();
        Assertions.assertNotNull(priv.getPrimeP());
        Assertions.assertNotNull(priv.getPrimeQ());
        Assertions.assertNotNull(priv.getPrimeExponentP());
        Assertions.assertNotNull(priv.getPrimeExponentQ());
        Assertions.assertNotNull(priv.getCrtCoefficient());

        // Sanity: p * q == modulus.
        Assertions.assertEquals(priv.getModulus(),
                priv.getPrimeP().multiply(priv.getPrimeQ()),
                "p × q must equal modulus");
    }


    // -----------------------------------------------------------------
    // Wrong-key-type rejection
    // -----------------------------------------------------------------

    @Test
    public void testInitSign_rejectsNonRSAKey() throws Exception
    {
        // A clearly-foreign key for an RSA Signature SPI must trigger
        // an InvalidKeyException through the JCE.
        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        ec.initialize(256);
        KeyPair ecKp = ec.generateKeyPair();

        Signature sig = Signature.getInstance("SHA256withRSA", JostleProvider.PROVIDER_NAME);
        try
        {
            sig.initSign(ecKp.getPrivate());
            Assertions.fail();
        }
        catch (InvalidKeyException expected) {}
    }

    @Test
    public void testInitVerify_rejectsNonRSAKey() throws Exception
    {
        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        ec.initialize(256);
        KeyPair ecKp = ec.generateKeyPair();

        Signature sig = Signature.getInstance("SHA256withRSA", JostleProvider.PROVIDER_NAME);
        try
        {
            sig.initVerify(ecKp.getPublic());
            Assertions.fail();
        }
        catch (InvalidKeyException expected) {}
    }


    // -----------------------------------------------------------------
    // OID alias resolution
    // -----------------------------------------------------------------

    @Test
    public void testOidAliases_resolveToRegisteredAlgorithms() throws Exception
    {
        // Smoke-test a couple of OID aliases.
        Signature sigSha256 = Signature.getInstance("1.2.840.113549.1.1.11",
                JostleProvider.PROVIDER_NAME);
        sigSha256.initSign(sharedKeyPair.getPrivate());
        sigSha256.update(new byte[]{1, 2, 3});
        byte[] s = sigSha256.sign();
        Assertions.assertTrue(s.length > 0);

        Signature sigPss = Signature.getInstance("1.2.840.113549.1.1.10",
                JostleProvider.PROVIDER_NAME);
        sigPss.initSign(sharedKeyPair.getPrivate());
        sigPss.update(new byte[]{1, 2, 3});
        byte[] sp = sigPss.sign();
        Assertions.assertTrue(sp.length > 0);
    }


    // -----------------------------------------------------------------
    // JCE state-machine: pre-init misuse must surface IllegalStateException,
    // not NPE on the underlying native ref. Mirrors the requireInitialised()
    // guard added to RSASignatureSpiBase.
    // -----------------------------------------------------------------

    @Test
    public void testSignature_UpdateWithoutInit_throwsIllegalState() throws Exception
    {
        Signature sig = Signature.getInstance("SHA256withRSA", JostleProvider.PROVIDER_NAME);
        try
        {
            sig.update(new byte[]{1, 2, 3});
            Assertions.fail();
        }
        catch (IllegalStateException | java.security.SignatureException expected)
        {
            // The JCE wrapper may translate IllegalStateException into
            // SignatureException for Signature.update; either is acceptable
            // as long as we don't escape NPE from the native layer.
        }
    }

    @Test
    public void testSignature_SignWithoutInit_throwsIllegalState() throws Exception
    {
        Signature sig = Signature.getInstance("SHA256withRSA", JostleProvider.PROVIDER_NAME);
        try
        {
            sig.sign();
            Assertions.fail();
        }
        catch (IllegalStateException | java.security.SignatureException expected) {}
    }

    @Test
    public void testSignature_VerifyWithoutInit_throwsIllegalState() throws Exception
    {
        Signature sig = Signature.getInstance("SHA256withRSA", JostleProvider.PROVIDER_NAME);
        try
        {
            sig.verify(new byte[]{1, 2, 3});
            Assertions.fail();
        }
        catch (IllegalStateException | java.security.SignatureException expected) {}
    }

    @Test
    public void testPSS_UpdateWithoutInit_throwsIllegalState() throws Exception
    {
        Signature sig = Signature.getInstance("RSASSA-PSS", JostleProvider.PROVIDER_NAME);
        try
        {
            sig.update(new byte[]{1, 2, 3});
            Assertions.fail();
        }
        catch (IllegalStateException | java.security.SignatureException expected) {}
    }

    @Test
    public void testPSS_SignWithoutInit_throwsIllegalState() throws Exception
    {
        Signature sig = Signature.getInstance("RSASSA-PSS", JostleProvider.PROVIDER_NAME);
        try
        {
            sig.sign();
            Assertions.fail();
        }
        catch (IllegalStateException | java.security.SignatureException expected) {}
    }


    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private static void signVerifyRoundTrip(String alg, KeyPair kp, byte[] msg)
            throws Exception
    {
        Signature signer = Signature.getInstance(alg, JostleProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());
        signer.update(msg);
        byte[] sig = signer.sign();
        Assertions.assertTrue(sig.length > 0, alg + ": empty signature");

        Signature verifier = Signature.getInstance(alg, JostleProvider.PROVIDER_NAME);
        verifier.initVerify(kp.getPublic());
        verifier.update(msg);
        Assertions.assertTrue(verifier.verify(sig), alg + ": failed self-verification");
    }

    private static byte[] randomMessage(int len)
    {
        byte[] m = new byte[len];
        RANDOM.nextBytes(m);
        return m;
    }

    /**
     * The RSA KeyFactory must import an {@code id-RSASSA-PSS}-tagged
     * key (OID 1.2.840.113549.1.1.10) — the encoding TLS 1.3
     * {@code rsa_pss_pss_*} certificates carry — treating it as a plain RSA
     * key, as BC/SunRsaSign do (JCA/TLS gap #7). An RSASSA-PSS key is
     * structurally identical to an rsaEncryption one.
     */
    @Test
    public void testKeyFactory_importsIdRSASSAPSSEncodedKey() throws Exception
    {
        // Base keypair from BC so the encodings are proper PKCS#8 / X.509 that
        // BC's ASN.1 can re-wrap (JSL's RSA getEncoded for the private key is
        // traditional PKCS#1, which PrivateKeyInfo.getInstance won't parse).
        KeyPairGenerator bcKpg = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        bcKpg.initialize(2048);
        KeyPair bcKp = bcKpg.generateKeyPair();

        // Re-wrap the same key bits under the id-RSASSA-PSS OID (params absent),
        // the form TLS rsa_pss_pss_* certificates carry.
        org.bouncycastle.asn1.x509.SubjectPublicKeyInfo spki =
                org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(bcKp.getPublic().getEncoded());
        byte[] pssPub = new org.bouncycastle.asn1.x509.SubjectPublicKeyInfo(
                new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                        org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_RSASSA_PSS),
                spki.getPublicKeyData().getBytes()).getEncoded();

        org.bouncycastle.asn1.pkcs.PrivateKeyInfo pki =
                org.bouncycastle.asn1.pkcs.PrivateKeyInfo.getInstance(bcKp.getPrivate().getEncoded());
        byte[] pssPriv = new org.bouncycastle.asn1.pkcs.PrivateKeyInfo(
                new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                        org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_RSASSA_PSS),
                pki.parsePrivateKey()).getEncoded();

        KeyFactory kf = KeyFactory.getInstance("RSA", JostleProvider.PROVIDER_NAME);
        PublicKey jslPub = kf.generatePublic(new X509EncodedKeySpec(pssPub));
        PrivateKey jslPriv = kf.generatePrivate(new PKCS8EncodedKeySpec(pssPriv));

        Assertions.assertTrue(jslPub instanceof RSAPublicKey, "imported key is not an RSA public key");
        Assertions.assertEquals(((RSAPublicKey) bcKp.getPublic()).getModulus(),
                ((RSAPublicKey) jslPub).getModulus(), "public modulus differs after import");
        Assertions.assertEquals(
                ((java.security.interfaces.RSAPrivateKey) bcKp.getPrivate()).getModulus(),
                ((java.security.interfaces.RSAPrivateKey) jslPriv).getModulus(),
                "private modulus differs after import");

        // The imported key is a plain RSA key: it re-encodes identically to a
        // JSL import of the equivalent rsaEncryption SPKI (PSS OID is dropped).
        PublicKey jslPlain = kf.generatePublic(new X509EncodedKeySpec(bcKp.getPublic().getEncoded()));
        Assertions.assertArrayEquals(jslPlain.getEncoded(), jslPub.getEncoded(),
                "imported id-RSASSA-PSS key did not canonicalise to plain rsaEncryption");

        // ...and it functions: a PSS round-trip with the imported keys verifies.
        SecureRandom sr = seededRandom("testKeyFactory_importsIdRSASSAPSSEncodedKey");
        byte[] msg = randomMessage(sr, 1 + sr.nextInt(256));
        Signature signer = Signature.getInstance("SHA256withRSAandMGF1", JostleProvider.PROVIDER_NAME);
        signer.initSign(jslPriv);
        signer.update(msg);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance("SHA256withRSAandMGF1", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(jslPub);
        verifier.update(msg);
        Assertions.assertTrue(verifier.verify(sig), "PSS round-trip with imported id-RSASSA-PSS key failed");

        // Negative: a tampered message must not verify — proves the imported
        // public key actually checks the signature (not a stub that accepts all).
        byte[] tampered = Arrays.clone(msg);
        tampered[sr.nextInt(tampered.length)] ^= 0x01;
        Signature badVerifier = Signature.getInstance("SHA256withRSAandMGF1", JostleProvider.PROVIDER_NAME);
        badVerifier.initVerify(jslPub);
        badVerifier.update(tampered);
        Assertions.assertFalse(badVerifier.verify(sig),
                "imported id-RSASSA-PSS key verified a tampered message");
    }

    /**
     * {@code RSAPrivateKey.getEncoded()} must be a real PKCS#8 PrivateKeyInfo —
     * matching the {@code getFormat() == "PKCS#8"} contract — not the
     * traditional PKCS#1 RSAPrivateKey (JCA/TLS gap #8). A strict PKCS#8 parser
     * (BC's {@code PrivateKeyInfo.getInstance}) must accept it, and the
     * privateKeyAlgorithm must be rsaEncryption.
     */
    @Test
    public void testPrivateKeyEncoding_isPkcs8NotPkcs1() throws Exception
    {
        PrivateKey priv = sharedKeyPair.getPrivate();
        Assertions.assertEquals("PKCS#8", priv.getFormat(), "getFormat() should advertise PKCS#8");

        byte[] encoded = priv.getEncoded();

        // Strict PKCS#8 parse — would throw on a traditional PKCS#1 RSAPrivateKey
        // (its second SEQUENCE element is the modulus INTEGER, not an AlgorithmIdentifier).
        org.bouncycastle.asn1.pkcs.PrivateKeyInfo pki =
                org.bouncycastle.asn1.pkcs.PrivateKeyInfo.getInstance(encoded);
        Assertions.assertEquals(
                org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.rsaEncryption,
                pki.getPrivateKeyAlgorithm().getAlgorithm(),
                "PKCS#8 privateKeyAlgorithm should be rsaEncryption");

        // Re-decode through JSL and confirm the key still functions.
        KeyFactory kf = KeyFactory.getInstance("RSA", JostleProvider.PROVIDER_NAME);
        PrivateKey roundTripped = kf.generatePrivate(new PKCS8EncodedKeySpec(encoded));
        Assertions.assertEquals(
                ((java.security.interfaces.RSAPrivateKey) priv).getModulus(),
                ((java.security.interfaces.RSAPrivateKey) roundTripped).getModulus());
    }

    private static byte[] randomMessage(SecureRandom sr, int len)
    {
        byte[] m = new byte[len];
        sr.nextBytes(m);
        return m;
    }

    /**
     * Per-test seeded random with seed-on-failure logging — see CLAUDE.md
     * "use fully random values for everything ... seed SecureRandom from
     * a value the test logs on failure so a flaky run is reproducible".
     */
    private static SecureRandom seededRandom(String testName) throws Exception
    {
        long seed = RANDOM.nextLong();
        System.out.println(testName + " seed=" + seed);
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        return sr;
    }

    private static int digestOutputBytes(String name)
    {
        switch (name)
        {
            case "SHA-1":      return 20;
            case "SHA-224":    return 28;
            case "SHA-256":    return 32;
            case "SHA-384":    return 48;
            case "SHA-512":    return 64;
            case "SHA3-224":   return 28;
            case "SHA3-256":   return 32;
            case "SHA3-384":   return 48;
            case "SHA3-512":   return 64;
            default:
                throw new IllegalArgumentException("unknown digest: " + name);
        }
    }
}
