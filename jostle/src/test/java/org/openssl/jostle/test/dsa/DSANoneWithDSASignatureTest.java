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

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;

/**
 * Tests for the raw {@code NoneWithDSA} Signature — the caller supplies
 * an already-computed digest, the engine signs it without hashing.
 * This is the externally-hashed signing pattern BouncyCastle's TLS
 * stack uses ({@code JcaTlsDSASigner.generateRawSignature}).
 *
 * <p>The semantic anchor: {@code NoneWithDSA(SHA256(msg))} must verify
 * via {@code SHA256withDSA(msg)} and vice versa — both pipelines hash
 * the message exactly once.
 */
public class DSANoneWithDSASignatureTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

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

    private static KeyPair generateKeyPair() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA", JostleProvider.PROVIDER_NAME);
        kpg.initialize(1024);
        return kpg.generateKeyPair();
    }


    @Test
    public void testNoneWithDsa_signRaw_verifyWithDigestAlgorithm() throws Exception
    {
        SecureRandom sr = seededRandom("testNoneWithDsa_signRaw_verifyWithDigestAlgorithm");
        KeyPair kp = generateKeyPair();
        byte[] msg = new byte[200 + sr.nextInt(300)];
        sr.nextBytes(msg);
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(msg);

        // Sign the pre-computed digest raw...
        Signature rawSigner = Signature.getInstance("NoneWithDSA", JostleProvider.PROVIDER_NAME);
        rawSigner.initSign(kp.getPrivate());
        rawSigner.update(digest);
        byte[] sig = rawSigner.sign();

        // ...and verify through the hashing pipeline over the message.
        Signature verifier = Signature.getInstance("SHA256withDSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(kp.getPublic());
        verifier.update(msg);
        Assertions.assertTrue(verifier.verify(sig),
                "NoneWithDSA(SHA256(msg)) must verify via SHA256withDSA(msg)");
    }

    @Test
    public void testNoneWithDsa_signWithDigestAlgorithm_verifyRaw() throws Exception
    {
        SecureRandom sr = seededRandom("testNoneWithDsa_signWithDigestAlgorithm_verifyRaw");
        KeyPair kp = generateKeyPair();
        byte[] msg = new byte[200 + sr.nextInt(300)];
        sr.nextBytes(msg);
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(msg);

        Signature signer = Signature.getInstance("SHA256withDSA", JostleProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());
        signer.update(msg);
        byte[] sig = signer.sign();

        Signature rawVerifier = Signature.getInstance("NoneWithDSA", JostleProvider.PROVIDER_NAME);
        rawVerifier.initVerify(kp.getPublic());
        rawVerifier.update(digest);
        Assertions.assertTrue(rawVerifier.verify(sig),
                "SHA256withDSA(msg) must verify via NoneWithDSA(SHA256(msg))");
    }

    @Test
    public void testNoneWithDsa_BCAgreement_bothDirections() throws Exception
    {
        SecureRandom sr = seededRandom("testNoneWithDsa_BCAgreement_bothDirections");
        KeyPair joKp = generateKeyPair();
        byte[] digest = new byte[20];   // SHA-1-sized: fits q = 160 bits exactly
        sr.nextBytes(digest);

        KeyFactory bcKf = KeyFactory.getInstance("DSA", BouncyCastleProvider.PROVIDER_NAME);
        PublicKey bcPub = bcKf.generatePublic(
                new X509EncodedKeySpec(joKp.getPublic().getEncoded()));

        // Jostle signs raw → BC verifies raw.
        Signature joSigner = Signature.getInstance("NoneWithDSA", JostleProvider.PROVIDER_NAME);
        joSigner.initSign(joKp.getPrivate());
        joSigner.update(digest);
        byte[] sig = joSigner.sign();

        Signature bcVerifier = Signature.getInstance("NONEwithDSA", BouncyCastleProvider.PROVIDER_NAME);
        bcVerifier.initVerify(bcPub);
        bcVerifier.update(digest);
        Assertions.assertTrue(bcVerifier.verify(sig),
                "Jostle raw DSA signature failed BC NONEwithDSA verify");

        // BC signs raw → Jostle verifies raw. Use the Jostle private
        // key imported into BC via PKCS#8.
        java.security.PrivateKey bcPriv = bcKf.generatePrivate(
                new java.security.spec.PKCS8EncodedKeySpec(joKp.getPrivate().getEncoded()));
        Signature bcSigner = Signature.getInstance("NONEwithDSA", BouncyCastleProvider.PROVIDER_NAME);
        bcSigner.initSign(bcPriv);
        bcSigner.update(digest);
        byte[] bcSig = bcSigner.sign();

        Signature joVerifier = Signature.getInstance("NoneWithDSA", JostleProvider.PROVIDER_NAME);
        joVerifier.initVerify(joKp.getPublic());
        joVerifier.update(digest);
        Assertions.assertTrue(joVerifier.verify(bcSig),
                "BC raw DSA signature failed Jostle NoneWithDSA verify");
    }

    @Test
    public void testNoneWithDsa_TamperedDigest_doesNotVerify() throws Exception
    {
        SecureRandom sr = seededRandom("testNoneWithDsa_TamperedDigest_doesNotVerify");
        KeyPair kp = generateKeyPair();
        byte[] digest = new byte[20];
        sr.nextBytes(digest);

        Signature signer = Signature.getInstance("NoneWithDSA", JostleProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());
        signer.update(digest);
        byte[] sig = signer.sign();

        byte[] tampered = Arrays.clone(digest);
        tampered[tampered.length / 2] ^= 0x01;

        Signature verifier = Signature.getInstance("NoneWithDSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(kp.getPublic());
        verifier.update(tampered);
        Assertions.assertFalse(verifier.verify(sig),
                "tampered digest must not verify");
    }

    @Test
    public void testNoneWithDsa_ChunkedDigestDelivery_verifies() throws Exception
    {
        SecureRandom sr = seededRandom("testNoneWithDsa_ChunkedDigestDelivery_verifies");
        // The raw path buffers caller input — delivering the digest in
        // pieces must be equivalent to one shot.
        KeyPair kp = generateKeyPair();
        byte[] digest = new byte[20];
        sr.nextBytes(digest);

        Signature signer = Signature.getInstance("NoneWithDSA", JostleProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());
        for (byte b : digest)
        {
            signer.update(b);
        }
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance("NoneWithDSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(kp.getPublic());
        verifier.update(digest, 0, 7);
        verifier.update(digest, 7, digest.length - 7);
        Assertions.assertTrue(verifier.verify(sig),
                "chunk-delivered raw digest must verify");
    }

    @Test
    public void testNoneWithDsa_ReuseAfterSign() throws Exception
    {
        SecureRandom sr = seededRandom("testNoneWithDsa_ReuseAfterSign");
        // The raw buffer must be cleared between operations on the same
        // instance — a stale buffer would make the second signature
        // cover both digests.
        KeyPair kp = generateKeyPair();
        byte[] digestA = new byte[20];
        byte[] digestB = new byte[20];
        sr.nextBytes(digestA);
        sr.nextBytes(digestB);

        Signature signer = Signature.getInstance("NoneWithDSA", JostleProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());
        signer.update(digestA);
        byte[] sigA = signer.sign();
        signer.update(digestB);
        byte[] sigB = signer.sign();

        Signature verifier = Signature.getInstance("NoneWithDSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(kp.getPublic());
        verifier.update(digestA);
        Assertions.assertTrue(verifier.verify(sigA), "first raw signature must verify");
        verifier.update(digestB);
        Assertions.assertTrue(verifier.verify(sigB),
                "second raw signature must verify over ONLY the second digest "
                        + "(stale raw buffer would break this)");
    }
}
