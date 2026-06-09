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
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.util.Arrays;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Tests for the raw PKCS#1 v1.5 {@code NoneWithRSA} Signature (JCA/TLS gap #4).
 * The engine performs no hashing — the caller supplies the already-formed
 * bytes (typically a DigestInfo) and the engine applies PKCS#1 v1.5
 * block-type-1 padding + the RSA private-key op. Required by TLS 1.3's
 * externally-hashed CertificateVerify.
 */
public class RSANoneWithRSASignatureTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    /** Shared keypair (Jostle) reused across tests to bound wall-clock time. */
    private static KeyPair joKeyPair;
    /** BouncyCastle-native copies of the same key, for cross-provider agreement. */
    private static PrivateKey bcPriv;
    private static PublicKey bcPub;

    /**
     * The fixed ASN.1 DigestInfo prefix for SHA-256 (RFC 8017 §9.2):
     * SEQUENCE { SEQUENCE { OID sha256, NULL }, OCTET STRING (32) }. The
     * 32-byte digest is appended to form the full DigestInfo.
     */
    private static final byte[] SHA256_DIGESTINFO_PREFIX = {
            (byte) 0x30, (byte) 0x31, (byte) 0x30, (byte) 0x0d,
            (byte) 0x06, (byte) 0x09, (byte) 0x60, (byte) 0x86,
            (byte) 0x48, (byte) 0x01, (byte) 0x65, (byte) 0x03,
            (byte) 0x04, (byte) 0x02, (byte) 0x01, (byte) 0x05,
            (byte) 0x00, (byte) 0x04, (byte) 0x20
    };

    private static SecureRandom seededRandom(String testName) throws Exception
    {
        long seed = RANDOM.nextLong();
        System.out.println(testName + " seed=" + seed);
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        return sr;
    }

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
        joKeyPair = kpg.generateKeyPair();

        // Re-decode the same key into BC-native objects so the cross-provider
        // agreement tests aren't entangled with cross-provider key-class
        // acceptance (that's covered elsewhere).
        KeyFactory bcKf = KeyFactory.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        bcPriv = bcKf.generatePrivate(new PKCS8EncodedKeySpec(joKeyPair.getPrivate().getEncoded()));
        bcPub = bcKf.generatePublic(new X509EncodedKeySpec(joKeyPair.getPublic().getEncoded()));
    }

    /**
     * NoneWithRSA over a properly-formed SHA-256 DigestInfo must produce a
     * signature byte-identical to SHA256withRSA over the original message —
     * SHA256withRSA is exactly "PKCS#1 v1.5 over DigestInfo(SHA-256, H(m))",
     * and PKCS#1 v1.5 signing is deterministic. This pins that the raw engine
     * pads the caller bytes directly (no extra DigestInfo wrapping, no hashing).
     */
    @Test
    public void testNoneWithRSA_equivalentToSHA256withRSA() throws Exception
    {
        SecureRandom sr = seededRandom("testNoneWithRSA_equivalentToSHA256withRSA");
        byte[] msg = new byte[1 + sr.nextInt(512)];
        sr.nextBytes(msg);

        byte[] hash = MessageDigest.getInstance("SHA-256", JostleProvider.PROVIDER_NAME).digest(msg);
        byte[] digestInfo = new byte[SHA256_DIGESTINFO_PREFIX.length + hash.length];
        System.arraycopy(SHA256_DIGESTINFO_PREFIX, 0, digestInfo, 0, SHA256_DIGESTINFO_PREFIX.length);
        System.arraycopy(hash, 0, digestInfo, SHA256_DIGESTINFO_PREFIX.length, hash.length);

        Signature none = Signature.getInstance("NoneWithRSA", JostleProvider.PROVIDER_NAME);
        none.initSign(joKeyPair.getPrivate());
        none.update(digestInfo);
        byte[] rawSig = none.sign();

        Signature full = Signature.getInstance("SHA256withRSA", JostleProvider.PROVIDER_NAME);
        full.initSign(joKeyPair.getPrivate());
        full.update(msg);
        byte[] fullSig = full.sign();

        Assertions.assertArrayEquals(fullSig, rawSig,
                "NoneWithRSA(DigestInfo) must equal SHA256withRSA(message)");

        // And the raw signature verifies through NoneWithRSA against the DigestInfo.
        Signature v = Signature.getInstance("NoneWithRSA", JostleProvider.PROVIDER_NAME);
        v.initVerify(joKeyPair.getPublic());
        v.update(digestInfo);
        Assertions.assertTrue(v.verify(rawSig), "NoneWithRSA failed to verify its own signature");
    }

    /**
     * Cross-provider agreement on raw bytes: JSL and BouncyCastle must produce
     * byte-identical NoneWithRSA signatures (deterministic) and each must
     * verify the other's. Random content and length per trial.
     */
    @Test
    public void testNoneWithRSA_agreesWithBouncyCastle() throws Exception
    {
        SecureRandom sr = seededRandom("testNoneWithRSA_agreesWithBouncyCastle");
        for (int trial = 0; trial < 10; trial++)
        {
            // Bounded well under k - 11 (= 245 for a 2048-bit modulus).
            byte[] tbs = new byte[1 + sr.nextInt(200)];
            sr.nextBytes(tbs);

            Signature joSign = Signature.getInstance("NoneWithRSA", JostleProvider.PROVIDER_NAME);
            joSign.initSign(joKeyPair.getPrivate());
            joSign.update(tbs);
            byte[] joSig = joSign.sign();

            Signature bcSign = Signature.getInstance("NoneWithRSA", BouncyCastleProvider.PROVIDER_NAME);
            bcSign.initSign(bcPriv);
            bcSign.update(tbs);
            byte[] bcSig = bcSign.sign();

            Assertions.assertArrayEquals(bcSig, joSig,
                    "deterministic NoneWithRSA signatures disagree (trial " + trial + ")");

            // JSL signature verifies under BC...
            Signature bcVerify = Signature.getInstance("NoneWithRSA", BouncyCastleProvider.PROVIDER_NAME);
            bcVerify.initVerify(bcPub);
            bcVerify.update(tbs);
            Assertions.assertTrue(bcVerify.verify(joSig), "BC rejected a JSL NoneWithRSA signature");

            // ...and BC's signature verifies under JSL.
            Signature joVerify = Signature.getInstance("NoneWithRSA", JostleProvider.PROVIDER_NAME);
            joVerify.initVerify(joKeyPair.getPublic());
            joVerify.update(tbs);
            Assertions.assertTrue(joVerify.verify(bcSig), "JSL rejected a BC NoneWithRSA signature");

            // Negative: tampering the signed bytes must break verification.
            byte[] tampered = Arrays.clone(tbs);
            tampered[sr.nextInt(tampered.length)] ^= 0x01;
            Signature joVerifyBad = Signature.getInstance("NoneWithRSA", JostleProvider.PROVIDER_NAME);
            joVerifyBad.initVerify(joKeyPair.getPublic());
            joVerifyBad.update(tampered);
            Assertions.assertFalse(joVerifyBad.verify(joSig), "JSL verified a tampered message");
        }
    }

    /**
     * The buffered input must be chunking-invariant: a one-shot update and a
     * byte-by-byte update of the same bytes produce the same signature.
     */
    @Test
    public void testNoneWithRSA_chunkingInvariant() throws Exception
    {
        SecureRandom sr = seededRandom("testNoneWithRSA_chunkingInvariant");
        byte[] tbs = new byte[1 + sr.nextInt(200)];
        sr.nextBytes(tbs);

        Signature oneShot = Signature.getInstance("NoneWithRSA", JostleProvider.PROVIDER_NAME);
        oneShot.initSign(joKeyPair.getPrivate());
        oneShot.update(tbs);
        byte[] sigOneShot = oneShot.sign();

        Signature byteWise = Signature.getInstance("NoneWithRSA", JostleProvider.PROVIDER_NAME);
        byteWise.initSign(joKeyPair.getPrivate());
        for (byte b : tbs)
        {
            byteWise.update(b);
        }
        byte[] sigByteWise = byteWise.sign();

        Assertions.assertArrayEquals(sigOneShot, sigByteWise,
                "NoneWithRSA signature depends on input chunking");
    }

    /**
     * PKCS#1 v1.5 signing requires the TBS to fit: {@code len <= k - 11}
     * (245 bytes for a 2048-bit modulus). Probe the exact boundary — 245
     * bytes must round-trip, 246 must be rejected — and confirm the rejection
     * surfaces as the typed {@link OpenSSLException} (OpenSSL's
     * {@code EVP_PKEY_sign} failing), not a silent truncation or a bare
     * {@code RuntimeException}.
     */
    @Test
    public void testNoneWithRSA_inputLengthBoundary() throws Exception
    {
        SecureRandom sr = seededRandom("testNoneWithRSA_inputLengthBoundary");

        // k - 11 = 245 for RSA-2048: the largest TBS PKCS#1 v1.5 accepts.
        byte[] maxFit = new byte[245];
        sr.nextBytes(maxFit);
        Signature ok = Signature.getInstance("NoneWithRSA", JostleProvider.PROVIDER_NAME);
        ok.initSign(joKeyPair.getPrivate());
        ok.update(maxFit);
        byte[] sig = ok.sign();
        Signature v = Signature.getInstance("NoneWithRSA", JostleProvider.PROVIDER_NAME);
        v.initVerify(joKeyPair.getPublic());
        v.update(maxFit);
        Assertions.assertTrue(v.verify(sig), "245-byte TBS (k - 11) failed to round-trip");

        // 246 bytes is one past the limit — must be rejected, typed.
        byte[] tooLong = new byte[246];
        sr.nextBytes(tooLong);
        Signature signer = Signature.getInstance("NoneWithRSA", JostleProvider.PROVIDER_NAME);
        signer.initSign(joKeyPair.getPrivate());
        signer.update(tooLong);
        Assertions.assertThrows(OpenSSLException.class, signer::sign,
                "NoneWithRSA accepted a TBS one byte past the PKCS#1 v1.5 limit");
    }

    /**
     * Reuse after a terminal op: the same instance must sign two different
     * inputs correctly (proves the native buffer is cleared on re-init).
     */
    @Test
    public void testNoneWithRSA_reuseAfterSign() throws Exception
    {
        SecureRandom sr = seededRandom("testNoneWithRSA_reuseAfterSign");
        byte[] a = new byte[1 + sr.nextInt(100)];
        byte[] b = new byte[1 + sr.nextInt(100)];
        sr.nextBytes(a);
        sr.nextBytes(b);

        Signature signer = Signature.getInstance("NoneWithRSA", JostleProvider.PROVIDER_NAME);
        signer.initSign(joKeyPair.getPrivate());
        signer.update(a);
        byte[] sigA = signer.sign();
        // Same instance, second message — no re-init.
        signer.update(b);
        byte[] sigB = signer.sign();

        Signature ref = Signature.getInstance("NoneWithRSA", JostleProvider.PROVIDER_NAME);
        ref.initVerify(joKeyPair.getPublic());
        ref.update(a);
        Assertions.assertTrue(ref.verify(sigA), "first reuse signature did not verify");

        ref.initVerify(joKeyPair.getPublic());
        ref.update(b);
        Assertions.assertTrue(ref.verify(sigB), "second reuse signature did not verify");

        Assertions.assertFalse(Arrays.areEqual(sigA, sigB),
                "distinct messages produced identical signatures (stale buffer?)");
    }

    /**
     * A valid signature must NOT verify under an unrelated public key — proves
     * verify() actually consults the key, not merely the PKCS#1/DigestInfo
     * structure. A message-tamper test alone can pass an implementation that
     * ignores the public key entirely.
     */
    @Test
    public void testNoneWithRSA_wrongKeyRejected() throws Exception
    {
        SecureRandom sr = seededRandom("testNoneWithRSA_wrongKeyRejected");
        byte[] tbs = new byte[1 + sr.nextInt(200)];
        sr.nextBytes(tbs);

        Signature signer = Signature.getInstance("NoneWithRSA", JostleProvider.PROVIDER_NAME);
        signer.initSign(joKeyPair.getPrivate());
        signer.update(tbs);
        byte[] sig = signer.sign();

        // A second, unrelated RSA-2048 keypair.
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", JostleProvider.PROVIDER_NAME);
        kpg.initialize(2048);
        KeyPair other = kpg.generateKeyPair();

        Signature verifier = Signature.getInstance("NoneWithRSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(other.getPublic());
        verifier.update(tbs);
        Assertions.assertFalse(verifier.verify(sig),
                "NoneWithRSA verified a signature under the wrong public key");
    }
}
