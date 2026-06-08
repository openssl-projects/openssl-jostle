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

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Tests for the raw ECDSA {@code NoneWithECDSA} Signature (JCA/TLS gap #6).
 * The engine performs no hashing — the caller supplies an already-computed
 * digest and the engine produces/consumes a DER-encoded ECDSA signature.
 * Required by TLS 1.3's externally-hashed ECDSA CertificateVerify.
 *
 * <p>ECDSA is randomised (OpenSSL does not use deterministic RFC&nbsp;6979
 * nonces), so — unlike the RSA NoneWithRSA test — these assert
 * verifiability and cross-provider agreement rather than byte-equality.
 */
public class ECDSANoneWithECDSASignatureTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    private static KeyPair joKeyPair;
    private static PrivateKey bcPriv;
    private static PublicKey bcPub;

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
        Assumptions.assumeTrue(NISelector.ECServiceNI.curveSupported("P-256"),
                "P-256 must be supported by the loaded OpenSSL build");

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", JostleProvider.PROVIDER_NAME);
        kpg.initialize(new ECGenParameterSpec("P-256"));
        joKeyPair = kpg.generateKeyPair();

        KeyFactory bcKf = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        bcPriv = bcKf.generatePrivate(new PKCS8EncodedKeySpec(joKeyPair.getPrivate().getEncoded()));
        bcPub = bcKf.generatePublic(new X509EncodedKeySpec(joKeyPair.getPublic().getEncoded()));
    }

    /**
     * A NoneWithECDSA signature over {@code H = SHA-256(m)} must verify under
     * the full {@code SHA256withECDSA} verifier on {@code m} (which computes
     * {@code H} itself and then raw-verifies), and vice versa. This is the
     * strongest functional check that the engine signs the supplied digest
     * directly with no extra hashing — and it doesn't depend on determinism.
     */
    @Test
    public void testNoneWithECDSA_interoperatesWithSHA256withECDSA() throws Exception
    {
        SecureRandom sr = seededRandom("testNoneWithECDSA_interoperatesWithSHA256withECDSA");
        byte[] msg = new byte[1 + sr.nextInt(512)];
        sr.nextBytes(msg);
        byte[] hash = MessageDigest.getInstance("SHA-256", JostleProvider.PROVIDER_NAME).digest(msg);

        // NoneWithECDSA(H) verifies under SHA256withECDSA(m).
        Signature none = Signature.getInstance("NoneWithECDSA", JostleProvider.PROVIDER_NAME);
        none.initSign(joKeyPair.getPrivate());
        none.update(hash);
        byte[] rawSig = none.sign();

        Signature full = Signature.getInstance("SHA256withECDSA", JostleProvider.PROVIDER_NAME);
        full.initVerify(joKeyPair.getPublic());
        full.update(msg);
        Assertions.assertTrue(full.verify(rawSig),
                "SHA256withECDSA did not verify a NoneWithECDSA signature over SHA-256(m)");

        // SHA256withECDSA(m) verifies under NoneWithECDSA(H).
        Signature fullSigner = Signature.getInstance("SHA256withECDSA", JostleProvider.PROVIDER_NAME);
        fullSigner.initSign(joKeyPair.getPrivate());
        fullSigner.update(msg);
        byte[] fullSig = fullSigner.sign();

        Signature noneVerify = Signature.getInstance("NoneWithECDSA", JostleProvider.PROVIDER_NAME);
        noneVerify.initVerify(joKeyPair.getPublic());
        noneVerify.update(hash);
        Assertions.assertTrue(noneVerify.verify(fullSig),
                "NoneWithECDSA did not verify a SHA256withECDSA signature over the matching digest");

        // Negative: a tampered digest must not verify.
        hash[0] ^= 0x01;
        Signature noneBad = Signature.getInstance("NoneWithECDSA", JostleProvider.PROVIDER_NAME);
        noneBad.initVerify(joKeyPair.getPublic());
        noneBad.update(hash);
        Assertions.assertFalse(noneBad.verify(fullSig), "NoneWithECDSA verified a tampered digest");
    }

    /**
     * Cross-provider agreement on a raw digest: each provider verifies the
     * other's NoneWithECDSA signature. No byte-equality (ECDSA is randomised).
     */
    @Test
    public void testNoneWithECDSA_agreesWithBouncyCastle() throws Exception
    {
        SecureRandom sr = seededRandom("testNoneWithECDSA_agreesWithBouncyCastle");
        for (int trial = 0; trial < 10; trial++)
        {
            byte[] digest = new byte[32]; // P-256 order is 256-bit
            sr.nextBytes(digest);

            Signature joSign = Signature.getInstance("NoneWithECDSA", JostleProvider.PROVIDER_NAME);
            joSign.initSign(joKeyPair.getPrivate());
            joSign.update(digest);
            byte[] joSig = joSign.sign();

            Signature bcVerify = Signature.getInstance("NoneWithECDSA", BouncyCastleProvider.PROVIDER_NAME);
            bcVerify.initVerify(bcPub);
            bcVerify.update(digest);
            Assertions.assertTrue(bcVerify.verify(joSig),
                    "BC rejected a JSL NoneWithECDSA signature (trial " + trial + ")");

            Signature bcSign = Signature.getInstance("NoneWithECDSA", BouncyCastleProvider.PROVIDER_NAME);
            bcSign.initSign(bcPriv);
            bcSign.update(digest);
            byte[] bcSig = bcSign.sign();

            Signature joVerify = Signature.getInstance("NoneWithECDSA", JostleProvider.PROVIDER_NAME);
            joVerify.initVerify(joKeyPair.getPublic());
            joVerify.update(digest);
            Assertions.assertTrue(joVerify.verify(bcSig),
                    "JSL rejected a BC NoneWithECDSA signature (trial " + trial + ")");

            // Negative: tampering the digest must break JSL verification.
            byte[] tampered = org.openssl.jostle.util.Arrays.clone(digest);
            tampered[sr.nextInt(tampered.length)] ^= 0x01;
            Signature joVerifyBad = Signature.getInstance("NoneWithECDSA", JostleProvider.PROVIDER_NAME);
            joVerifyBad.initVerify(joKeyPair.getPublic());
            joVerifyBad.update(tampered);
            Assertions.assertFalse(joVerifyBad.verify(joSig), "JSL verified a tampered digest");
        }
    }

    /**
     * The raw path is curve-agnostic (it just signs the supplied digest), but
     * exercise P-384 and P-521 too — different field/order sizes and digest
     * lengths — to confirm no fixed-length assumption crept in. Cross-verifies
     * with BouncyCastle in both directions per curve.
     */
    @Test
    public void testNoneWithECDSA_multiCurve_agreesWithBC() throws Exception
    {
        SecureRandom sr = seededRandom("testNoneWithECDSA_multiCurve_agreesWithBC");
        // (curve, digest length matching the curve's order size)
        String[][] curves = {{"P-256", "32"}, {"P-384", "48"}, {"P-521", "66"}};

        int tested = 0;
        for (String[] row : curves)
        {
            String curve = row[0];
            int digestLen = Integer.parseInt(row[1]);
            if (!NISelector.ECServiceNI.curveSupported(curve))
            {
                continue;
            }

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", JostleProvider.PROVIDER_NAME);
            kpg.initialize(new ECGenParameterSpec(curve));
            KeyPair kp = kpg.generateKeyPair();

            KeyFactory bcKf = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
            PublicKey curveBcPub = bcKf.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
            PrivateKey curveBcPriv = bcKf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

            byte[] digest = new byte[digestLen];
            sr.nextBytes(digest);

            Signature joSign = Signature.getInstance("NoneWithECDSA", JostleProvider.PROVIDER_NAME);
            joSign.initSign(kp.getPrivate());
            joSign.update(digest);
            byte[] joSig = joSign.sign();

            Signature bcVerify = Signature.getInstance("NoneWithECDSA", BouncyCastleProvider.PROVIDER_NAME);
            bcVerify.initVerify(curveBcPub);
            bcVerify.update(digest);
            Assertions.assertTrue(bcVerify.verify(joSig), curve + ": BC rejected a JSL NoneWithECDSA signature");

            Signature bcSign = Signature.getInstance("NoneWithECDSA", BouncyCastleProvider.PROVIDER_NAME);
            bcSign.initSign(curveBcPriv);
            bcSign.update(digest);
            byte[] bcSig = bcSign.sign();

            Signature joVerify = Signature.getInstance("NoneWithECDSA", JostleProvider.PROVIDER_NAME);
            joVerify.initVerify(kp.getPublic());
            joVerify.update(digest);
            Assertions.assertTrue(joVerify.verify(bcSig), curve + ": JSL rejected a BC NoneWithECDSA signature");

            tested++;
        }
        Assertions.assertTrue(tested > 0, "no EC curves were testable against this OpenSSL build");
    }

    /**
     * Buffering must be chunking-invariant: a one-shot update and a
     * byte-by-byte update of the same digest each produce a signature that
     * verifies. (The two signatures differ — ECDSA is randomised — so we
     * assert verifiability, not equality.)
     */
    @Test
    public void testNoneWithECDSA_chunkingInvariant() throws Exception
    {
        SecureRandom sr = seededRandom("testNoneWithECDSA_chunkingInvariant");
        byte[] digest = new byte[32];
        sr.nextBytes(digest);

        Signature oneShot = Signature.getInstance("NoneWithECDSA", JostleProvider.PROVIDER_NAME);
        oneShot.initSign(joKeyPair.getPrivate());
        oneShot.update(digest);
        byte[] sigOneShot = oneShot.sign();

        Signature byteWise = Signature.getInstance("NoneWithECDSA", JostleProvider.PROVIDER_NAME);
        byteWise.initSign(joKeyPair.getPrivate());
        for (byte b : digest)
        {
            byteWise.update(b);
        }
        byte[] sigByteWise = byteWise.sign();

        for (byte[] sig : new byte[][]{sigOneShot, sigByteWise})
        {
            Signature v = Signature.getInstance("NoneWithECDSA", JostleProvider.PROVIDER_NAME);
            v.initVerify(joKeyPair.getPublic());
            v.update(digest);
            Assertions.assertTrue(v.verify(sig), "a chunking variant produced an unverifiable signature");
        }
    }

    /**
     * Reuse after a terminal op: the same instance signs two distinct digests,
     * each verifying (proves the native buffer is cleared on re-init).
     */
    @Test
    public void testNoneWithECDSA_reuseAfterSign() throws Exception
    {
        SecureRandom sr = seededRandom("testNoneWithECDSA_reuseAfterSign");
        byte[] d1 = new byte[32];
        byte[] d2 = new byte[32];
        sr.nextBytes(d1);
        sr.nextBytes(d2);

        Signature signer = Signature.getInstance("NoneWithECDSA", JostleProvider.PROVIDER_NAME);
        signer.initSign(joKeyPair.getPrivate());
        signer.update(d1);
        byte[] sig1 = signer.sign();
        signer.update(d2);
        byte[] sig2 = signer.sign();

        Signature v = Signature.getInstance("NoneWithECDSA", JostleProvider.PROVIDER_NAME);
        v.initVerify(joKeyPair.getPublic());
        v.update(d1);
        Assertions.assertTrue(v.verify(sig1), "first reuse signature did not verify");

        v.initVerify(joKeyPair.getPublic());
        v.update(d2);
        Assertions.assertTrue(v.verify(sig2), "second reuse signature did not verify");

        // Cross-check: sig1 must NOT verify against d2 (guards a stale buffer
        // that signed the wrong digest).
        v.initVerify(joKeyPair.getPublic());
        v.update(d2);
        Assertions.assertFalse(v.verify(sig1), "sig over d1 wrongly verified against d2");
    }
}
