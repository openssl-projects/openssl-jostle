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

package org.openssl.jostle.test.provider;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

/**
 * Tests that JSL's RSA and ECDSA Signature SPIs accept <em>foreign</em> key
 * objects directly — i.e. a key instance from another provider passed straight
 * to {@code initVerify} / {@code initSign} without the caller first re-importing
 * it through a JSL {@code KeyFactory}.
 *
 * <p>This exercises the new {@code importPublic} / {@code importPrivate}
 * coercion in {@code RSASignatureSpiBase} and {@code ECDSASignatureSpi}, which
 * re-import foreign keys via {@code engineTranslateKey}. The motivating case is
 * the CMS/PKIX verifier handing over a {@code sun.*} key parsed from a
 * certificate (mirrored here with BouncyCastle keys, which are likewise not JSL
 * key types).
 *
 * <p>Unlike the existing {@code *BCAgreement*} tests in {@code RSATest} /
 * {@code ECDSATest} — which manually round-trip the foreign key through a JSL
 * {@code KeyFactory} before {@code init} — these pass the raw foreign key
 * object, so they cover the coercion path itself. Both directions are tested,
 * and a wrong-algorithm foreign key must still be rejected with
 * {@link InvalidKeyException}.
 */
public class ForeignKeyImportTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    private static byte[] randomMessage(int len)
    {
        byte[] m = new byte[len];
        RANDOM.nextBytes(m);
        return m;
    }

    // -----------------------------------------------------------------
    // RSA (PKCS#1 v1.5)
    // -----------------------------------------------------------------

    @Test
    public void testRsa_foreignPublicKeyObject_acceptedByJslVerify() throws Exception
    {
        KeyPairGenerator bcKpg = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        bcKpg.initialize(2048);
        KeyPair bcKp = bcKpg.generateKeyPair();
        byte[] msg = randomMessage(200);

        // BC signs.
        Signature bcSigner = Signature.getInstance("SHA256withRSA", BouncyCastleProvider.PROVIDER_NAME);
        bcSigner.initSign(bcKp.getPrivate());
        bcSigner.update(msg);
        byte[] sig = bcSigner.sign();

        // JSL verifies using the raw BC public key object (no manual re-import).
        Signature joVerifier = Signature.getInstance("SHA256withRSA", JostleProvider.PROVIDER_NAME);
        joVerifier.initVerify(bcKp.getPublic());
        joVerifier.update(msg);
        Assertions.assertTrue(joVerifier.verify(sig),
                "JSL verify failed against a raw foreign (BC) RSA public key");
    }

    @Test
    public void testRsa_foreignPrivateKeyObject_acceptedByJslSign() throws Exception
    {
        KeyPairGenerator bcKpg = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        bcKpg.initialize(2048);
        KeyPair bcKp = bcKpg.generateKeyPair();
        byte[] msg = randomMessage(200);

        // JSL signs using the raw BC private key object (no manual re-import).
        Signature joSigner = Signature.getInstance("SHA256withRSA", JostleProvider.PROVIDER_NAME);
        joSigner.initSign(bcKp.getPrivate());
        joSigner.update(msg);
        byte[] sig = joSigner.sign();

        // BC verifies with its own public key.
        Signature bcVerifier = Signature.getInstance("SHA256withRSA", BouncyCastleProvider.PROVIDER_NAME);
        bcVerifier.initVerify(bcKp.getPublic());
        bcVerifier.update(msg);
        Assertions.assertTrue(bcVerifier.verify(sig),
                "BC verify failed against a JSL signature made with a raw foreign (BC) RSA private key");
    }

    @Test
    public void testRsaPss_foreignKeyObjects_roundTrip() throws Exception
    {
        // The coercion lives in the shared RSASignatureSpiBase, so PSS gets it
        // too. Default PSS params (SHA-256/MGF1-SHA-256) on both ends.
        KeyPairGenerator bcKpg = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        bcKpg.initialize(2048);
        KeyPair bcKp = bcKpg.generateKeyPair();
        byte[] msg = randomMessage(200);

        Signature joSigner = Signature.getInstance("SHA256WITHRSAANDMGF1", JostleProvider.PROVIDER_NAME);
        joSigner.initSign(bcKp.getPrivate());
        joSigner.update(msg);
        byte[] sig = joSigner.sign();

        Signature joVerifier = Signature.getInstance("SHA256WITHRSAANDMGF1", JostleProvider.PROVIDER_NAME);
        joVerifier.initVerify(bcKp.getPublic());
        joVerifier.update(msg);
        Assertions.assertTrue(joVerifier.verify(sig),
                "JSL PSS round-trip failed using raw foreign (BC) RSA key objects");
    }

    // -----------------------------------------------------------------
    // ECDSA
    // -----------------------------------------------------------------

    @Test
    public void testEcdsa_foreignPublicKeyObject_acceptedByJslVerify() throws Exception
    {
        KeyPairGenerator bcKpg = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        bcKpg.initialize(new ECGenParameterSpec("P-256"));
        KeyPair bcKp = bcKpg.generateKeyPair();
        byte[] msg = randomMessage(200);

        Signature bcSigner = Signature.getInstance("SHA256withECDSA", BouncyCastleProvider.PROVIDER_NAME);
        bcSigner.initSign(bcKp.getPrivate());
        bcSigner.update(msg);
        byte[] sig = bcSigner.sign();

        Signature joVerifier = Signature.getInstance("SHA256withECDSA", JostleProvider.PROVIDER_NAME);
        joVerifier.initVerify(bcKp.getPublic());
        joVerifier.update(msg);
        Assertions.assertTrue(joVerifier.verify(sig),
                "JSL verify failed against a raw foreign (BC) EC public key");
    }

    @Test
    public void testEcdsa_foreignPrivateKeyObject_acceptedByJslSign() throws Exception
    {
        KeyPairGenerator bcKpg = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        bcKpg.initialize(new ECGenParameterSpec("P-256"));
        KeyPair bcKp = bcKpg.generateKeyPair();
        byte[] msg = randomMessage(200);

        Signature joSigner = Signature.getInstance("SHA256withECDSA", JostleProvider.PROVIDER_NAME);
        joSigner.initSign(bcKp.getPrivate());
        joSigner.update(msg);
        byte[] sig = joSigner.sign();

        Signature bcVerifier = Signature.getInstance("SHA256withECDSA", BouncyCastleProvider.PROVIDER_NAME);
        bcVerifier.initVerify(bcKp.getPublic());
        bcVerifier.update(msg);
        Assertions.assertTrue(bcVerifier.verify(sig),
                "BC verify failed against a JSL signature made with a raw foreign (BC) EC private key");
    }

    // -----------------------------------------------------------------
    // Negative path: wrong-algorithm foreign key still rejected
    // -----------------------------------------------------------------

    @Test
    public void testRsaSignature_rejectsForeignEcKey() throws Exception
    {
        // A foreign EC key handed to a JSL RSA Signature must still surface
        // InvalidKeyException (so JCE provider fallback works) — the coercion
        // must not turn a wrong-algorithm key into a silent success.
        KeyPairGenerator bcKpg = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        bcKpg.initialize(new ECGenParameterSpec("P-256"));
        KeyPair bcKp = bcKpg.generateKeyPair();

        Signature joVerifier = Signature.getInstance("SHA256withRSA", JostleProvider.PROVIDER_NAME);
        try
        {
            joVerifier.initVerify(bcKp.getPublic());
            Assertions.fail("expected InvalidKeyException for a foreign EC key on an RSA Signature");
        }
        catch (InvalidKeyException expected)
        {
            Assertions.assertEquals("expected an RSAPublicKey from the Jostle provider",
                    expected.getMessage());
        }
    }

    @Test
    public void testEcdsaSignature_rejectsForeignRsaKey() throws Exception
    {
        KeyPairGenerator bcKpg = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        bcKpg.initialize(2048);
        KeyPair bcKp = bcKpg.generateKeyPair();

        Signature joVerifier = Signature.getInstance("SHA256withECDSA", JostleProvider.PROVIDER_NAME);
        try
        {
            joVerifier.initVerify(bcKp.getPublic());
            Assertions.fail("expected InvalidKeyException for a foreign RSA key on an ECDSA Signature");
        }
        catch (InvalidKeyException expected)
        {
            Assertions.assertEquals("expected an ECPublicKey from the Jostle provider",
                    expected.getMessage());
        }
    }
}
