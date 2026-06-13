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

package org.openssl.jostle.test.eddsa;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;

/**
 * Regression for RAW_EDWARDS_OID_GAP.md: the EdDSA {@code KeyFactory} and
 * {@code Signature} services must resolve by the curve <em>OID</em>
 * (Ed25519 = 1.3.101.112, Ed448 = 1.3.101.113), not only by name. BouncyCastle's
 * TLS RFC 7250 raw-public-key path materialises a peer key via
 * {@code KeyFactory.getInstance(<spki-oid>)}, so the by-name-only registration
 * left raw-key verification failing with NoSuchAlgorithmException.
 */
public class EdwardsOidResolutionTest
{
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String JSL = JostleProvider.PROVIDER_NAME;

    private static final String ED25519_OID = "1.3.101.112";
    private static final String ED448_OID = "1.3.101.113";

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    private static SecureRandom seededRandom(String testName) throws Exception
    {
        long seed = RANDOM.nextLong();
        System.out.println(testName + " seed=" + seed);
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        return sr;
    }

    @Test
    public void keyFactoryResolvesByOid() throws Exception
    {
        // The bare fix: the OID must resolve at all (RFC 7250 path).
        Assertions.assertNotNull(KeyFactory.getInstance(ED25519_OID, JSL));
        Assertions.assertNotNull(KeyFactory.getInstance(ED448_OID, JSL));
    }

    @Test
    public void signatureResolvesByOid() throws Exception
    {
        Assertions.assertNotNull(Signature.getInstance(ED25519_OID, JSL));
        Assertions.assertNotNull(Signature.getInstance(ED448_OID, JSL));
    }

    @Test
    public void ed25519_signByName_verifyViaOidResolvedKey() throws Exception
    {
        roundTripViaOid("Ed25519", ED25519_OID, seededRandom("ed25519_signByName_verifyViaOidResolvedKey"));
    }

    @Test
    public void ed448_signByName_verifyViaOidResolvedKey() throws Exception
    {
        roundTripViaOid("Ed448", ED448_OID, seededRandom("ed448_signByName_verifyViaOidResolvedKey"));
    }

    /**
     * The full RFC 7250 shape: sign with a by-name key, then rebuild the public
     * key through the OID-keyed KeyFactory (as the TLS verifier does from the
     * SPKI), and verify with a by-OID Signature. Includes a tampered-message
     * negative so the test proves verification actually depends on the data.
     */
    private void roundTripViaOid(String name, String oid, SecureRandom random) throws Exception
    {
        // The named generator (Ed25519/Ed448) carries its key type already; no
        // initialize() needed (and null params would be rejected).
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(name, JSL);
        KeyPair kp = kpg.generateKeyPair();

        byte[] msg = new byte[1 + random.nextInt(512)];
        random.nextBytes(msg);

        Signature signer = Signature.getInstance(name, JSL);
        signer.initSign(kp.getPrivate(), random);
        signer.update(msg);
        byte[] sig = signer.sign();

        // Rebuild the peer public key from its SPKI through the OID-keyed
        // KeyFactory — exactly what JcaTlsRawKeyCertificate.getPublicKey does.
        KeyFactory kfByOid = KeyFactory.getInstance(oid, JSL);
        PublicKey rebuilt = kfByOid.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));

        Signature verifier = Signature.getInstance(oid, JSL);
        verifier.initVerify(rebuilt);
        verifier.update(msg);
        Assertions.assertTrue(verifier.verify(sig),
                name + ": signature must verify through the OID-resolved key/Signature");

        // Negative path: a tampered message must not verify.
        byte[] tampered = org.openssl.jostle.util.Arrays.clone(msg);
        tampered[random.nextInt(tampered.length)] ^= (byte) 0x01;
        Signature verifier2 = Signature.getInstance(oid, JSL);
        verifier2.initVerify(rebuilt);
        verifier2.update(tampered);
        Assertions.assertFalse(verifier2.verify(sig),
                name + ": tampered message must not verify");
    }
}
