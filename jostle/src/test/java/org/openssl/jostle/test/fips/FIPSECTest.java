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
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;

import javax.crypto.KeyAgreement;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
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
        ensureProviders();

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
        ensureProviders();

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
        ensureProviders();

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
    public void unapprovedCurveRejected()
        throws Exception
    {
        ensureProviders();

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
}
