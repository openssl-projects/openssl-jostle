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
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;

/**
 * DSA and DH through the FIPS provider ("JSLFIPS"): DSA signatures agree
 * with BouncyCastle both directions, DH shared secrets match BC, and key
 * encodings round-trip. Gated on JOSTLE_TEST_FIPS_DIR; skipped when unset.
 */
public class FIPSDSADHTest
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

    @Test
    public void dsaSignaturesAgreeWithBouncyCastle()
        throws Exception
    {
        ensureProviders();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA", JostleFIPSProvider.PROVIDER_NAME);
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        byte[] message = new byte[1 + RANDOM.nextInt(512)];
        RANDOM.nextBytes(message);

        Signature signer = Signature.getInstance("SHA256withDSA", JostleFIPSProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());
        signer.update(message);
        byte[] sig = signer.sign();

        Signature bcVerifier = Signature.getInstance("SHA256withDSA", BouncyCastleProvider.PROVIDER_NAME);
        bcVerifier.initVerify(kp.getPublic());
        bcVerifier.update(message);
        Assertions.assertTrue(bcVerifier.verify(sig), "JSLFIPS sign -> BC verify");

        // Tampered message must not verify.
        byte[] tampered = message.clone();
        tampered[RANDOM.nextInt(tampered.length)] ^= 0x01;
        Signature fipsVerifier = Signature.getInstance("SHA256withDSA", JostleFIPSProvider.PROVIDER_NAME);
        fipsVerifier.initVerify(kp.getPublic());
        fipsVerifier.update(tampered);
        Assertions.assertFalse(fipsVerifier.verify(sig), "tampered message verified");

        // BC sign -> JSLFIPS verify.
        Signature bcSigner = Signature.getInstance("SHA256withDSA", BouncyCastleProvider.PROVIDER_NAME);
        bcSigner.initSign(kp.getPrivate());
        bcSigner.update(message);
        byte[] bcSig = bcSigner.sign();
        fipsVerifier.initVerify(kp.getPublic());
        fipsVerifier.update(message);
        Assertions.assertTrue(fipsVerifier.verify(bcSig), "BC sign -> JSLFIPS verify");

        // Encoding round-trip: BC decodes the JSLFIPS public key and verifies.
        KeyFactory bcKf = KeyFactory.getInstance("DSA", BouncyCastleProvider.PROVIDER_NAME);
        PublicKey bcPub = bcKf.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
        bcVerifier.initVerify(bcPub);
        bcVerifier.update(message);
        Assertions.assertTrue(bcVerifier.verify(sig), "BC-decoded DSA public key verifies");
    }

    @Test
    public void dhSharedSecretsMatchBouncyCastle()
        throws Exception
    {
        ensureProviders();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH", JostleFIPSProvider.PROVIDER_NAME);
        kpg.initialize(2048);
        KeyPair alice = kpg.generateKeyPair();
        KeyPair bob = kpg.generateKeyPair();

        KeyAgreement fipsKa = KeyAgreement.getInstance("DH", JostleFIPSProvider.PROVIDER_NAME);
        fipsKa.init(alice.getPrivate());
        fipsKa.doPhase(bob.getPublic(), true);
        byte[] fipsSecret = fipsKa.generateSecret();

        KeyAgreement bcKa = KeyAgreement.getInstance("DH", BouncyCastleProvider.PROVIDER_NAME);
        bcKa.init(bob.getPrivate());
        bcKa.doPhase(alice.getPublic(), true);
        Assertions.assertArrayEquals(fipsSecret, bcKa.generateSecret(),
                "JSLFIPS(alice) and BC(bob) must derive the same secret");

        // JSLFIPS KeyFactory decodes BC-encoded keys and derives the same secret.
        KeyFactory fipsKf = KeyFactory.getInstance("DH", JostleFIPSProvider.PROVIDER_NAME);
        PublicKey decoded = fipsKf.generatePublic(new X509EncodedKeySpec(bob.getPublic().getEncoded()));
        fipsKa.init(alice.getPrivate());
        fipsKa.doPhase(decoded, true);
        Assertions.assertArrayEquals(fipsSecret, fipsKa.generateSecret(),
                "decoded peer key must derive the same secret");
    }
}
