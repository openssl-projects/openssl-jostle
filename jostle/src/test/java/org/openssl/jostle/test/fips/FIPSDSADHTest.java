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
import org.junit.jupiter.api.BeforeAll;
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
 * encodings round-trip. Gated on TEST_FIPS_LIB; skipped when unset.
 */
public class FIPSDSADHTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * Class-level gate: the whole class skips when TEST_FIPS_LIB is unset.
     * Gating here rather than per test method fails closed, so a test added
     * later is gated automatically.
     */
    @BeforeAll
    static void before()
    {
        ensureProviders();
    }

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

    /**
     * DSA agreement with BouncyCastle, in whichever directions the loaded
     * module supports.
     * <p>
     * BC-signs / JSLFIPS-verifies runs always: verification is the one DSA
     * operation both supported modules perform, and it is what proves the FIPS
     * verifier accepts a real signature from an independent implementation.
     * The reverse direction runs only where the module signs — OpenSSL's 3.5.x
     * FIPS module is verify-only for DSA (see
     * {@link FIPSTestUtil#fipsDsaCanSign()}). The keypair comes from
     * {@link FIPSTestUtil#dsaKeyPair} for the same reason: 3.5.x refuses every
     * DSA generation path.
     */
    @Test
    public void dsaSignaturesAgreeWithBouncyCastle()
        throws Exception
    {
        KeyPair kp = FIPSTestUtil.dsaKeyPair(JostleFIPSProvider.PROVIDER_NAME);

        byte[] message = new byte[1 + RANDOM.nextInt(512)];
        RANDOM.nextBytes(message);
        byte[] tampered = message.clone();
        tampered[RANDOM.nextInt(tampered.length)] ^= 0x01;

        // BC sign -> JSLFIPS verify, plus the tamper differentiator.
        Signature bcSigner = Signature.getInstance("SHA256withDSA", BouncyCastleProvider.PROVIDER_NAME);
        bcSigner.initSign(kp.getPrivate());
        bcSigner.update(message);
        byte[] bcSig = bcSigner.sign();

        Signature fipsVerifier = Signature.getInstance("SHA256withDSA", JostleFIPSProvider.PROVIDER_NAME);
        fipsVerifier.initVerify(kp.getPublic());
        fipsVerifier.update(message);
        Assertions.assertTrue(fipsVerifier.verify(bcSig), "BC sign -> JSLFIPS verify");

        fipsVerifier.initVerify(kp.getPublic());
        fipsVerifier.update(tampered);
        Assertions.assertFalse(fipsVerifier.verify(bcSig), "tampered message verified");

        // Encoding round-trip: BC decodes the JSLFIPS public key and verifies
        // a signature it did not make against that decoded key.
        KeyFactory bcKf = KeyFactory.getInstance("DSA", BouncyCastleProvider.PROVIDER_NAME);
        PublicKey bcPub = bcKf.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
        Signature bcVerifier = Signature.getInstance("SHA256withDSA", BouncyCastleProvider.PROVIDER_NAME);
        bcVerifier.initVerify(bcPub);
        bcVerifier.update(message);
        Assertions.assertTrue(bcVerifier.verify(bcSig), "BC-decoded DSA public key verifies");

        if (!FIPSTestUtil.fipsDsaCanSign())
        {
            return;
        }

        // JSLFIPS sign -> BC verify.
        Signature signer = Signature.getInstance("SHA256withDSA", JostleFIPSProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());
        signer.update(message);
        byte[] sig = signer.sign();

        bcVerifier.initVerify(bcPub);
        bcVerifier.update(message);
        Assertions.assertTrue(bcVerifier.verify(sig), "JSLFIPS sign -> BC verify");

        bcVerifier.initVerify(bcPub);
        bcVerifier.update(tampered);
        Assertions.assertFalse(bcVerifier.verify(sig), "tampered message verified (BC)");
    }

    @Test
    public void dhSharedSecretsMatchBouncyCastle()
        throws Exception
    {
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
