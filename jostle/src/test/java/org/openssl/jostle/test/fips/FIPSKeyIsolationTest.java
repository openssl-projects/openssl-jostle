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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
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
 * Cross-provider key isolation: a Jostle key is bound to the interface
 * library (and OSSL_LIB_CTX) that created it, and the operational SPIs
 * (Signature, Cipher, KeyAgreement) of one provider must reject keys created
 * by the other with a typed InvalidKeyException. Sharing a key between JSL
 * and JSLFIPS is done explicitly: encode it (getEncoded()) and decode it
 * through the target provider's KeyFactory - which this test proves works.
 * Gated on JOSTLE_TEST_FIPS_DIR; skipped when unset.
 */
public class FIPSKeyIsolationTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    private static void ensureProviders()
    {
        FIPSTestUtil.assumeFipsProvider();
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    private static void assertRejected(Executable action)
    {
        InvalidKeyException e = Assertions.assertThrows(InvalidKeyException.class, action::run);
        Assertions.assertTrue(e.getMessage().contains("different Jostle provider"),
                "expected the isolation message, got: " + e.getMessage());
    }

    private interface Executable
    {
        void run() throws Exception;
    }

    @Test
    public void rsaKeysDoNotCrossProviders()
        throws Exception
    {
        ensureProviders();

        KeyPairGenerator jslKpg = KeyPairGenerator.getInstance("RSA", JostleProvider.PROVIDER_NAME);
        jslKpg.initialize(2048);
        KeyPair jslKp = jslKpg.generateKeyPair();

        // JSL private key into a JSLFIPS Signature: rejected.
        Signature fipsSigner = Signature.getInstance("SHA256withRSA", JostleFIPSProvider.PROVIDER_NAME);
        assertRejected(() -> fipsSigner.initSign(jslKp.getPrivate()));

        // JSL public key into a JSLFIPS Cipher (wrap direction): rejected.
        Cipher fipsCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", JostleFIPSProvider.PROVIDER_NAME);
        assertRejected(() -> fipsCipher.init(Cipher.ENCRYPT_MODE, jslKp.getPublic()));

        // And symmetrically: a JSLFIPS key into a JSL Signature is rejected.
        KeyPairGenerator fipsKpg = KeyPairGenerator.getInstance("RSA", JostleFIPSProvider.PROVIDER_NAME);
        fipsKpg.initialize(2048);
        KeyPair fipsKp = fipsKpg.generateKeyPair();
        Signature jslVerifier = Signature.getInstance("SHA256withRSA", JostleProvider.PROVIDER_NAME);
        assertRejected(() -> jslVerifier.initVerify(fipsKp.getPublic()));

        // The sanctioned route: encode and decode through the target
        // provider's KeyFactory, then use.
        KeyFactory fipsKf = KeyFactory.getInstance("RSA", JostleFIPSProvider.PROVIDER_NAME);
        PrivateKey crossed = fipsKf.generatePrivate(new PKCS8EncodedKeySpec(jslKp.getPrivate().getEncoded()));
        PublicKey crossedPub = fipsKf.generatePublic(new X509EncodedKeySpec(jslKp.getPublic().getEncoded()));
        byte[] message = new byte[128];
        RANDOM.nextBytes(message);
        fipsSigner.initSign(crossed);
        fipsSigner.update(message);
        byte[] sig = fipsSigner.sign();
        Signature fipsVerifier = Signature.getInstance("SHA256withRSA", JostleFIPSProvider.PROVIDER_NAME);
        fipsVerifier.initVerify(crossedPub);
        fipsVerifier.update(message);
        Assertions.assertTrue(fipsVerifier.verify(sig), "re-encoded key must work");
    }

    @Test
    public void ecDhAndXdhKeysDoNotCrossProviders()
        throws Exception
    {
        ensureProviders();

        // EC: JSLFIPS key into a JSL KeyAgreement.
        KeyPairGenerator fipsEc = KeyPairGenerator.getInstance("EC", JostleFIPSProvider.PROVIDER_NAME);
        fipsEc.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair fipsEcKp = fipsEc.generateKeyPair();
        KeyAgreement jslEcdh = KeyAgreement.getInstance("ECDH", JostleProvider.PROVIDER_NAME);
        assertRejected(() -> jslEcdh.init(fipsEcKp.getPrivate()));

        // ECDSA verify direction too.
        Signature jslEcdsa = Signature.getInstance("SHA256withECDSA", JostleProvider.PROVIDER_NAME);
        assertRejected(() -> jslEcdsa.initVerify(fipsEcKp.getPublic()));

        // DH: JSL key into a JSLFIPS KeyAgreement.
        KeyPairGenerator jslDh = KeyPairGenerator.getInstance("DH", JostleProvider.PROVIDER_NAME);
        jslDh.initialize(2048);
        KeyPair jslDhKp = jslDh.generateKeyPair();
        KeyAgreement fipsDh = KeyAgreement.getInstance("DH", JostleFIPSProvider.PROVIDER_NAME);
        assertRejected(() -> fipsDh.init(jslDhKp.getPrivate()));

        // XDH: JSL key into a JSLFIPS KeyAgreement, and the peer (doPhase)
        // direction.
        KeyPairGenerator jslX = KeyPairGenerator.getInstance("X25519", JostleProvider.PROVIDER_NAME);
        KeyPair jslXKp = jslX.generateKeyPair();
        KeyAgreement fipsX = KeyAgreement.getInstance("X25519", JostleFIPSProvider.PROVIDER_NAME);
        assertRejected(() -> fipsX.init(jslXKp.getPrivate()));

        KeyPairGenerator fipsXKpg = KeyPairGenerator.getInstance("X25519", JostleFIPSProvider.PROVIDER_NAME);
        KeyPair fipsXKp = fipsXKpg.generateKeyPair();
        fipsX.init(fipsXKp.getPrivate());
        assertRejected(() -> fipsX.doPhase(jslXKp.getPublic(), true));
    }

    @Test
    public void symmetricKeysAreUnaffected()
        throws Exception
    {
        ensureProviders();

        // SecretKeys are raw bytes with no native residency: a key generated
        // by JSL's KeyGenerator works in a JSLFIPS cipher (and vice versa).
        javax.crypto.KeyGenerator jslKg = javax.crypto.KeyGenerator.getInstance("AES", JostleProvider.PROVIDER_NAME);
        jslKg.init(256);
        SecretKey key = jslKg.generateKey();

        byte[] nonce = new byte[12];
        RANDOM.nextBytes(nonce);
        byte[] message = new byte[64];
        RANDOM.nextBytes(message);

        Cipher enc = Cipher.getInstance("AES/GCM/NoPadding", JostleFIPSProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key.getEncoded(), "AES"), new GCMParameterSpec(128, nonce));
        byte[] ct = enc.doFinal(message);

        Cipher dec = Cipher.getInstance("AES/GCM/NoPadding", JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, nonce));
        Assertions.assertArrayEquals(message, dec.doFinal(ct));
    }
}
