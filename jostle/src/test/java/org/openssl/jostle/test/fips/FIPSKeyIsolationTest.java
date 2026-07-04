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
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * Cross-provider key policy: PUBLIC keys carry no secret material and may be
 * used freely with either provider's operational services; PRIVATE keys are
 * bound to the interface library (and OSSL_LIB_CTX) that created them and
 * are rejected by the other provider's SPIs with a typed
 * InvalidKeyException. Sharing a private key between JSL and JSLFIPS is done
 * explicitly: encode it (getEncoded()) and decode it through the target
 * provider's KeyFactory - which this test proves works. SecretKeys (raw
 * bytes, no native residency) are unaffected. Gated on JOSTLE_TEST_FIPS_DIR;
 * skipped when unset.
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
    public void rsaPrivateKeysIsolatedPublicKeysShared()
        throws Exception
    {
        ensureProviders();

        KeyPairGenerator jslKpg = KeyPairGenerator.getInstance("RSA", JostleProvider.PROVIDER_NAME);
        jslKpg.initialize(2048);
        KeyPair jslKp = jslKpg.generateKeyPair();
        KeyPairGenerator fipsKpg = KeyPairGenerator.getInstance("RSA", JostleFIPSProvider.PROVIDER_NAME);
        fipsKpg.initialize(2048);
        KeyPair fipsKp = fipsKpg.generateKeyPair();

        byte[] message = new byte[128];
        RANDOM.nextBytes(message);

        // PRIVATE keys are isolated, in both directions.
        Signature fipsSigner = Signature.getInstance("SHA256withRSA", JostleFIPSProvider.PROVIDER_NAME);
        assertRejected(() -> fipsSigner.initSign(jslKp.getPrivate()));
        Signature jslSigner = Signature.getInstance("SHA256withRSA", JostleProvider.PROVIDER_NAME);
        assertRejected(() -> jslSigner.initSign(fipsKp.getPrivate()));
        Cipher fipsDec = Cipher.getInstance("RSA/ECB/PKCS1Padding", JostleFIPSProvider.PROVIDER_NAME);
        assertRejected(() -> fipsDec.init(Cipher.DECRYPT_MODE, jslKp.getPrivate()));

        // PUBLIC keys cross freely: sign with JSLFIPS, verify through JSL
        // using the JSLFIPS key object directly - and vice versa.
        fipsSigner.initSign(fipsKp.getPrivate());
        fipsSigner.update(message);
        byte[] fipsSig = fipsSigner.sign();
        Signature jslVerifier = Signature.getInstance("SHA256withRSA", JostleProvider.PROVIDER_NAME);
        jslVerifier.initVerify(fipsKp.getPublic());
        jslVerifier.update(message);
        Assertions.assertTrue(jslVerifier.verify(fipsSig), "JSLFIPS public key must verify through JSL");

        jslSigner.initSign(jslKp.getPrivate());
        jslSigner.update(message);
        byte[] jslSig = jslSigner.sign();
        Signature fipsVerifier = Signature.getInstance("SHA256withRSA", JostleFIPSProvider.PROVIDER_NAME);
        fipsVerifier.initVerify(jslKp.getPublic());
        fipsVerifier.update(message);
        Assertions.assertTrue(fipsVerifier.verify(jslSig), "JSL public key must verify through JSLFIPS");

        // Public-key encrypt through the other provider round-trips.
        byte[] small = new byte[32];
        RANDOM.nextBytes(small);
        Cipher fipsEnc = Cipher.getInstance("RSA/ECB/PKCS1Padding", JostleFIPSProvider.PROVIDER_NAME);
        fipsEnc.init(Cipher.ENCRYPT_MODE, jslKp.getPublic());
        byte[] ct = fipsEnc.doFinal(small);
        Cipher jslDec = Cipher.getInstance("RSA/ECB/PKCS1Padding", JostleProvider.PROVIDER_NAME);
        jslDec.init(Cipher.DECRYPT_MODE, jslKp.getPrivate());
        Assertions.assertArrayEquals(small, jslDec.doFinal(ct),
                "JSLFIPS encrypt with JSL public key must round-trip");

        // The sanctioned route for PRIVATE keys: encode and decode through
        // the target provider's KeyFactory, then use.
        KeyFactory fipsKf = KeyFactory.getInstance("RSA", JostleFIPSProvider.PROVIDER_NAME);
        PrivateKey crossed = fipsKf.generatePrivate(new PKCS8EncodedKeySpec(jslKp.getPrivate().getEncoded()));
        fipsSigner.initSign(crossed);
        fipsSigner.update(message);
        byte[] sig = fipsSigner.sign();
        fipsVerifier.initVerify(jslKp.getPublic());
        fipsVerifier.update(message);
        Assertions.assertTrue(fipsVerifier.verify(sig), "re-encoded private key must work");
    }

    @Test
    public void ecDhAndXdhPolicy()
        throws Exception
    {
        ensureProviders();

        // EC: private isolated...
        KeyPairGenerator fipsEc = KeyPairGenerator.getInstance("EC", JostleFIPSProvider.PROVIDER_NAME);
        fipsEc.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair fipsEcKp = fipsEc.generateKeyPair();
        KeyAgreement jslEcdh = KeyAgreement.getInstance("ECDH", JostleProvider.PROVIDER_NAME);
        assertRejected(() -> jslEcdh.init(fipsEcKp.getPrivate()));

        // ... but the public half verifies through the other provider.
        byte[] message = new byte[128];
        RANDOM.nextBytes(message);
        Signature fipsEcdsa = Signature.getInstance("SHA256withECDSA", JostleFIPSProvider.PROVIDER_NAME);
        fipsEcdsa.initSign(fipsEcKp.getPrivate());
        fipsEcdsa.update(message);
        byte[] sig = fipsEcdsa.sign();
        Signature jslEcdsa = Signature.getInstance("SHA256withECDSA", JostleProvider.PROVIDER_NAME);
        jslEcdsa.initVerify(fipsEcKp.getPublic());
        jslEcdsa.update(message);
        Assertions.assertTrue(jslEcdsa.verify(sig), "JSLFIPS EC public key must verify through JSL");

        // DH: private isolated.
        KeyPairGenerator jslDh = KeyPairGenerator.getInstance("DH", JostleProvider.PROVIDER_NAME);
        jslDh.initialize(2048);
        KeyPair jslDhKp = jslDh.generateKeyPair();
        KeyAgreement fipsDh = KeyAgreement.getInstance("DH", JostleFIPSProvider.PROVIDER_NAME);
        assertRejected(() -> fipsDh.init(jslDhKp.getPrivate()));

        // XDH: private isolated; a foreign PUBLIC peer key in doPhase is
        // fine and derives the same secret as the pure-provider path.
        KeyPairGenerator jslX = KeyPairGenerator.getInstance("X25519", JostleProvider.PROVIDER_NAME);
        KeyPair jslXKp = jslX.generateKeyPair();
        KeyPairGenerator fipsXKpg = KeyPairGenerator.getInstance("X25519", JostleFIPSProvider.PROVIDER_NAME);
        KeyPair fipsXKp = fipsXKpg.generateKeyPair();

        KeyAgreement fipsX = KeyAgreement.getInstance("X25519", JostleFIPSProvider.PROVIDER_NAME);
        assertRejected(() -> fipsX.init(jslXKp.getPrivate()));

        fipsX.init(fipsXKp.getPrivate());
        fipsX.doPhase(jslXKp.getPublic(), true);
        byte[] mixed = fipsX.generateSecret();

        KeyAgreement jslX2 = KeyAgreement.getInstance("X25519", JostleProvider.PROVIDER_NAME);
        jslX2.init(jslXKp.getPrivate());
        jslX2.doPhase(fipsXKp.getPublic(), true);
        Assertions.assertArrayEquals(mixed, jslX2.generateSecret(),
                "foreign public peer keys must derive the same secret");
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
