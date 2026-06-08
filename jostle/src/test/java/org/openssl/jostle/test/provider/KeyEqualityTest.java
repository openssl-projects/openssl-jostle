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
import org.openssl.jostle.jcajce.spec.ScryptKeySpec;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Tests the value-equality contracts added to JSL key types:
 * <ul>
 *   <li>{@code AsymmetricKeyImpl} (RSA / EC public + private keys) — encoded-form
 *       equality; encoding embeds the algorithm OID and key role, so two keys
 *       with the same encoding are equal regardless of provider,</li>
 *   <li>{@code JOPBEKey} and {@code JOScryptKey} — algorithm (case-insensitive)
 *       plus raw-key equality, following the {@code SecretKeySpec} contract.</li>
 * </ul>
 *
 * <p>Before these overrides, JSL keys inherited identity equality, so two
 * instances of the same key never compared equal — breaking callers that key
 * collections on keys or compare a parsed key against a certificate's key. Each
 * case asserts both directions of the contract: equal-when-same and (the
 * negative path) unequal-when-different, plus {@code equals}/{@code hashCode}
 * consistency.
 */
public class KeyEqualityTest
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

    // -----------------------------------------------------------------
    // AsymmetricKeyImpl — RSA
    // -----------------------------------------------------------------

    @Test
    public void testRsaPublicKey_encodedEqualityAndHashCode() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", JostleProvider.PROVIDER_NAME);
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kf = KeyFactory.getInstance("RSA", JostleProvider.PROVIDER_NAME);
        PublicKey reimported = kf.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));

        // Two distinct JSL instances of the same key must be equal with equal hashCodes.
        Assertions.assertNotSame(kp.getPublic(), reimported);
        Assertions.assertEquals(kp.getPublic(), reimported);
        Assertions.assertEquals(reimported, kp.getPublic());
        Assertions.assertEquals(kp.getPublic().hashCode(), reimported.hashCode());

        // A different key must not be equal.
        KeyPair other = kpg.generateKeyPair();
        Assertions.assertNotEquals(kp.getPublic(), other.getPublic());

        // Public must not equal the private half of the same pair (different encoding/role).
        Assertions.assertNotEquals((Object) kp.getPublic(), (Object) kp.getPrivate());
    }

    @Test
    public void testRsaPrivateKey_encodedEqualityAndHashCode() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", JostleProvider.PROVIDER_NAME);
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kf = KeyFactory.getInstance("RSA", JostleProvider.PROVIDER_NAME);
        PrivateKey reimported = kf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        Assertions.assertNotSame(kp.getPrivate(), reimported);
        Assertions.assertEquals(kp.getPrivate(), reimported);
        Assertions.assertEquals(kp.getPrivate().hashCode(), reimported.hashCode());

        KeyPair other = kpg.generateKeyPair();
        Assertions.assertNotEquals(kp.getPrivate(), other.getPrivate());
    }

    @Test
    public void testRsaPublicKey_equalsForeignKeyWithSameEncoding() throws Exception
    {
        // Encoded-form equality is provider-agnostic: a BC RSA public key with
        // byte-identical SubjectPublicKeyInfo must compare equal to the JSL key.
        // This is the "compare a parsed key against a certificate's key" use case.
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", JostleProvider.PROVIDER_NAME);
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        KeyFactory bcKf = KeyFactory.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        PublicKey bcPub = bcKf.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));

        Assertions.assertArrayEquals(kp.getPublic().getEncoded(), bcPub.getEncoded(),
                "precondition: BC re-encode must be byte-identical");
        Assertions.assertEquals(kp.getPublic(), bcPub,
                "JSL key did not equal a foreign key with identical encoding");
    }

    // -----------------------------------------------------------------
    // AsymmetricKeyImpl — EC
    // -----------------------------------------------------------------

    @Test
    public void testEcKeys_encodedEqualityAndHashCode() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", JostleProvider.PROVIDER_NAME);
        kpg.initialize(new ECGenParameterSpec("P-256"));
        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kf = KeyFactory.getInstance("EC", JostleProvider.PROVIDER_NAME);
        PublicKey reimportedPub = kf.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
        PrivateKey reimportedPriv = kf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        Assertions.assertEquals(kp.getPublic(), reimportedPub);
        Assertions.assertEquals(kp.getPublic().hashCode(), reimportedPub.hashCode());
        Assertions.assertEquals(kp.getPrivate(), reimportedPriv);
        Assertions.assertEquals(kp.getPrivate().hashCode(), reimportedPriv.hashCode());

        KeyPair other = kpg.generateKeyPair();
        Assertions.assertNotEquals(kp.getPublic(), other.getPublic());
        Assertions.assertNotEquals(kp.getPrivate(), other.getPrivate());
    }

    // -----------------------------------------------------------------
    // JOPBEKey
    // -----------------------------------------------------------------

    @Test
    public void testPbeKey_algorithmAndRawKeyEquality() throws Exception
    {
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        char[] pwd = "correct horse battery staple".toCharArray();

        SecretKeyFactory kf = SecretKeyFactory.getInstance("PBKDF2WITHHMACSHA256", JostleProvider.PROVIDER_NAME);
        SecretKey k1 = kf.generateSecret(new PBEKeySpec(pwd, salt, 1000, 256));
        SecretKey k2 = kf.generateSecret(new PBEKeySpec(pwd, salt, 1000, 256));

        // Same derivation → equal with equal hashCodes.
        Assertions.assertNotSame(k1, k2);
        Assertions.assertEquals(k1, k2);
        Assertions.assertEquals(k1.hashCode(), k2.hashCode());

        // A SecretKeySpec carrying the same algorithm + bytes is equal (the
        // override accepts any SecretKey, per the SecretKeySpec contract).
        SecretKey spec = new SecretKeySpec(k1.getEncoded(), k1.getAlgorithm());
        Assertions.assertEquals(k1, spec);

        // Different password → different key.
        SecretKey k3 = kf.generateSecret(new PBEKeySpec("different".toCharArray(), salt, 1000, 256));
        Assertions.assertNotEquals(k1, k3);
    }

    // -----------------------------------------------------------------
    // JOScryptKey
    // -----------------------------------------------------------------

    @Test
    public void testScryptKey_algorithmAndRawKeyEquality() throws Exception
    {
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        char[] pwd = "scrypt password".toCharArray();

        SecretKeyFactory kf = SecretKeyFactory.getInstance("SCRYPT", JostleProvider.PROVIDER_NAME);
        SecretKey k1 = kf.generateSecret(new ScryptKeySpec(pwd, salt, 2, 1, 1, 256));
        SecretKey k2 = kf.generateSecret(new ScryptKeySpec(pwd, salt, 2, 1, 1, 256));

        Assertions.assertNotSame(k1, k2);
        Assertions.assertEquals(k1, k2);
        Assertions.assertEquals(k1.hashCode(), k2.hashCode());

        SecretKey spec = new SecretKeySpec(k1.getEncoded(), k1.getAlgorithm());
        Assertions.assertEquals(k1, spec);

        // Different password → different key.
        SecretKey k3 = kf.generateSecret(new ScryptKeySpec("other".toCharArray(), salt, 2, 1, 1, 256));
        Assertions.assertNotEquals(k1, k3);
    }
}
