/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.kdf;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.HKDFParameterSpec;
import org.openssl.jostle.jcajce.spec.IESKEMParameterSpec;
import org.openssl.jostle.jcajce.spec.ScryptKeySpec;
import org.openssl.jostle.jcajce.spec.UserKeyingMaterialSpec;
import org.openssl.jostle.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * D50/C45 regressions: BouncyCastle's own spec types are refused typed by the
 * key-agreement KDF, the ETSI KEM cipher, and the scrypt/HKDF secret-key
 * factories — this test file names one site for each, plus a Jostle-spec
 * positive twin producing the same bytes as BC given the same content.
 */
public class ForeignSpecRefusalRegressionTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final SecureRandom RANDOM = new SecureRandom();

    @BeforeAll
    public static void setUp()
    {
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    // -----------------------------------------------------------------
    // KeyAgreementKDF: BC's UserKeyingMaterialSpec is refused.
    // -----------------------------------------------------------------

    @Test
    public void bcUserKeyingMaterialSpecRefusedByKeyAgreementKdf() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", JSL);
        kpg.initialize(new ECGenParameterSpec("P-256"));
        KeyPair alice = kpg.generateKeyPair();
        KeyPair bob = kpg.generateKeyPair();

        byte[] ukm = new byte[16];
        RANDOM.nextBytes(ukm);
        org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec bcSpec =
                new org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec(ukm);

        KeyAgreement ka = KeyAgreement.getInstance("ECDHWITHSHA256KDF", JSL);
        Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                () -> ka.init(alice.getPrivate(), bcSpec));
    }

    /** Jostle's own UserKeyingMaterialSpec must derive what BC's own does. */
    @Test
    public void ourUserKeyingMaterialSpecAgreesWithBc() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", JSL);
        kpg.initialize(new ECGenParameterSpec("P-256"));
        KeyPair alice = kpg.generateKeyPair();
        KeyPair bob = kpg.generateKeyPair();

        byte[] ukm = new byte[16];
        RANDOM.nextBytes(ukm);

        KeyAgreement jsl = KeyAgreement.getInstance("ECDHWITHSHA256KDF", JSL);
        jsl.init(alice.getPrivate(), new UserKeyingMaterialSpec(ukm));
        jsl.doPhase(bob.getPublic(), true);
        byte[] jslKek = jsl.generateSecret("2.16.840.1.101.3.4.1.45").getEncoded(); // id-aes256-wrap

        PrivateKey bcAlicePriv = KeyFactory.getInstance("EC", BC)
                .generatePrivate(new PKCS8EncodedKeySpec(alice.getPrivate().getEncoded()));
        PublicKey bcBobPub = KeyFactory.getInstance("EC", BC)
                .generatePublic(new X509EncodedKeySpec(bob.getPublic().getEncoded()));
        KeyAgreement bc = KeyAgreement.getInstance("ECDHWITHSHA256KDF", BC);
        bc.init(bcAlicePriv, new org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec(ukm));
        bc.doPhase(bcBobPub, true);
        byte[] bcKek = bc.generateSecret("2.16.840.1.101.3.4.1.45").getEncoded();

        Assertions.assertArrayEquals(bcKek, jslKek, "Jostle's UserKeyingMaterialSpec must agree with BC's own");
    }

    // -----------------------------------------------------------------
    // ETSI KEM: BC's IESKEMParameterSpec is refused.
    // -----------------------------------------------------------------

    @Test
    public void bcIesKemParameterSpecRefusedByEtsiKem() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", JSL);
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair recipient = kpg.generateKeyPair();

        org.bouncycastle.jcajce.spec.IESKEMParameterSpec bcSpec =
                new org.bouncycastle.jcajce.spec.IESKEMParameterSpec(new byte[12]);

        Cipher c = Cipher.getInstance("ETSIKEMwithSHA256", JSL);
        InvalidAlgorithmParameterException e = Assertions.assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> c.init(Cipher.WRAP_MODE, recipient.getPublic(), bcSpec, RANDOM));
        Assertions.assertTrue(e.getMessage().contains("IESKEMParameterSpec"),
                "message must name IESKEMParameterSpec: " + e.getMessage());
    }

    /** Jostle's own IESKEMParameterSpec wraps and unwraps through the Jostle cipher. */
    @Test
    public void ourIesKemParameterSpecRoundTrips() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", JSL);
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair recipient = kpg.generateKeyPair();

        byte[] recipientInfo = new byte[12];
        RANDOM.nextBytes(recipientInfo);
        byte[] cekBytes = new byte[16];
        RANDOM.nextBytes(cekBytes);
        SecretKey cek = new SecretKeySpec(cekBytes, "AES");

        Cipher w = Cipher.getInstance("ETSIKEMwithSHA256", JSL);
        w.init(Cipher.WRAP_MODE, recipient.getPublic(), new IESKEMParameterSpec(recipientInfo), RANDOM);
        byte[] wrapped = w.wrap(cek);

        Cipher u = Cipher.getInstance("ETSIKEMwithSHA256", JSL);
        u.init(Cipher.UNWRAP_MODE, recipient.getPrivate(), new IESKEMParameterSpec(recipientInfo));
        Assertions.assertArrayEquals(cekBytes,
                u.unwrap(wrapped, "AES", Cipher.SECRET_KEY).getEncoded(), "ETSI KEM round trip failed");
    }

    // -----------------------------------------------------------------
    // SCRYPT: BC's ScryptKeySpec is refused.
    // -----------------------------------------------------------------

    @Test
    public void bcScryptKeySpecRefused() throws Exception
    {
        char[] password = "a-password".toCharArray();
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        org.bouncycastle.jcajce.spec.ScryptKeySpec bcSpec =
                new org.bouncycastle.jcajce.spec.ScryptKeySpec(password, salt, 16, 1, 1, 256);

        SecretKeyFactory kf = SecretKeyFactory.getInstance("SCRYPT", JSL);
        InvalidKeySpecException e = Assertions.assertThrows(InvalidKeySpecException.class,
                () -> kf.generateSecret(bcSpec));
        Assertions.assertTrue(e.getMessage().contains("org.openssl.jostle.jcajce.spec.ScryptKeySpec"),
                "message must name the Jostle class: " + e.getMessage());
    }

    @Test
    public void ourScryptKeySpecAgreesWithBc() throws Exception
    {
        char[] password = "a-password".toCharArray();
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);

        byte[] jsl = SecretKeyFactory.getInstance("SCRYPT", JSL)
                .generateSecret(new ScryptKeySpec(password, salt, 16, 1, 1, 256)).getEncoded();
        byte[] bc = SecretKeyFactory.getInstance("SCRYPT", BC)
                .generateSecret(new org.bouncycastle.jcajce.spec.ScryptKeySpec(password, salt, 16, 1, 1, 256))
                .getEncoded();

        Assertions.assertArrayEquals(bc, jsl, "Jostle's ScryptKeySpec must agree with BC's own");
    }

    // -----------------------------------------------------------------
    // HKDF: BC's HKDFParameterSpec is refused.
    // -----------------------------------------------------------------

    @Test
    public void bcHkdfParameterSpecRefused() throws Exception
    {
        byte[] ikm = new byte[32];
        RANDOM.nextBytes(ikm);
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        org.bouncycastle.jcajce.spec.HKDFParameterSpec bcSpec =
                new org.bouncycastle.jcajce.spec.HKDFParameterSpec(ikm, salt, null, 32);

        SecretKeyFactory kf = SecretKeyFactory.getInstance("HKDF-SHA256", JSL);
        InvalidKeySpecException e = Assertions.assertThrows(InvalidKeySpecException.class,
                () -> kf.generateSecret(bcSpec));
        Assertions.assertTrue(e.getMessage().contains("org.openssl.jostle.jcajce.spec.HKDFParameterSpec"),
                "message must name the Jostle class: " + e.getMessage());
    }

    @Test
    public void ourHkdfParameterSpecAgreesWithBc() throws Exception
    {
        byte[] ikm = new byte[32];
        RANDOM.nextBytes(ikm);
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);

        byte[] jsl = SecretKeyFactory.getInstance("HKDF-SHA256", JSL)
                .generateSecret(new HKDFParameterSpec(ikm, salt, null, 32)).getEncoded();
        byte[] bc = SecretKeyFactory.getInstance("HKDF-SHA256", BC)
                .generateSecret(new org.bouncycastle.jcajce.spec.HKDFParameterSpec(ikm, salt, null, 32))
                .getEncoded();

        Assertions.assertArrayEquals(bc, jsl, "Jostle's HKDFParameterSpec must agree with BC's own");
        Assertions.assertFalse(Arrays.areEqual(new byte[32], jsl), "derived key must not be all zero");
    }
}
