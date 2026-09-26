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

package org.openssl.jostle.test.parity;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.IESKEMParameterSpec;
import org.openssl.jostle.jcajce.spec.KTSParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Secret-producer sizing rows for the key-transport ciphers, against BouncyCastle in both directions: the ML-KEM
 * KTS cipher with no KDF at KEK sizes up to its 32-byte shared secret, and the ETSI EC key-encapsulation wrap,
 * whose KEK follows the wrapped key's length, at wrapped-key sizes other than 16 bytes.
 */
public class SecretSizingParityTest
{
    private static Provider jsl;
    private static Provider bc;

    @BeforeAll
    public static void setUp()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        jsl = Security.getProvider(JostleProvider.PROVIDER_NAME);
        bc = Security.getProvider("BC") != null ? Security.getProvider("BC") : new BouncyCastleProvider();
    }

    @Test
    public void mlKemKtsWithNoKdfAgreesWithBouncyCastleAtEachKekSize() throws Exception
    {
        KeyPair bcPair = KeyPairGenerator.getInstance("ML-KEM-768", bc).generateKeyPair();
        KeyFactory kf = KeyFactory.getInstance("ML-KEM-768", jsl);
        PublicKey ourPub = kf.generatePublic(new X509EncodedKeySpec(bcPair.getPublic().getEncoded()));
        PrivateKey ourPriv = kf.generatePrivate(new PKCS8EncodedKeySpec(bcPair.getPrivate().getEncoded()));
        SecretKeySpec cek = new SecretKeySpec(new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, "AES");
        for (int bits : new int[]{128, 192, 256})
        {
            org.bouncycastle.jcajce.spec.KTSParameterSpec theirs =
                    new org.bouncycastle.jcajce.spec.KTSParameterSpec.Builder("AESWRAP", bits).withNoKdf().build();
            KTSParameterSpec ours = new KTSParameterSpec.Builder("AESWRAP", bits).withNoKdf().build();

            Cipher w = Cipher.getInstance("ML-KEM", bc);
            w.init(Cipher.WRAP_MODE, bcPair.getPublic(), theirs);
            Cipher u = Cipher.getInstance("ML-KEM", jsl);
            u.init(Cipher.UNWRAP_MODE, ourPriv, ours);
            Assertions.assertArrayEquals(cek.getEncoded(),
                    u.unwrap(w.wrap(cek), "AES", Cipher.SECRET_KEY).getEncoded(), bits + " bits, BC to JSL");

            Cipher ow = Cipher.getInstance("ML-KEM", jsl);
            ow.init(Cipher.WRAP_MODE, ourPub, ours);
            Cipher bu = Cipher.getInstance("ML-KEM", bc);
            bu.init(Cipher.UNWRAP_MODE, bcPair.getPrivate(), theirs);
            Assertions.assertArrayEquals(cek.getEncoded(),
                    bu.unwrap(ow.wrap(cek), "AES", Cipher.SECRET_KEY).getEncoded(), bits + " bits, JSL to BC");
        }
    }

    @Test
    public void etsiKemAgreesWithBouncyCastleAtEachWrappedKeySize() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", bc);
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair bcPair = kpg.generateKeyPair();
        KeyFactory kf = KeyFactory.getInstance("EC", jsl);
        PublicKey ourPub = kf.generatePublic(new X509EncodedKeySpec(bcPair.getPublic().getEncoded()));
        PrivateKey ourPriv = kf.generatePrivate(new PKCS8EncodedKeySpec(bcPair.getPrivate().getEncoded()));
        byte[] recipientInfo = {1, 2, 3};
        for (int n : new int[]{16, 17, 24, 32, 64})
        {
            byte[] raw = new byte[n];
            for (int i = 0; i < n; i++)
            {
                raw[i] = (byte) (i + 1);
            }
            SecretKeySpec cek = new SecretKeySpec(raw, "AES");

            Cipher w = Cipher.getInstance("ETSIKEMwithSHA256", jsl);
            w.init(Cipher.WRAP_MODE, ourPub, new IESKEMParameterSpec(recipientInfo));
            Cipher bu = Cipher.getInstance("ETSIKEMwithSHA256", bc);
            bu.init(Cipher.UNWRAP_MODE, bcPair.getPrivate(),
                    new org.bouncycastle.jcajce.spec.IESKEMParameterSpec(recipientInfo));
            Assertions.assertArrayEquals(raw, bu.unwrap(w.wrap(cek), "AES", Cipher.SECRET_KEY).getEncoded(),
                    n + " bytes, JSL to BC");

            Cipher bw = Cipher.getInstance("ETSIKEMwithSHA256", bc);
            bw.init(Cipher.WRAP_MODE, bcPair.getPublic(),
                    new org.bouncycastle.jcajce.spec.IESKEMParameterSpec(recipientInfo));
            Cipher u = Cipher.getInstance("ETSIKEMwithSHA256", jsl);
            u.init(Cipher.UNWRAP_MODE, ourPriv, new IESKEMParameterSpec(recipientInfo));
            Assertions.assertArrayEquals(raw, u.unwrap(bw.wrap(cek), "AES", Cipher.SECRET_KEY).getEncoded(),
                    n + " bytes, BC to JSL");
        }
    }
}
