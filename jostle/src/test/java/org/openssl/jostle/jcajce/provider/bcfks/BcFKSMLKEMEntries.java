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

package org.openssl.jostle.jcajce.provider.bcfks;

import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.interfaces.MLKEMPrivateKey;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.openssl.jostle.jcajce.spec.KEMExtractSpec;

import javax.crypto.KeyGenerator;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.cert.Certificate;

/**
 * BouncyCastle's ML-KEM private keys, expanded-only and the both-form control, set into a BCFKS store of the
 * provider under test, stored and loaded back: the key read back opens a BouncyCastle encapsulation to
 * BouncyCastle's secret. Shared by the base and FIPS agreement classes.
 */
final class BcFKSMLKEMEntries
{
    static final String[] PARAMETER_SETS = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"};
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final int PASSWORD_CHARS = 16;
    private static final int LETTERS = 26;
    private static final int SECRET_BITS = 256;
    private static final SecureRandom RANDOM = new SecureRandom();

    private BcFKSMLKEMEntries()
    {
    }

    static void storeAndOpen(Provider provider, Certificate certificate) throws Exception
    {
        for (String name : PARAMETER_SETS)
        {
            KeyPair bc = KeyPairGenerator.getInstance(name, BC).generateKeyPair();
            PrivateKey expanded = ((MLKEMPrivateKey) bc.getPrivate()).getPrivateKey(false);
            storeAndOpen(provider, certificate, bc, bc.getPrivate(), name + ": both forms");
            storeAndOpen(provider, certificate, bc, expanded, name + ": expanded only");
        }
    }

    private static void storeAndOpen(Provider provider, Certificate certificate, KeyPair bc, PrivateKey key,
                                     String label) throws Exception
    {
        char[] password = password();
        KeyStore store = KeyStore.getInstance("BCFKS", provider);
        store.load(null, null);
        store.setKeyEntry("k", key, password, new Certificate[]{certificate});
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        store.store(out, password);

        KeyStore back = KeyStore.getInstance("BCFKS", provider);
        back.load(new ByteArrayInputStream(out.toByteArray()), password);
        PrivateKey readBack = (PrivateKey) back.getKey("k", password);
        Assertions.assertNotNull(readBack, label);

        KeyGenerator bcGen = KeyGenerator.getInstance("ML-KEM", BC);
        bcGen.init(new KEMGenerateSpec.Builder(bc.getPublic(), "AES", SECRET_BITS).withKdfAlgorithm(null).build());
        SecretKeyWithEncapsulation sent = (SecretKeyWithEncapsulation) bcGen.generateKey();
        KeyGenerator joGen = KeyGenerator.getInstance("ML-KEM", provider);
        joGen.init(KEMExtractSpec.builder().withPrivate(readBack).withEncapsulatedKey(sent.getEncapsulation())
                .withAlgorithmName("AES").withKeySizeInBits(SECRET_BITS).withNoKdf().build());
        Assertions.assertArrayEquals(sent.getEncoded(), joGen.generateKey().getEncoded(), label);
    }

    private static char[] password()
    {
        char[] password = new char[PASSWORD_CHARS];
        for (int i = 0; i < password.length; i++)
        {
            password[i] = (char) ('a' + RANDOM.nextInt(LETTERS));
        }
        return password;
    }
}
