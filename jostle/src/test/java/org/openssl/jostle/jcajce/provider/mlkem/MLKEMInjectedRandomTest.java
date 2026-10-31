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

package org.openssl.jostle.jcajce.provider.mlkem;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.kts.InjectedRandom;
import org.openssl.jostle.jcajce.SecretKeyWithEncapsulation;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.KEMExtractSpec;
import org.openssl.jostle.jcajce.spec.KEMGenerateSpec;
import org.openssl.jostle.jcajce.spec.KTSParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

/**
 * The KEM KeyGenerator and the KTS cipher recognise the SecureRandom the JCE injects when the caller passes none,
 * by identity, and draw from the provider's own DRBG instead; a source the caller passes is not that object. Read
 * through the package-private record of the last encapsulating init on this thread. In the provider package
 * because the record is package-private.
 */
public class MLKEMInjectedRandomTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final SecureRandom RANDOM = new SecureRandom();

    @BeforeAll
    public static void before()
    {
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    private static KEMGenerateSpec generate(KeyPair kp)
    {
        return KEMGenerateSpec.builder().withPublicKey(kp.getPublic()).withAlgorithmName("AES")
                .withKeySizeInBits(256).build();
    }

    @Test
    public void encapsulateInitRecognisesTheInjectedDefaultOnly() throws Exception
    {
        for (String name : new String[]{"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"})
        {
            KeyPair kp = KeyPairGenerator.getInstance(name, JSL).generateKeyPair();

            KeyGenerator plain = KeyGenerator.getInstance("ML-KEM", JSL);
            plain.init(generate(kp));
            Assertions.assertTrue(InjectedRandom.lastInitSawInjectedDefault(), name + ": init(spec)");
            SecretKeyWithEncapsulation sent = (SecretKeyWithEncapsulation) plain.generateKey();

            KeyGenerator explicit = KeyGenerator.getInstance("ML-KEM", JSL);
            explicit.init(generate(kp), new SecureRandom());
            Assertions.assertFalse(InjectedRandom.lastInitSawInjectedDefault(), name + ": init(spec, random)");

            // Control: the default-initialised encapsulation opens.
            KeyGenerator receiver = KeyGenerator.getInstance("ML-KEM", JSL);
            receiver.init(KEMExtractSpec.builder().withPrivate(kp.getPrivate()).withAlgorithmName("AES")
                    .withKeySizeInBits(256).withEncapsulatedKey(sent.getEncapsulation()).build());
            Assertions.assertArrayEquals(sent.getEncoded(), receiver.generateKey().getEncoded(), name);
        }
    }

    @Test
    public void wrapInitRecognisesTheInjectedDefaultOnly() throws Exception
    {
        for (String name : new String[]{"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"})
        {
            KeyPair kp = KeyPairGenerator.getInstance(name, JSL).generateKeyPair();
            KTSParameterSpec spec = new KTSParameterSpec.Builder("AES-KWP", 256).build();

            Cipher plain = Cipher.getInstance("ML-KEM", JSL);
            plain.init(Cipher.WRAP_MODE, kp.getPublic(), spec);
            Assertions.assertTrue(InjectedRandom.lastInitSawInjectedDefault(), name + ": init(WRAP, key, spec)");
            byte[] raw = new byte[16];
            RANDOM.nextBytes(raw);
            byte[] wrapped = plain.wrap(new SecretKeySpec(raw, "AES"));

            Cipher explicit = Cipher.getInstance("ML-KEM", JSL);
            explicit.init(Cipher.WRAP_MODE, kp.getPublic(), spec, SecureRandom.getInstance("SHA1PRNG"));
            Assertions.assertFalse(InjectedRandom.lastInitSawInjectedDefault(), name + ": init with a source");

            // Control: the default-initialised wrap unwraps.
            Cipher unwrap = Cipher.getInstance("ML-KEM", JSL);
            unwrap.init(Cipher.UNWRAP_MODE, kp.getPrivate(), spec);
            Assertions.assertArrayEquals(raw, unwrap.unwrap(wrapped, "AES", Cipher.SECRET_KEY).getEncoded(), name);
        }
    }
}
