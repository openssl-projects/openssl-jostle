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

package org.openssl.jostle.test.mlxkem;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.jcajce.SecretKeyWithEncapsulation;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.kts.InjectedRandom;
import org.openssl.jostle.jcajce.spec.KEMExtractSpec;
import org.openssl.jostle.jcajce.spec.KEMGenerateSpec;
import org.openssl.jostle.jcajce.spec.MLXKEMParameterSpec;

import javax.crypto.KeyGenerator;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

/**
 * The hybrid KEM KeyGenerator recognises the SecureRandom the JCE injects when the caller passes none, by identity,
 * and draws from the provider's own DRBG instead; a source the caller passes is not that object. Read through the
 * record of the last encapsulating init on this thread.
 */
public class MLXKEMInjectedRandomTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;

    @BeforeAll
    public static void before()
    {
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    private static KEMGenerateSpec generate(MLXKEMParameterSpec spec, KeyPair kp)
    {
        return KEMGenerateSpec.builder().withPublicKey(kp.getPublic()).withAlgorithmName("AES")
                .withKeySizeInBits(spec.getSharedSecretBytes() * 8).build();
    }

    @Test
    public void encapsulateInitRecognisesTheInjectedDefaultOnly() throws Exception
    {
        for (MLXKEMParameterSpec spec : MLXKEMParameterSpec.all())
        {
            String name = spec.getName();
            KeyPair kp = KeyPairGenerator.getInstance(name, JSL).generateKeyPair();

            KeyGenerator plain = KeyGenerator.getInstance(name, JSL);
            plain.init(generate(spec, kp));
            Assertions.assertTrue(InjectedRandom.lastInitSawInjectedDefault(), name + ": init(spec)");
            SecretKeyWithEncapsulation sent = (SecretKeyWithEncapsulation) plain.generateKey();

            KeyGenerator explicit = KeyGenerator.getInstance(name, JSL);
            explicit.init(generate(spec, kp), CryptoServicesRegistrar.getSecureRandom(256));
            Assertions.assertFalse(InjectedRandom.lastInitSawInjectedDefault(), name + ": init(spec, random)");

            // Control: the default-initialised encapsulation opens.
            KeyGenerator receiver = KeyGenerator.getInstance(name, JSL);
            receiver.init(KEMExtractSpec.builder().withPrivate(kp.getPrivate()).withAlgorithmName("AES")
                    .withKeySizeInBits(spec.getSharedSecretBytes() * 8)
                    .withEncapsulatedKey(sent.getEncapsulation()).build());
            Assertions.assertArrayEquals(sent.getEncoded(), receiver.generateKey().getEncoded(), name);
        }
    }
}
