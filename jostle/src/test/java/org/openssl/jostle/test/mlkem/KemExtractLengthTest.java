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

package org.openssl.jostle.test.mlkem;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.SecretKeyWithEncapsulation;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.KEMExtractSpec;
import org.openssl.jostle.jcajce.spec.KEMGenerateSpec;
import org.openssl.jostle.jcajce.spec.MLXKEMParameterSpec;

import javax.crypto.KeyGenerator;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Arrays;

/**
 * An encapsulation of the wrong length is refused before the native call. MLKEMAgreementTest pins the ML-KEM cell
 * against the type BouncyCastle throws for the same input.
 */
public class KemExtractLengthTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;

    @BeforeAll
    public static void beforeAll()
    {
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    @Test
    public void mlxKem_wrongLengthEncapsulation_refused() throws Exception
    {
        int measured = 0;
        for (MLXKEMParameterSpec spec : MLXKEMParameterSpec.all())
        {
            String name = spec.getName();
            if (Security.getProvider(JSL).getService("KeyGenerator", name) == null)
            {
                continue;
            }
            KeyPair kp = KeyPairGenerator.getInstance(name, JSL).generateKeyPair();
            int bits = spec.getSharedSecretBytes() * 8;
            byte[] enc = hybridEncapsulation(name, kp, bits);
            for (int delta : new int[]{-1, 1})
            {
                IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                        () -> hybridExtract(name, kp, Arrays.copyOf(enc, enc.length + delta), bits), name);
                Assertions.assertTrue(e.getMessage().startsWith("encapsulation wrong length: "), e.getMessage());
            }
            Assertions.assertNotNull(hybridExtract(name, kp, enc, bits));
            measured++;
        }
        Assertions.assertTrue(measured > 0, "no hybrid KEM registered");
    }

    static byte[] encapsulation(String name, String provider, KeyPair kp) throws Exception
    {
        KeyGenerator g = KeyGenerator.getInstance(name, provider);
        g.init(KEMGenerateSpec.builder().withPublicKey(kp.getPublic()).withAlgorithmName("AES")
                .withKeySizeInBits(256).build());
        return ((SecretKeyWithEncapsulation) g.generateKey()).getEncapsulation();
    }

    static Object extract(String name, String provider, KeyPair kp, byte[] enc, int bits) throws Exception
    {
        KeyGenerator g = KeyGenerator.getInstance(name, provider);
        g.init(new KEMExtractSpec(kp.getPrivate(), "AES", bits, enc));
        return g.generateKey();
    }

    private static byte[] hybridEncapsulation(String name, KeyPair kp, int bits) throws Exception
    {
        KeyGenerator g = KeyGenerator.getInstance(name, JSL);
        g.init(KEMGenerateSpec.builder().withPublicKey(kp.getPublic()).withAlgorithmName("AES")
                .withKeySizeInBits(bits).withNoKdf().build());
        return ((SecretKeyWithEncapsulation) g.generateKey()).getEncapsulation();
    }

    private static Object hybridExtract(String name, KeyPair kp, byte[] enc, int bits) throws Exception
    {
        KeyGenerator g = KeyGenerator.getInstance(name, JSL);
        g.init(KEMExtractSpec.builder().withPrivate(kp.getPrivate()).withAlgorithmName("AES")
                .withKeySizeInBits(bits).withEncapsulatedKey(enc).withNoKdf().build());
        return g.generateKey();
    }
}
