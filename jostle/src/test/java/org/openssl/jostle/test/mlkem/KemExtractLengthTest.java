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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
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
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;

/**
 * An encapsulation of the wrong length is refused before the native call, with the exception type BouncyCastle's
 * extractor throws for the same input.
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
    public void mlKem_wrongLengthEncapsulation_refusedAsBouncyCastleDoes() throws Exception
    {
        Provider bc = new BouncyCastleProvider();
        for (String name : new String[]{"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"})
        {
            KeyPair ours = KeyPairGenerator.getInstance(name, JSL).generateKeyPair();
            byte[] enc = encapsulation(name, JSL, ours);

            KeyPair theirs = KeyPairGenerator.getInstance(name, bc).generateKeyPair();
            KeyGenerator bcGen = KeyGenerator.getInstance("ML-KEM", bc);
            // KEMGenerateSpec is qualified where BouncyCastle's is meant: jostle's of that name is imported
            bcGen.init(new org.bouncycastle.jcajce.spec.KEMGenerateSpec(theirs.getPublic(), "AES", 256));
            // SecretKeyWithEncapsulation is qualified where BouncyCastle's is meant: jostle's of that name is imported
            byte[] bcEnc = ((org.bouncycastle.jcajce.SecretKeyWithEncapsulation) bcGen.generateKey())
                    .getEncapsulation();

            for (int delta : new int[]{-1, 1, -enc.length})
            {
                IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                        () -> extract(name, JSL, ours, Arrays.copyOf(enc, enc.length + delta), 256),
                        name + " delta " + delta);
                Assertions.assertEquals("encapsulation wrong length: " + (enc.length + delta) + " bytes, "
                        + name.replace('-', '_') + " takes " + enc.length, e.getMessage());

                // BouncyCastle's half, measured live.
                KeyGenerator x = KeyGenerator.getInstance("ML-KEM", bc);
                // KEMExtractSpec is qualified where BouncyCastle's is meant: jostle's of that name is imported
                x.init(new org.bouncycastle.jcajce.spec.KEMExtractSpec(theirs.getPrivate(),
                        Arrays.copyOf(bcEnc, bcEnc.length + delta), "AES", 256));
                Assertions.assertThrows(IllegalArgumentException.class, x::generateKey, "BC " + name);
            }

            // Control: the whole encapsulation extracts.
            Assertions.assertNotNull(extract(name, JSL, ours, enc, 256));
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
