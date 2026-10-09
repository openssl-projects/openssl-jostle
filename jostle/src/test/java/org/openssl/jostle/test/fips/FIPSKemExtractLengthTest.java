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

package org.openssl.jostle.test.fips;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.SecretKeyWithEncapsulation;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.jcajce.spec.KEMExtractSpec;
import org.openssl.jostle.jcajce.spec.KEMGenerateSpec;
import org.openssl.jostle.jcajce.spec.MLXKEMParameterSpec;
import org.openssl.jostle.test.TestUtil;

import javax.crypto.KeyGenerator;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Arrays;

/**
 * JSLFIPS refuses an encapsulation of the wrong length before the native call, with the type the base twin pins
 * against BouncyCastle.
 */
public class FIPSKemExtractLengthTest
{
    private static final String FIPS = JostleFIPSProvider.PROVIDER_NAME;

    @BeforeAll
    public static void beforeAll()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        TestUtil.addFipsProvider();
    }

    @Test
    public void mlKem_wrongLengthEncapsulation_refused() throws Exception
    {
        Assumptions.assumeTrue(FIPSTestUtil.moduleServesKeyMgmt("ML-KEM-768"),
                "the loaded FIPS module implements no ML-KEM (3.1.2)");
        for (String name : new String[]{"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"})
        {
            KeyPair kp = KeyPairGenerator.getInstance(name, FIPS).generateKeyPair();
            KeyGenerator g = KeyGenerator.getInstance(name, FIPS);
            g.init(KEMGenerateSpec.builder().withPublicKey(kp.getPublic()).withAlgorithmName("AES")
                    .withKeySizeInBits(256).build());
            byte[] enc = ((SecretKeyWithEncapsulation) g.generateKey()).getEncapsulation();
            for (int delta : new int[]{-1, 1, -enc.length})
            {
                KeyGenerator x = KeyGenerator.getInstance(name, FIPS);
                x.init(new KEMExtractSpec(kp.getPrivate(), "AES", 256, Arrays.copyOf(enc, enc.length + delta)));
                IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                        x::generateKey, name + " delta " + delta);
                Assertions.assertEquals("encapsulation wrong length: " + (enc.length + delta) + " bytes, "
                        + name.replace('-', '_') + " takes " + enc.length, e.getMessage());
            }
            KeyGenerator ok = KeyGenerator.getInstance(name, FIPS);
            ok.init(new KEMExtractSpec(kp.getPrivate(), "AES", 256, enc));
            Assertions.assertNotNull(ok.generateKey());
        }
    }

    /**
     * Each hybrid KeyGenerator is registered exactly where the module serves the type, and where it is, refuses an
     * encapsulation one byte short or long. Runs on every module.
     */
    @Test
    public void mlxKem_registeredIffServed_andWrongLengthRefused() throws Exception
    {
        for (MLXKEMParameterSpec spec : MLXKEMParameterSpec.all())
        {
            String name = spec.getName();
            boolean registered = Security.getProvider(FIPS).getService("KeyGenerator", name) != null;
            Assertions.assertEquals(FIPSTestUtil.moduleServesKeyMgmt(name), registered, name);
            if (!registered)
            {
                continue;
            }
            int bits = spec.getSharedSecretBytes() * 8;
            KeyPair kp = KeyPairGenerator.getInstance(name, FIPS).generateKeyPair();
            KeyGenerator g = KeyGenerator.getInstance(name, FIPS);
            g.init(KEMGenerateSpec.builder().withPublicKey(kp.getPublic()).withAlgorithmName("AES")
                    .withKeySizeInBits(bits).withNoKdf().build());
            byte[] enc = ((SecretKeyWithEncapsulation) g.generateKey()).getEncapsulation();
            for (int delta : new int[]{-1, 1})
            {
                KeyGenerator x = KeyGenerator.getInstance(name, FIPS);
                x.init(KEMExtractSpec.builder().withPrivate(kp.getPrivate()).withAlgorithmName("AES")
                        .withKeySizeInBits(bits).withEncapsulatedKey(Arrays.copyOf(enc, enc.length + delta))
                        .withNoKdf().build());
                IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                        x::generateKey, name + " delta " + delta);
                Assertions.assertTrue(e.getMessage().startsWith("encapsulation wrong length: "), e.getMessage());
            }
        }
    }
}
