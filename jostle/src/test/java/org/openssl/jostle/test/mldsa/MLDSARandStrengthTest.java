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

package org.openssl.jostle.test.mldsa;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.MLDSAParameterSpec;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;

/**
 * Regression coverage for the GH issue #34 family of bugs — same root
 * cause as the ML-KEM case, but applied to ML-DSA where ML-DSA-65 needs
 * 192-bit RNG strength and ML-DSA-87 needs 256-bit. Without the fix,
 * the higher-strength variants fail keygen when no explicit
 * {@link java.security.SecureRandom} is supplied because the JDK
 * default DRBG only reports 128-bit strength.
 */
public class MLDSARandStrengthTest
{
    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }


    @Test
    public void mldsa44_noExplicitRandom_keyPairGen() throws Exception
    {
        KeyPair kp = generateKeyPair(MLDSAParameterSpec.ml_dsa_44);
        Assertions.assertNotNull(kp);
        Assertions.assertNotNull(kp.getPublic());
        Assertions.assertNotNull(kp.getPrivate());
    }

    @Test
    public void mldsa65_noExplicitRandom_keyPairGen() throws Exception
    {
        // 192-bit strength variant — previously failed without explicit
        // SecureRandom because JDK default DRBG only provides 128 bits.
        KeyPair kp = generateKeyPair(MLDSAParameterSpec.ml_dsa_65);
        Assertions.assertNotNull(kp);
        Assertions.assertNotNull(kp.getPublic());
        Assertions.assertNotNull(kp.getPrivate());
    }

    @Test
    public void mldsa87_noExplicitRandom_keyPairGen() throws Exception
    {
        // 256-bit strength variant — same root cause as above.
        KeyPair kp = generateKeyPair(MLDSAParameterSpec.ml_dsa_87);
        Assertions.assertNotNull(kp);
        Assertions.assertNotNull(kp.getPublic());
        Assertions.assertNotNull(kp.getPrivate());
    }


    @Test
    public void mldsaParameterSpec_getRequiredStrengthBits()
    {
        Assertions.assertEquals(128, MLDSAParameterSpec.ml_dsa_44.getRequiredStrengthBits());
        Assertions.assertEquals(192, MLDSAParameterSpec.ml_dsa_65.getRequiredStrengthBits());
        Assertions.assertEquals(256, MLDSAParameterSpec.ml_dsa_87.getRequiredStrengthBits());
    }


    private static KeyPair generateKeyPair(MLDSAParameterSpec spec) throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(spec.getName(),
                JostleProvider.PROVIDER_NAME);
        // Note: passing only the spec, NO SecureRandom — this is the
        // reproducer trigger.
        kpg.initialize(spec);
        return kpg.generateKeyPair();
    }
}
