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

package org.openssl.jostle.test.slhdsa;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.SLHDSAParameterSpec;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;

/**
 * Regression coverage for the GH issue #34 family of bugs applied to
 * SLH-DSA. Without the fix, the 192-bit and 256-bit security category
 * variants fail keygen when no explicit {@link java.security.SecureRandom}
 * is supplied because the JDK default DRBG only reports 128-bit strength.
 *
 * <p>We pick one representative variant per security category
 * (fast/small symmetric, SHA-2 vs SHAKE) rather than exhaustively
 * covering all twelve registered SLH-DSA transformations — the
 * strength-resolution path is identical for all of them.
 */
public class SLHDSARandStrengthTest
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
    public void slhdsaSha2_128f_noExplicitRandom_keyPairGen() throws Exception
    {
        // 128-bit strength — baseline that worked before the fix.
        KeyPair kp = generateKeyPair(SLHDSAParameterSpec.slh_dsa_sha2_128f);
        Assertions.assertNotNull(kp);
    }

    @Test
    public void slhdsaSha2_192f_noExplicitRandom_keyPairGen() throws Exception
    {
        // 192-bit strength — previously failed without explicit
        // SecureRandom.
        KeyPair kp = generateKeyPair(SLHDSAParameterSpec.slh_dsa_sha2_192f);
        Assertions.assertNotNull(kp);
    }

    @Test
    public void slhdsaSha2_256f_noExplicitRandom_keyPairGen() throws Exception
    {
        // 256-bit strength — previously failed without explicit
        // SecureRandom.
        KeyPair kp = generateKeyPair(SLHDSAParameterSpec.slh_dsa_sha2_256f);
        Assertions.assertNotNull(kp);
    }

    @Test
    public void slhdsaShake_192f_noExplicitRandom_keyPairGen() throws Exception
    {
        // SHAKE variant of the 192-bit case — exercises the same code
        // path but with a different OSSLKeyType so the strength-lookup
        // by name (containsSubstring "-192") is also covered.
        KeyPair kp = generateKeyPair(SLHDSAParameterSpec.slh_dsa_shake_192f);
        Assertions.assertNotNull(kp);
    }

    @Test
    public void slhdsaShake_256s_noExplicitRandom_keyPairGen() throws Exception
    {
        // 256-bit small (slow signing, smaller signatures) variant —
        // the SHAKE family's heaviest case.
        KeyPair kp = generateKeyPair(SLHDSAParameterSpec.slh_dsa_shake_256s);
        Assertions.assertNotNull(kp);
    }


    @Test
    public void slhdsaParameterSpec_getRequiredStrengthBits()
    {
        Assertions.assertEquals(128, SLHDSAParameterSpec.slh_dsa_sha2_128f.getRequiredStrengthBits());
        Assertions.assertEquals(128, SLHDSAParameterSpec.slh_dsa_sha2_128s.getRequiredStrengthBits());
        Assertions.assertEquals(192, SLHDSAParameterSpec.slh_dsa_sha2_192f.getRequiredStrengthBits());
        Assertions.assertEquals(192, SLHDSAParameterSpec.slh_dsa_sha2_192s.getRequiredStrengthBits());
        Assertions.assertEquals(256, SLHDSAParameterSpec.slh_dsa_sha2_256f.getRequiredStrengthBits());
        Assertions.assertEquals(256, SLHDSAParameterSpec.slh_dsa_sha2_256s.getRequiredStrengthBits());

        Assertions.assertEquals(128, SLHDSAParameterSpec.slh_dsa_shake_128f.getRequiredStrengthBits());
        Assertions.assertEquals(192, SLHDSAParameterSpec.slh_dsa_shake_192f.getRequiredStrengthBits());
        Assertions.assertEquals(256, SLHDSAParameterSpec.slh_dsa_shake_256s.getRequiredStrengthBits());
    }


    private static KeyPair generateKeyPair(SLHDSAParameterSpec spec) throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(spec.getName(),
                JostleProvider.PROVIDER_NAME);
        // Note: passing only the spec, NO SecureRandom — this is the
        // reproducer trigger.
        kpg.initialize(spec);
        return kpg.generateKeyPair();
    }
}
