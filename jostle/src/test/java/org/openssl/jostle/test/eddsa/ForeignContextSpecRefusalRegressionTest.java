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

package org.openssl.jostle.test.eddsa;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.EdDSAParameterSpec;
import org.openssl.jostle.jcajce.spec.MLDSAParameterSpec;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;

/**
 * D50/C46: BouncyCastle's own {@code org.bouncycastle.jcajce.spec.ContextParameterSpec}
 * is refused typed by {@code EdSignatureSpi} and {@code MLDSASignatureSpi} —
 * on EVERY JDK level, since neither the baseline nor any {@code javaN} copy
 * special-cases BC's class. Lives in {@code src/test/java} (not gated by
 * {@code MultiReleaseOverrides}) precisely so it runs on JDK 8 too.
 */
public class ForeignContextSpecRefusalRegressionTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    @BeforeAll
    public static void before()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    @Test
    public void ed25519_refusesBouncyCastleContextParameterSpec() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
        kpg.initialize(EdDSAParameterSpec.ED25519, RANDOM);
        KeyPair kp = kpg.generateKeyPair();

        Signature s = Signature.getInstance("ED25519", JostleProvider.PROVIDER_NAME);
        s.initSign(kp.getPrivate());
        org.bouncycastle.jcajce.spec.ContextParameterSpec foreign =
                new org.bouncycastle.jcajce.spec.ContextParameterSpec(new byte[]{1, 2, 3});
        Assertions.assertThrows(InvalidAlgorithmParameterException.class, () -> s.setParameter(foreign),
                "ED25519 must refuse BouncyCastle's own ContextParameterSpec");
    }

    @Test
    public void mldsa_refusesBouncyCastleContextParameterSpec() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
        kpg.initialize(MLDSAParameterSpec.ml_dsa_44, RANDOM);
        KeyPair kp = kpg.generateKeyPair();

        Signature s = Signature.getInstance("ML-DSA-44", JostleProvider.PROVIDER_NAME);
        s.initSign(kp.getPrivate());
        org.bouncycastle.jcajce.spec.ContextParameterSpec foreign =
                new org.bouncycastle.jcajce.spec.ContextParameterSpec(new byte[]{1, 2, 3});
        Assertions.assertThrows(InvalidAlgorithmParameterException.class, () -> s.setParameter(foreign),
                "ML-DSA-44 must refuse BouncyCastle's own ContextParameterSpec");
    }
}
