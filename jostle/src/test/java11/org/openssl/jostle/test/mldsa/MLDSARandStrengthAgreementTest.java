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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.MLDSAParameterSpec;

import java.security.DrbgParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;

/**
 * The caller's SecureRandom against the ML-DSA strength gate, per parameter set: JSL refuses a source reporting less
 * strength than the set requires and accepts one reporting enough or none; BouncyCastle accepts every source. The
 * Java gate is JSL's only strength gate.
 */
public class MLDSARandStrengthAgreementTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final MLDSAParameterSpec[] SPECS = {
            MLDSAParameterSpec.ml_dsa_44, MLDSAParameterSpec.ml_dsa_65, MLDSAParameterSpec.ml_dsa_87};
    // MLDSAParameterSpec is qualified where BouncyCastle's is meant: jostle's of that name is imported
    private static final org.bouncycastle.jcajce.spec.MLDSAParameterSpec[] BC_SPECS = {
            org.bouncycastle.jcajce.spec.MLDSAParameterSpec.ml_dsa_44,
            org.bouncycastle.jcajce.spec.MLDSAParameterSpec.ml_dsa_65,
            org.bouncycastle.jcajce.spec.MLDSAParameterSpec.ml_dsa_87};
    private static final int[] STRENGTHS = {128, 192, 256};

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static SecureRandom drbg(int strength) throws Exception
    {
        return SecureRandom.getInstance("DRBG",
                DrbgParameters.instantiation(strength, DrbgParameters.Capability.NONE, null));
    }

    @Test
    public void jslRefusesAWeakerSourceAndBouncyCastleAcceptsEverySource() throws Exception
    {
        for (int i = 0; i < SPECS.length; i++)
        {
            MLDSAParameterSpec spec = SPECS[i];
            int required = spec.getRequiredStrengthBits();
            for (int strength : STRENGTHS)
            {
                SecureRandom rand = drbg(strength);
                KeyPairGenerator jsl = KeyPairGenerator.getInstance(spec.getName(), JSL);
                if (strength < required)
                {
                    InvalidAlgorithmParameterException e = Assertions.assertThrows(
                            InvalidAlgorithmParameterException.class, () -> jsl.initialize(spec, rand));
                    Assertions.assertEquals("supplied SecureRandom reports " + strength + "-bit strength but "
                            + spec.getName() + " requires " + required, e.getMessage());
                }
                else
                {
                    jsl.initialize(spec, rand);
                    assertSigns(jsl.generateKeyPair(), JSL, spec.getName());
                }

                KeyPairGenerator bc = KeyPairGenerator.getInstance(spec.getName(), BC);
                bc.initialize(BC_SPECS[i], rand);
                assertSigns(bc.generateKeyPair(), BC, spec.getName());
            }

            // A source that reports no strength is accepted on both sides.
            SecureRandom unknown = SecureRandom.getInstance("SHA1PRNG");
            KeyPairGenerator jsl = KeyPairGenerator.getInstance(spec.getName(), JSL);
            jsl.initialize(spec, unknown);
            assertSigns(jsl.generateKeyPair(), JSL, spec.getName());
            KeyPairGenerator bc = KeyPairGenerator.getInstance(spec.getName(), BC);
            bc.initialize(BC_SPECS[i], unknown);
            assertSigns(bc.generateKeyPair(), BC, spec.getName());
        }
    }

    private static void assertSigns(KeyPair kp, String provider, String alg) throws Exception
    {
        byte[] msg = {1, 2, 3, 4};
        Signature signer = Signature.getInstance(alg, provider);
        signer.initSign(kp.getPrivate());
        signer.update(msg);
        byte[] sig = signer.sign();
        Signature verifier = Signature.getInstance(alg, provider);
        verifier.initVerify(kp.getPublic());
        verifier.update(msg);
        Assertions.assertTrue(verifier.verify(sig), provider + " " + alg);
    }
}
