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
import org.openssl.jostle.jcajce.spec.MLDSAParameterSpec;
import org.openssl.jostle.test.TestUtil;

import java.security.DrbgParameters;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Signature;

/**
 * JSLFIPS accepts a SecureRandom of every strength for every ML-DSA parameter set, because the module draws its own
 * entropy and never reads the caller's source; the keys it generates sign. 3.1.2 has no ML-DSA at all.
 */
public class FIPSMLDSARandStrengthTest
{
    private static final MLDSAParameterSpec[] SPECS = {
            MLDSAParameterSpec.ml_dsa_44, MLDSAParameterSpec.ml_dsa_65, MLDSAParameterSpec.ml_dsa_87};

    @BeforeAll
    public static void beforeAll()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        TestUtil.addFipsProvider();
    }

    @Test
    public void everySourceStrengthIsAcceptedAndTheModuleSigns() throws Exception
    {
        FipsModuleProfile profile = FipsModuleProfile.get();
        Provider fips = FIPSTestUtil.assumeFipsProvider();
        if (profile.isVersion312())
        {
            Assertions.assertNull(fips.getService("KeyPairGenerator", "ML-DSA-65"));
            return;
        }
        Assertions.assertEquals(FipsModuleProfile.MODULE_3_5_8, profile.version());
        for (MLDSAParameterSpec spec : SPECS)
        {
            for (int strength : new int[]{128, 192, 256})
            {
                SecureRandom rand = SecureRandom.getInstance("DRBG",
                        DrbgParameters.instantiation(strength, DrbgParameters.Capability.NONE, null));
                KeyPairGenerator kpg = KeyPairGenerator.getInstance(spec.getName(), fips);
                kpg.initialize(spec, rand);
                KeyPair kp = kpg.generateKeyPair();
                byte[] msg = {5, 6, 7};
                Signature signer = Signature.getInstance(spec.getName(), fips);
                signer.initSign(kp.getPrivate());
                signer.update(msg);
                byte[] sig = signer.sign();
                Signature verifier = Signature.getInstance(spec.getName(), fips);
                verifier.initVerify(kp.getPublic());
                verifier.update(msg);
                Assertions.assertTrue(verifier.verify(sig), spec.getName() + " with a " + strength + "-bit source");
            }
        }
    }
}
