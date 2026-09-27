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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.jcajce.spec.MLDSAParameterSpec;
import org.openssl.jostle.jcajce.spec.MLKEMParameterSpec;
import org.openssl.jostle.test.provider.PQCUmbrellaKeyPairGeneratorLimitTest;

import java.security.Security;

/**
 * The JSLFIPS twin of {@link PQCUmbrellaKeyPairGeneratorLimitTest}: the same defaults through the module, for each
 * family the module implements. Whether JSLFIPS registers a family follows the module (3.1.2 implements none of
 * them), so each family's cells run only where it is registered, and the registration is checked against the
 * module on every module.
 */
public class FIPSPQCUmbrellaKeyPairGeneratorLimitTest
{
    private static final String FIPS = JostleFIPSProvider.PROVIDER_NAME;

    private static JostleFIPSProvider fips;

    @BeforeAll
    static void before()
    {
        fips = FIPSTestUtil.assumeFipsProvider();
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    public void genericGeneratorsRegisteredIffModuleImplementsTheFamily() throws Exception
    {
        assertRegisteredIffImplemented("ML-DSA", "ML-DSA-87");
        assertRegisteredIffImplemented("ML-KEM", "ML-KEM-768");
        assertRegisteredIffImplemented("SLH-DSA", "SLH-DSA-SHA2-128S");
    }

    @Test
    public void bareMlDsaGeneratorsGenerateMlDsa87() throws Exception
    {
        assumeRegistered("ML-DSA");
        PQCUmbrellaKeyPairGeneratorLimitTest.assertBareDefault(FIPS, "ML-DSA", "ML-DSA-87");
        PQCUmbrellaKeyPairGeneratorLimitTest.assertBareDefault(FIPS, "MLDSA", "ML-DSA-87");
    }

    @Test
    public void bareMlKemGeneratorsGenerateMlKem768() throws Exception
    {
        assumeRegistered("ML-KEM");
        PQCUmbrellaKeyPairGeneratorLimitTest.assertBareDefault(FIPS, "ML-KEM", "ML-KEM-768");
        PQCUmbrellaKeyPairGeneratorLimitTest.assertBareDefault(FIPS, "MLKEM", "ML-KEM-768");
    }

    @Test
    public void initializeStillSelectsTheParameterSet() throws Exception
    {
        if (fips.getService("KeyPairGenerator", "ML-DSA") != null)
        {
            PQCUmbrellaKeyPairGeneratorLimitTest.assertInitialized(FIPS, "ML-DSA", MLDSAParameterSpec.ml_dsa_44,
                    "ML-DSA-44");
        }
        assumeRegistered("ML-KEM");
        PQCUmbrellaKeyPairGeneratorLimitTest.assertInitialized(FIPS, "ML-KEM", MLKEMParameterSpec.ml_kem_512,
                "ML-KEM-512");
    }

    @Test
    public void bareSlhDsaGeneratorStillRefusesTyped() throws Exception
    {
        assumeRegistered("SLH-DSA");
        PQCUmbrellaKeyPairGeneratorLimitTest.assertSlhDsaRefuses(FIPS);
    }

    private static void assertRegisteredIffImplemented(String generic, String keyMgmt)
    {
        boolean implemented = FIPSTestUtil.moduleServesKeyMgmt(keyMgmt);
        Assertions.assertEquals(implemented, fips.getService("KeyPairGenerator", generic) != null,
                "JSLFIPS KeyPairGenerator." + generic + " registration disagrees with the loaded module");
    }

    private static void assumeRegistered(String generic)
    {
        Assumptions.assumeTrue(fips.getService("KeyPairGenerator", generic) != null,
                "the loaded FIPS module implements no " + generic);
    }
}
