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

package org.openssl.jostle.test.rand;


import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.OpenSSL;
import org.openssl.jostle.jcajce.provider.mlkem.MLKEMServiceNI;
import org.openssl.jostle.rand.DefaultRandSource;
import org.openssl.jostle.rand.RandSource;
import org.openssl.jostle.test.crypto.TestNISelector;
import org.openssl.jostle.util.ops.OperationsTestNI;

import java.security.DrbgParameters;
import java.security.SecureRandom;
import java.security.Security;

import static java.security.DrbgParameters.Capability.PR_AND_RESEED;


public class BridgeRandValOpsTest
{

    OperationsTestNI operationsTestNI = TestNISelector.getOperationsTestNI();
    MLKEMServiceNI mldsaServiceNI = TestNISelector.getMLKEMNI();

    @BeforeAll
    public static void beforeAll()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    @Test
    public void doesNotExplodeOrReturnAllZeros() throws Exception
    {
        // Oh boy!
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        DefaultRandSource randSource = DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom());

        byte[] random = new byte[128];
        int rc = operationsTestNI.getEntropy(random, random.length, 1, false, randSource);

        Assertions.assertEquals(1, rc);
        boolean isAllZero = true;
        for (byte b : random)
        {
            isAllZero &= b == 0;
        }
        Assertions.assertFalse(isAllZero);
    }

    @Test
    public void testStrengthAssertion() throws Exception
    {
        SecureRandom secRand = SecureRandom.getInstance("DRBG",
                DrbgParameters.instantiation(128, PR_AND_RESEED, null));

        DefaultRandSource randSource = DefaultRandSource.wrap(secRand);
        byte[] random = new byte[128];
        int len = operationsTestNI.getEntropy(random, random.length, 129, false, randSource);

        Assertions.assertEquals(0, len); // FALSE from RAND_bytes_ex


        String err = OpenSSL.getOpenSSLErrors();

        Assertions.assertTrue(err.contains("-97")); // Insufficient strength

    }


    @Test
    public void testFailsIfRandFails() throws Exception
    {
        SecureRandom secRand = SecureRandom.getInstance("DRBG",
                DrbgParameters.instantiation(128, PR_AND_RESEED, null));

        RandSource randSource = new FailingRandSource();

        //
        // Try and generate a key pair expect error code.
        //

        long result = mldsaServiceNI.generateKeyPair(17, randSource);

        Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode(), result);
        String err = OpenSSL.getOpenSSLErrors();

        Assertions.assertTrue(err.contains("-999")); // Insufficient strength

    }

    public OperationsTestNI getOperationsTestNI()
    {
        return operationsTestNI;
    }

    public class FailingRandSource implements RandSource
    {
        @Override
        public int getEntropy(byte[] out, int len, int strength, boolean predictionResistant)
        {
            return -999;
        }

        @Override
        public SecureRandom getRandom()
        {
            return null;
        }
    }


}
