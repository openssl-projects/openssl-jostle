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

import java.security.SecureRandom;
import java.security.Security;


public class BridgeRandOpsTest
{
    //
    // The Java 8 version of this test.,
    // SecureRandom at Java level, does not have attributes, so strength assertion is not possible
    //


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
        Assumptions.assumeFalse(Loader.isFFI(), "JNI only");


        DefaultRandSource randSource = DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom());

        byte[] random = new byte[128];
        int len = operationsTestNI.getRandDataViaOpenSSL(random, random.length, 1, false, randSource);

        Assertions.assertEquals(1, len); // Success code not length
        boolean isAllZero = true;
        for (byte b : random)
        {
            isAllZero &= b == 0;
        }
        Assertions.assertFalse(isAllZero);
    }


    @Test
    public void testFailsIfRandFails() throws Exception
    {
        RandSource randSource = new FailingRandSource();

        //
        // Try and generate a key pair expect error code.
        //

        long result = mldsaServiceNI.generateKeyPair(17, randSource);

        Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode(), result);
        String err = OpenSSL.getOpenSSLErrors();

        Assertions.assertTrue(err.contains("-999")); // Insufficient strength

    }

    public class FailingRandSource implements RandSource
    {
        @Override
        public int getRandomBytes(byte[] out, int len, int strength, boolean predictionResistant)
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
