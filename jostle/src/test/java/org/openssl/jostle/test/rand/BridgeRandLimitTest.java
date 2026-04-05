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
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.mlkem.MLKEMServiceNI;
import org.openssl.jostle.rand.RandSource;
import org.openssl.jostle.test.crypto.TestNISelector;

import java.security.SecureRandom;
import java.security.Security;

public class BridgeRandLimitTest
{

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
    public void testFailShortSizeWithBrokenRndSource() throws Exception
    {
        try
        {

            mldsaServiceNI.generateKeyPair(17, new ShortRandSource());
            Assertions.fail();
        }
        catch (Exception t)
        {
            Assertions.assertTrue(t.getClass() == OpenSSLException.class);
            Assertions.assertTrue(t.getMessage().contains("handler fail, short output: -95"));
        }
    }

    @Test
    public void testFailsIfRandFails() throws Exception
    {

        RandSource randSource = new FailingRandSource();

        //
        // Try and generate a key pair expect error code.
        //
        try
        {
            mldsaServiceNI.generateKeyPair(17, randSource);
            Assertions.fail();
        }
        catch (OpenSSLException e)
        {
            Assertions.assertTrue(e.getMessage().contains("-999"));
        }


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

    public class ShortRandSource implements RandSource
    {
        SecureRandom random = new SecureRandom();

        @Override
        public int getRandomBytes(byte[] out, int len, int strength, boolean predictionResistant)
        {
            random.nextBytes(out);
            return len - 1;
        }

        @Override
        public SecureRandom getRandom()
        {
            return null;
        }
    }
}
