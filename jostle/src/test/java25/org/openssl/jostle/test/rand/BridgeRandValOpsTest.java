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
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.OpenSSL;
import org.openssl.jostle.jcajce.provider.mlkem.MLKEMServiceNI;
import org.openssl.jostle.rand.DefaultRandSource;
import org.openssl.jostle.rand.RandSource;
import org.openssl.jostle.test.crypto.TestNISelector;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.ops.OperationsTestNI;

import java.security.DrbgParameters;
import java.security.SecureRandom;
import java.security.SecureRandomParameters;
import java.security.Security;

import static java.security.DrbgParameters.Capability.PR_AND_RESEED;


public class BridgeRandValOpsTest
{

    OperationsTestNI operationsTestNI = TestNISelector.getOperationsTestNI();


    @BeforeAll
    public static void beforeAll()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }



    /**
     * Test strength is asserted.
     *
     * @throws Exception
     */
    @Test
    public void testStrengthAssertion_rngLess() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        SecureRandom secRand = SecureRandom.getInstance("DRBG",
                DrbgParameters.instantiation(128, PR_AND_RESEED, null));

        DefaultRandSource randSource = DefaultRandSource.wrap(secRand);
        byte[] random = new byte[128];
        int len = operationsTestNI.getRandDataViaOpenSSL(random, random.length, 129, false, randSource);

        Assertions.assertEquals(0, len); // FALSE from RAND_bytes_ex

        String err = OpenSSL.getOpenSSLErrors();

        Assertions.assertTrue(err.contains("-97")); // JO_RAND_INSUFFICIENT_STRENGTH
    }

    @Test
    public void testStrengthAssertion_rngExceedsRequired() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        SecureRandom secRand = SecureRandom.getInstance("DRBG",
                DrbgParameters.instantiation(128, PR_AND_RESEED, null));

        DefaultRandSource randSource = DefaultRandSource.wrap(secRand);
        byte[] random = new byte[128];
        int len = operationsTestNI.getRandDataViaOpenSSL(random, random.length, 127, false, randSource);

        Assertions.assertEquals(1, len); // SUCCESS

    }

    @Test
    public void testStrengthAssertion_rngSame() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        SecureRandom secRand = SecureRandom.getInstance("DRBG",
                DrbgParameters.instantiation(128, PR_AND_RESEED, null));

        DefaultRandSource randSource = DefaultRandSource.wrap(secRand);
        byte[] random = new byte[128];
        int len = operationsTestNI.getRandDataViaOpenSSL(random, random.length, 128, false, randSource);

        Assertions.assertEquals(1, len); // SUCCESS

    }


    @Test
    public void testReseedCalled() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        ReseedCountingSecureRandom random = new ReseedCountingSecureRandom(SecureRandom.getInstance("DRBG",
                DrbgParameters.instantiation(128, DrbgParameters.Capability.RESEED_ONLY, null)));

        DefaultRandSource randSource = DefaultRandSource.wrap(random);

        byte[] data = new byte[128];
        int rc = operationsTestNI.getRandDataViaOpenSSL(data, data.length, 128, true, randSource);

        Assertions.assertEquals(1, rc); // SUCCESS
        Assertions.assertEquals(1, random.reseedCounter); // reseed was called!


    }

    @Test
    public void testNoPredNoReseedFails() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        ReseedCountingSecureRandom random = new ReseedCountingSecureRandom(new SecureRandom());

        DefaultRandSource randSource = new TestRandRandSource(random, DrbgParameters.instantiation(128, DrbgParameters.Capability.NONE, null));

        byte[] data = new byte[128];
        int rc = operationsTestNI.getRandDataViaOpenSSL(data, data.length, 128, true, randSource);

        Assertions.assertEquals(0, rc); // Fail due to no reseed
        Assertions.assertEquals(0, random.reseedCounter); // reseed was called!

        String err = OpenSSL.getOpenSSLErrors();
        Assertions.assertTrue(err.contains("-100")); // JO_RAND_NO_RESEED
    }

    // Pass DRBGParams regardless of what's in the SecureRandom.
    public static class TestRandRandSource extends DefaultRandSource
    {
        public TestRandRandSource(SecureRandom secureRandom, SecureRandomParameters params)
        {
            super(secureRandom, params);
        }
    }


    //
    // Counts the number of times reseed is called.
    //
    public static class ReseedCountingSecureRandom extends SecureRandom
    {
        private SecureRandom random;
        public int reseedCounter = 0;

        public ReseedCountingSecureRandom(SecureRandom random)
        {
            this.random = random;
        }

        @Override
        public SecureRandomParameters getParameters()
        {
            return this.random.getParameters();
        }

        @Override
        public void reseed()
        {
            reseedCounter++;
            this.random.reseed();
        }

        @Override
        public void nextBytes(byte[] bytes)
        {
            random.nextBytes(bytes);
        }
    }





}
