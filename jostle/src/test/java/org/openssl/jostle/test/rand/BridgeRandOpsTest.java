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


import org.junit.jupiter.api.*;
import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.mlkem.MLKEMServiceNI;
import org.openssl.jostle.rand.DefaultRandSource;
import org.openssl.jostle.test.crypto.TestNISelector;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.ops.OperationsTestNI;

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

    @BeforeEach
    public void beforeEach()
    {
        if (operationsTestNI.opsTestAvailable())
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void doesNotExplodeOrReturnAllZeros() throws Exception
    {
        // Basically a sanity test.
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI(), "JNI only");


        DefaultRandSource randSource = DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom());

        byte[] random = new byte[128];
        int len = operationsTestNI.getRandDataViaOpenSSL(random, random.length, 1, false, randSource);

        Assertions.assertEquals(1, len); // Success code not length
        Assertions.assertFalse(Arrays.areAllZeroes(random, 0, random.length));
    }


    @Test
    public void testThreadAttach() throws Exception
    {
        Assumptions.assumeTrue(!Loader.isFFI(), "JNI only");
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_THREAD_ATTACH_1);
            mldsaServiceNI.generateKeyPair(17, DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom()));
            Assertions.fail();
        }
        catch (Exception t)
        {
            Assertions.assertTrue(t.getClass() == OpenSSLException.class);
            Assertions.assertTrue(t.getMessage().contains("handler fail, attach thread: -99"));
        }
    }


    @Test
    public void testFailCreate() throws Exception
    {
        Assumptions.assumeTrue(!Loader.isFFI(), "JNI only");
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_CREATE_1);
            mldsaServiceNI.generateKeyPair(17, DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom()));
            Assertions.fail();
        }
        catch (Exception t)
        {
            Assertions.assertTrue(t.getClass() == OpenSSLException.class);
            Assertions.assertTrue(t.getMessage().contains("handler fail, create bytearray: -99"));
        }
    }

    @Test
    public void testOverflowOutLen() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);
            mldsaServiceNI.generateKeyPair(17, DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom()));
            Assertions.fail();
        }
        catch (Exception t)
        {
            Assertions.assertTrue(t.getClass() == OpenSSLException.class);
            Assertions.assertTrue(t.getMessage().contains("out_len > INT_MAX"));
        }
    }

    @Test
    public void testOverflowStrength() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_2);
            mldsaServiceNI.generateKeyPair(17, DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom()));
            Assertions.fail();
        }
        catch (Exception t)
        {
            Assertions.assertTrue(t.getClass() == OpenSSLException.class);
            Assertions.assertTrue(t.getMessage().contains("strength > INT_MAX"));
        }
    }


    @Test
    public void testFailShortSizeOpsTest() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_SHORT_SIZE_1);
            mldsaServiceNI.generateKeyPair(17, DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom()));
            Assertions.fail();
        }
        catch (Exception t)
        {
            Assertions.assertTrue(t.getClass() == OpenSSLException.class);
            Assertions.assertTrue(t.getMessage().contains("handler fail, short output: -96"));
        }
    }


    @Test
    public void testAccessByteArray() throws Exception
    {
        Assumptions.assumeTrue(!Loader.isFFI(), "JNI only");
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_2);
            mldsaServiceNI.generateKeyPair(17, DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom()));
            Assertions.fail();
        }
        catch (Exception t)
        {
            Assertions.assertTrue(t.getClass() == OpenSSLException.class);
            Assertions.assertTrue(t.getMessage().contains("handler fail, access bytearray: -101"));
        }
    }


    @Test
    public void testNoRandUpcall() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_RAND_UP_CALL_NULL);
            mldsaServiceNI.generateKeyPair(17, DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom()));
            Assertions.fail();
        }
        catch (Throwable t)
        {
            Assertions.assertTrue(t.getClass() == OpenSSLException.class);
            Assertions.assertTrue(t.getMessage().contains("handler fail, rand up call is null: -98"));
        }
    }


}
