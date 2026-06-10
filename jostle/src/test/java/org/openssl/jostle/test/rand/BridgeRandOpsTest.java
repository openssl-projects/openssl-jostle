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
import org.openssl.jostle.jcajce.provider.rand.RandServiceNI;
import org.openssl.jostle.rand.DefaultRandSource;
import org.openssl.jostle.test.crypto.TestNISelector;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.ops.OperationsTestNI;

import java.security.Security;


public class BridgeRandOpsTest
{
    private static final int JO_OPENSSL_ERROR = -2;
    private static final int JO_UNEXPECTED_STATE = -40;
    private static final int JO_RAND_RESEED = -100;

    //
    // The Java 8 version of this test.,
    // SecureRandom at Java level, does not have attributes, so strength assertion is not possible
    //


    OperationsTestNI operationsTestNI = TestNISelector.getOperationsTestNI();
    MLKEMServiceNI mldsaServiceNI = TestNISelector.getMLKEMNI();
    RandServiceNI randServiceNI = TestNISelector.getRandNI();

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
            // Exercises interface/jni/rand_upcall_jni.c:93
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_THREAD_ATTACH_1);
            mldsaServiceNI.generateKeyPair(17, DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom()));
            Assertions.fail();
        }
        catch (Exception t)
        {
            assertOpenSSLMessageContains(t, "handler fail, attach thread: -99");
        }
    }


    @Test
    public void testFailCreate() throws Exception
    {
        Assumptions.assumeTrue(!Loader.isFFI(), "JNI only");
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        try
        {
            // Exercises interface/jni/rand_upcall_jni.c:101
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_CREATE_1);
            mldsaServiceNI.generateKeyPair(17, DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom()));
            Assertions.fail();
        }
        catch (Exception t)
        {
            assertOpenSSLMessageContains(t, "handler fail, create bytearray: -99");
        }
    }

    @Test
    public void testOverflowOutLen() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        try
        {
            // Exercises interface/jni/rand_upcall_jni.c:67
            // Exercises interface/ffi/rand_upcall_ffi.c:35
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);
            mldsaServiceNI.generateKeyPair(17, DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom()));
            Assertions.fail();
        }
        catch (Exception t)
        {
            assertOpenSSLMessageContains(t, "out_len > INT_MAX");
        }
    }

    @Test
    public void testOverflowStrength() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        try
        {
            // Exercises interface/jni/rand_upcall_jni.c:72
            // Exercises interface/ffi/rand_upcall_ffi.c:40
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_2);
            mldsaServiceNI.generateKeyPair(17, DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom()));
            Assertions.fail();
        }
        catch (Exception t)
        {
            assertOpenSSLMessageContains(t, "strength > INT_MAX");
        }
    }


    @Test
    public void testFailShortSizeOpsTest() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        try
        {
            // Exercises interface/jni/rand_upcall_jni.c:132
            // Exercises interface/ffi/rand_upcall_ffi.c:50
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_SHORT_SIZE_1);
            mldsaServiceNI.generateKeyPair(17, DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom()));
            Assertions.fail();
        }
        catch (Exception t)
        {
            assertOpenSSLMessageContains(t, "handler fail, short output: -96");
        }
    }


    @Test
    public void testAccessByteArray() throws Exception
    {
        Assumptions.assumeTrue(!Loader.isFFI(), "JNI only");
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        try
        {
            // Exercises interface/jni/rand_upcall_jni.c:146
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_2);
            mldsaServiceNI.generateKeyPair(17, DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom()));
            Assertions.fail();
        }
        catch (Exception t)
        {
            assertOpenSSLMessageContains(t, "handler fail, access bytearray: -101");
        }
    }


    @Test
    public void testNoRandUpcall() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        try
        {
            // Exercises interface/jni/rand_upcall_jni.c:61
            // Exercises interface/ffi/rand_upcall_ffi.c:29
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_RAND_UP_CALL_NULL);
            mldsaServiceNI.generateKeyPair(17, DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom()));
            Assertions.fail();
        }
        catch (Exception t)
        {
            assertOpenSSLMessageContains(t, "handler fail, rand up call is null: -98");
        }
    }

    private static void assertOpenSSLMessageContains(Exception t, String message)
    {
        Assertions.assertEquals(OpenSSLException.class, t.getClass());
        Assertions.assertTrue(t.getMessage().startsWith("OpenSSL Error:"));
        Assertions.assertTrue(t.getMessage().contains(message));
    }

    @Test
    public void instantiateRandGetPrivateFails()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        // Exercises interface/util/rand.c:173
        operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
        int code = randServiceNI.ni_instantiate(0, false);

        Assertions.assertEquals(JO_OPENSSL_ERROR - 3000, code);
    }

    @Test
    public void instantiateEvpInstantiateFails()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        // Exercises interface/util/rand.c:181
        operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_INIT_1);
        // Exercises interface/util/rand.c:182
        operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
        int code = randServiceNI.ni_instantiate(0, false);

        Assertions.assertEquals(JO_OPENSSL_ERROR - 3001, code);
    }

    @Test
    public void instantiatePredictionResistantReseedFails()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        // Exercises interface/util/rand.c:191
        operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_INIT_2);
        // Exercises interface/util/rand.c:193
        operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);
        int code = randServiceNI.ni_instantiate(0, true);

        Assertions.assertEquals(JO_RAND_RESEED - 3002, code);
    }

    @Test
    public void instantiateUnexpectedStateFails()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        // Exercises interface/util/rand.c:178
        operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_SET_1);
        int code = randServiceNI.ni_instantiate(0, false);

        Assertions.assertEquals(JO_UNEXPECTED_STATE, code);
    }

    @Test
    public void reseedRandGetPrivateFails()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        // Exercises interface/util/rand.c:213
        operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
        int code = randServiceNI.ni_reseed(0, false);

        Assertions.assertEquals(JO_OPENSSL_ERROR - 3010, code);
    }

    @Test
    public void reseedEvpInstantiateFails()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        // Exercises interface/util/rand.c:221
        operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_INIT_1);
        // Exercises interface/util/rand.c:222
        operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_4);
        int code = randServiceNI.ni_reseed(0, false);

        Assertions.assertEquals(JO_OPENSSL_ERROR - 3011, code);
    }

    @Test
    public void reseedEvpReseedFails()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        // Exercises interface/util/rand.c:231
        operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_INIT_2);
        // Exercises interface/util/rand.c:232
        operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_5);
        int code = randServiceNI.ni_reseed(0, false);

        Assertions.assertEquals(JO_RAND_RESEED - 3012, code);
    }

    @Test
    public void reseedUnexpectedStateFails()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        // Exercises interface/util/rand.c:218
        operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_SET_1);
        int code = randServiceNI.ni_reseed(0, false);

        Assertions.assertEquals(JO_UNEXPECTED_STATE, code);
    }

    @Test
    public void parameterizedRandomBytesRandGetPrivateFails()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        // Exercises interface/util/rand.c:126
        operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_6);
        int code = randServiceNI.ni_randomBytes(new byte[1], 1, 0, false, new byte[1]);

        Assertions.assertEquals(JO_OPENSSL_ERROR - 3020, code);
    }

    @Test
    public void parameterizedRandomBytesInstantiateFails()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        // Exercises interface/util/rand.c:134
        operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_INIT_1);
        // Exercises interface/util/rand.c:135
        operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_7);
        int code = randServiceNI.ni_randomBytes(new byte[1], 1, 0, false, new byte[1]);

        Assertions.assertEquals(JO_OPENSSL_ERROR - 3021, code);
    }

    @Test
    public void parameterizedRandomBytesGenerateFails()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        // Exercises interface/util/rand.c:148
        operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_8);
        int code = randServiceNI.ni_randomBytes(new byte[1], 1, 0, false, new byte[1]);

        Assertions.assertEquals(JO_OPENSSL_ERROR - 3022, code);
    }

    @Test
    public void parameterizedRandomBytesUnexpectedStateFails()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        // Exercises interface/util/rand.c:131
        operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_SET_2);
        int code = randServiceNI.ni_randomBytes(new byte[1], 1, 0, false, new byte[1]);

        Assertions.assertEquals(JO_UNEXPECTED_STATE, code);
    }

}
