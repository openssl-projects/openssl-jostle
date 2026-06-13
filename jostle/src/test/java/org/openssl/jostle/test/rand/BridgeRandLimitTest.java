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
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.OpenSSL;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.mlkem.MLKEMServiceNI;
import org.openssl.jostle.rand.DefaultRandSource;
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
            assertOpenSSLMessageContains(t, "handler fail, short output: -96");
        }
    }

    @Test
    public void testFailLongSizeWithBrokenRndSource() throws Exception
    {
        // Up-call returns rc > out_len: caught by the defensive overlong
        // guard in both bridges. JNI rejects before memcpy; FFI rejects
        // after the buffer was already overwritten.
        try
        {
            mldsaServiceNI.generateKeyPair(17, new LongRandSource());
            Assertions.fail();
        }
        catch (Exception t)
        {
            assertOpenSSLMessageContains(t, "rand up call returned");
            Assertions.assertTrue(t.getMessage().contains("> requested"));
        }
    }

    @Test
    public void testJavaUpCallThrows() throws Exception
    {
        // RandSource that throws — JNI-only: FFI's upcallStub kills the JVM
        // on a leaked exception, so this path doesn't apply there.
        Assumptions.assumeFalse(Loader.isFFI(), "JNI only");
        try
        {
            mldsaServiceNI.generateKeyPair(17, new ThrowingRandSource());
            Assertions.fail();
        }
        catch (Exception t)
        {
            assertOpenSSLMessageContains(t, "rand up call threw an exception");
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
            assertOpenSSLMessageContains(e, "-999");
        }


    }

    @Test
    public void testDefaultRandSourceCatchesThrowable() throws Exception
    {
        // SecureRandom whose nextBytes throws: DefaultRandSource catches and
        // returns JO_RAND_ERROR (-99). Validates the catch-Throwable path
        // that swallows arbitrary failures from the underlying SecureRandom.
        DefaultRandSource randSource = DefaultRandSource.wrap(new ThrowingSecureRandom());
        try
        {
            mldsaServiceNI.generateKeyPair(17, randSource);
            Assertions.fail();
        }
        catch (OpenSSLException e)
        {
            assertOpenSSLMessageContains(e, "-99");
        }
    }

    private static void assertOpenSSLMessageContains(Exception t, String message)
    {
        Assertions.assertEquals(OpenSSLException.class, t.getClass());
        Assertions.assertTrue(t.getMessage().startsWith("OpenSSL Error:"));
        Assertions.assertTrue(t.getMessage().contains(message));
    }

    @Test
    public void testNullProvName() throws Exception
    {
        // Bypass the OpenSSL.setOSSLProvider Java guards — those would throw
        // before reaching the C side. We want to exercise the C-side null
        // check directly. Doesn't mutate global state.
        int rc = TestNISelector.getOpenSSLNI().setOSSLProviderModule(null);
        Assertions.assertEquals(ErrorCode.JO_PROV_NAME_NULL.getCode(), rc);
    }

    @Test
    public void testEmptyProvName() throws Exception
    {
        // Same approach: exercise the C-side empty-name guard.
        int rc = TestNISelector.getOpenSSLNI().setOSSLProviderModule("");
        Assertions.assertEquals(ErrorCode.JO_PROV_NAME_EMPTY.getCode(), rc);
    }

    @Test
    public void testInvalidProviderName() throws Exception
    {
        // Provider is already initialised by JostleProvider's @BeforeAll.
        // Native RAND state is process-wide and bound to the first provider
        // name, so a different name is rejected by the run-once guard before
        // OpenSSL attempts to load it.
        int rc = TestNISelector.getOpenSSLNI().setOSSLProviderModule("this-provider-does-not-exist");
        Assertions.assertEquals(ErrorCode.JO_UNEXPECTED_STATE.getCode(), rc);
    }

    @Test
    public void testSecondCallRejection() throws Exception
    {
        // Provider is already initialised by JostleProvider's @BeforeAll.
        // A second call with the same name gets past RAND and reaches
        // set_global_jostle_lib_ctx, which raises an OpenSSL provider init error
        // while rejecting repeated initialisation.
        int rc = TestNISelector.getOpenSSLNI().setOSSLProviderModule("default");
        Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode(), rc);

        String err = OpenSSL.getOpenSSLErrors();
        Assertions.assertTrue(err.contains("set_global_jostle_lib_ctx already called"));
    }


    public static class FailingRandSource implements RandSource
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

        @Override
        public int getStrength()
        {
            return 0;
        }
    }

    public static class ShortRandSource implements RandSource
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

        @Override
        public int getStrength()
        {
            return 0;
        }
    }

    public static class LongRandSource implements RandSource
    {
        SecureRandom random = new SecureRandom();

        @Override
        public int getRandomBytes(byte[] out, int len, int strength, boolean predictionResistant)
        {
            random.nextBytes(out);
            return len + 1;  // claim more bytes than the buffer holds
        }

        @Override
        public SecureRandom getRandom()
        {
            return null;
        }

        @Override
        public int getStrength()
        {
            return 0;
        }
    }

    public static class ThrowingRandSource implements RandSource
    {
        @Override
        public int getRandomBytes(byte[] out, int len, int strength, boolean predictionResistant)
        {
            throw new RuntimeException("intentional throw for test");
        }

        @Override
        public SecureRandom getRandom()
        {
            return null;
        }

        @Override
        public int getStrength()
        {
            return 0;
        }
    }

    public static class ThrowingSecureRandom extends SecureRandom
    {
        @Override
        public void nextBytes(byte[] bytes)
        {
            throw new RuntimeException("intentional throw from SecureRandom");
        }
    }
}
