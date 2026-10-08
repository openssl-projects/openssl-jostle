/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.rand;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.mlkem.MLKEMServiceNI;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.rand.DefaultRandSource;
import org.openssl.jostle.test.crypto.TestNISelector;

import java.security.DrbgParameters;
import java.security.SecureRandom;
import java.security.Security;

/**
 * A RandSource that refuses a draw for want of strength returns a code that reaches Java only as OpenSSL error
 * text. The refusal's own type must still reach the caller, as the cause of the operation's exception.
 *
 * <p>Driven at the NI: the JCA SPIs refuse a weak source before any draw.
 */
public class UpCallRefusalCauseTest
{
    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    @Test
    public void aStrengthRefusalIsTheCause() throws Exception
    {
        MLKEMServiceNI ni = TestNISelector.getMLKEMNI();
        DefaultRandSource weak = DefaultRandSource.wrap(SecureRandom.getInstance("DRBG",
                DrbgParameters.instantiation(128, DrbgParameters.Capability.RESEED_ONLY, null)));

        // ML-KEM-768 draws at 192 bits; the source is a 128-bit DRBG.
        OpenSSLException ex = Assertions.assertThrows(OpenSSLException.class,
                () -> ni.generateKeyPair(OSSLKeyType.ML_KEM_768.getKsType(), weak));

        Assertions.assertTrue(ex.getMessage().contains("rand up-call failed with code -97"), ex.getMessage());
        Throwable cause = ex.getCause();
        Assertions.assertNotNull(cause, "the refusal's type is lost: no cause");
        Assertions.assertEquals(IllegalArgumentException.class, cause.getClass());
        Assertions.assertEquals("insufficient random strength", cause.getMessage());
    }

    @Test
    public void aStrongEnoughSourceSucceedsAndLeavesNoCause() throws Exception
    {
        MLKEMServiceNI ni = TestNISelector.getMLKEMNI();
        DefaultRandSource strong = DefaultRandSource.wrap(SecureRandom.getInstance("DRBG",
                DrbgParameters.instantiation(256, DrbgParameters.Capability.RESEED_ONLY, null)));

        long ref = ni.generateKeyPair(OSSLKeyType.ML_KEM_768.getKsType(), strong);
        Assertions.assertTrue(ref != 0);
        TestNISelector.getSpecNI().dispose(ref);
    }
}
