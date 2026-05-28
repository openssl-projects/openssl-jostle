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

import java.security.SecureRandom;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.security.DrbgParameters;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

public class RandServiceParameterTest
{
    @BeforeAll
    public static void beforeAll()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    @Test
    public void drbgInstantiationParametersAreUnsupported()
    {
        Assertions.assertThrows(NoSuchAlgorithmException.class, () ->
                SecureRandom.getInstance("DRBG",
                        DrbgParameters.instantiation(128, DrbgParameters.Capability.PR_AND_RESEED, null),
                        JostleProvider.PROVIDER_NAME));
    }

    @Test
    public void nextBytesParametersAreUnsupported() throws Exception
    {
        SecureRandom random = SecureRandom.getInstance("DRBG", JostleProvider.PROVIDER_NAME);

        Assertions.assertThrows(UnsupportedOperationException.class, () ->
                random.nextBytes(new byte[16], DrbgParameters.nextBytes(128, false, null)));
    }

    @Test
    public void reseedParametersAreUnsupported() throws Exception
    {
        SecureRandom random = SecureRandom.getInstance("DRBG", JostleProvider.PROVIDER_NAME);

        Assertions.assertThrows(UnsupportedOperationException.class, () ->
                random.reseed(DrbgParameters.reseed(false, null)));
    }
}
