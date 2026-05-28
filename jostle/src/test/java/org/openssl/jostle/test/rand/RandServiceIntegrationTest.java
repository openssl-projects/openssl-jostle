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

import java.security.Provider;
import java.security.Security;

public class RandServiceIntegrationTest
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
    public void noAlgorithmConstructorUsesJostleWhenJostleIsFirst()
    {
        Provider provider = Security.getProvider(JostleProvider.PROVIDER_NAME);
        int previousPosition = providerPosition(JostleProvider.PROVIDER_NAME);

        Security.removeProvider(JostleProvider.PROVIDER_NAME);
        Security.insertProviderAt(provider, 1);
        try
        {
            SecureRandom random = new SecureRandom();

            Assertions.assertEquals(JostleProvider.PROVIDER_NAME, random.getProvider().getName());
            Assertions.assertEquals("DRBG", random.getAlgorithm());
        }
        finally
        {
            Security.removeProvider(JostleProvider.PROVIDER_NAME);
            Security.insertProviderAt(provider, previousPosition);
        }
    }

    @Test
    public void repeatedProviderConstructionIsAccepted()
    {
        new JostleProvider();
    }

    private static int providerPosition(String name)
    {
        Provider[] providers = Security.getProviders();
        for (int i = 0; i < providers.length; i++)
        {
            if (providers[i].getName().equals(name))
            {
                return i + 1;
            }
        }

        return -1;
    }
}
