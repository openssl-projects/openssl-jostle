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

package org.openssl.jostle.test.provider;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.security.Provider;
import java.security.Security;
import java.util.Set;

public class ServiceTest
{
    @Test
    public void testBasicServiceIteration() throws Exception
    {
        //
        // For Regression reported https://github.com/openssl-projects/openssl-jostle/pull/28
        //

        final JostleProvider provider = new JostleProvider();
        Security.addProvider(provider);

        Set<Provider.Service> serviceSet = Security.getProvider(JostleProvider.PROVIDER_NAME).getServices();
        serviceSet.forEach(service -> {
            Assertions.assertEquals(service.getProvider(), provider);
        });

    }
}
