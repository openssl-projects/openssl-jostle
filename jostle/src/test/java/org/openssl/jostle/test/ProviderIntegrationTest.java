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

package org.openssl.jostle.test;

import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.Security;

public class ProviderIntegrationTest
{
    /**
     * This checks that loading fails and that the OPENSSL_PROVIDER_NAME is respected when detected.
     */
    @Test
    public void testNonDefaultOSSLProvider_notFound() throws Exception
    {
        System.setProperty(JostleProvider.OPENSSL_PROVIDER_NAME, "dsdffds");
        try
        {
            Security.addProvider(new JostleProvider());
            Assertions.fail("Should have thrown an exception");
        } catch (OpenSSLException t)
        {
            Assertions.assertTrue(t.getMessage().contains("name=dsdffds"));
        } finally
        {
            System.clearProperty(JostleProvider.OPENSSL_PROVIDER_NAME);
        }

    }


}
