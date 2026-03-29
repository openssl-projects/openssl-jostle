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

import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.OpenSSL;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class OpenSSLIntegrationTest
{

    //@Test
    public void testModuleSelectionFailures_nullProviderName()
    {
        CryptoServicesRegistrar.assertNativeAvailable();
        try
        {
           //TODO add back OpenSSL.setOSSLProvider(null);
            Assertions.fail();
        } catch (Exception e)
        {
            Assertions.assertTrue(e instanceof IllegalArgumentException);
            Assertions.assertEquals("provider name is null", e.getMessage());
        }
    }

  // TODO @Test
    public void testModuleSelectionFailures_emptyProviderName()
    {
        CryptoServicesRegistrar.assertNativeAvailable();
        try
        {
         // TODO   OpenSSL.setOSSLProvider("");
            Assertions.fail();
        } catch (Exception e)
        {
            Assertions.assertTrue(e instanceof IllegalArgumentException);
            Assertions.assertEquals("provider name is empty", e.getMessage());
        }
    }

  // TODO  @Test
    public void testModuleSelectionFailures_invalidProviderName()
    {
        CryptoServicesRegistrar.assertNativeAvailable();
        try
        {
           // TODO OpenSSL.setOSSLProvider("!lkdsjf");
            Assertions.fail();
        } catch (Exception e)
        {
            Assertions.assertTrue(e instanceof OpenSSLException);
            Assertions.assertTrue(e.getMessage().contains(":name=!lkdsjf"));
        }
    }

  // TODO  @Test
    public void testGetOpenSSLError() throws Exception
    {
        //
        // Sanity tests that it can return null when no errors available.
        //
        CryptoServicesRegistrar.assertNativeAvailable();
        Assertions.assertNull(OpenSSL.getOpenSSLErrors());

    }

}
