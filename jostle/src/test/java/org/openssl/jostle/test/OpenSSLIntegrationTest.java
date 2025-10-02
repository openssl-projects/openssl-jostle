package org.openssl.jostle.test;

import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.OpenSSL;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class OpenSSLIntegrationTest
{

    @Test
    public void testModuleSelectionFailures_nullProviderName()
    {
        CryptoServicesRegistrar.assertNativeAvailable();
        try
        {
            OpenSSL.setOSSLProvider(null);
        } catch (Exception e)
        {
            Assertions.assertTrue(e instanceof IllegalArgumentException);
            Assertions.assertEquals("provider name is null", e.getMessage());
        }
    }

    @Test
    public void testModuleSelectionFailures_emptyProviderName()
    {
        CryptoServicesRegistrar.assertNativeAvailable();
        try
        {
            OpenSSL.setOSSLProvider("");
        } catch (Exception e)
        {
            Assertions.assertTrue(e instanceof IllegalArgumentException);
            Assertions.assertEquals("provider name is empty", e.getMessage());
        }
    }

    @Test
    public void testModuleSelectionFailures_invalidProviderName()
    {
        CryptoServicesRegistrar.assertNativeAvailable();
        try
        {
            OpenSSL.setOSSLProvider("!lkdsjf");
        } catch (Exception e)
        {
            Assertions.assertTrue(e instanceof OpenSSLException);
            Assertions.assertTrue(e.getMessage().contains(":name=!lkdsjf"));
        }
    }

    @Test
    public void testGetOpenSSLError() throws Exception
    {
        //
        // Sanity tests that it can return null when no errors available.
        //
        CryptoServicesRegistrar.assertNativeAvailable();
        Assertions.assertNull(OpenSSL.getOpenSSLErrors());

    }

}
