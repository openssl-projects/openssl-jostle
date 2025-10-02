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
            Security.addProvider(new JostleProvider()); // Will trigger loading
        } catch (OpenSSLException t)
        {
            Assertions.assertTrue(t.getMessage().contains("name=dsdffds"));
        } finally
        {
            System.clearProperty(JostleProvider.OPENSSL_PROVIDER_NAME);
        }

    }


}
