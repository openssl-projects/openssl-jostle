package org.openssl.jostle.test.digest;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.security.MessageDigest;
import java.security.Security;

/**
 * Java 25 specific tests that assert FFI is active and functional for
 * MessageDigest. These tests are compiled/used only on Java 25+ via the
 * multi-release test source set.
 */
public class MessageDigestFFITest
{
    @BeforeAll
    static void setup()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    @Test
    public void testFfiInterfaceActive()
            throws Exception
    {
        // Ensure native is initialized and interface resolved
        String iface = Loader.getInterfaceTypeName();
        Assertions.assertEquals("FFI", iface.toUpperCase(),
                "Expected FFI interface on Java 25");

        // Sanity: compute a digest to ensure the path is working
        MessageDigest md = MessageDigest.getInstance("SHA-256", JostleProvider.PROVIDER_NAME);
        byte[] out = md.digest("abc".getBytes("UTF-8"));
        Assertions.assertEquals(32, out.length);
    }
}
