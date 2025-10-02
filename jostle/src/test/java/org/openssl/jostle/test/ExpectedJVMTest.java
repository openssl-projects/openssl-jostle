package org.openssl.jostle.test;

import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.Loader;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class ExpectedJVMTest
{
    @Test
    public void testExpectedJVMVersion()
    {
        String version = System.getProperty("java.version");
        String expectedPrefix = System.getProperty("test.java.version.prefix", "!");

        if ("!".equals(expectedPrefix))
        {
            System.out.println("Skipping JVM version assertion");
            return;
        }

        if ("any".equals(expectedPrefix))
        {
            return;
        }

        Assertions.assertTrue(version.startsWith(expectedPrefix));
    }

    @Test
    public void testExpectedInterface()
    {
        // Trigger Loading
        CryptoServicesRegistrar.isNativeAvailable();

        String interfaceName = Loader.getInterfaceTypeName();
        String expectedType = System.getProperty("test.java.interface_type", "!");

        System.out.println("Expected: " + expectedType + " got " + interfaceName);

        if ("!".equals(expectedType))
        {
            System.out.println("Skipping loader interface assertion");
            return;
        }

        if ("any".equals(expectedType))
        {
            return;
        }

        Assertions.assertTrue(interfaceName.equalsIgnoreCase(expectedType));

    }

}
