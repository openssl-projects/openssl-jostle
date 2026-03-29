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

package org.openssl.jostle.test.md;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.md.MDServiceNI;
import org.openssl.jostle.test.crypto.TestNISelector;

import java.lang.foreign.Arena;
import java.lang.foreign.ValueLayout;
import java.security.Security;

public class MDInternalLimitTest
{
    @BeforeAll
    public static void beforeAll()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    MDServiceNI mdNI = TestNISelector.getMDNI();


    @Test
    public void testMDdigestLenZero() throws Exception
    {

        // Verifies a fully zeroed out state is detected as not initialized
        // if a call to getDigestOutputLen is made.


        try (var a = Arena.ofConfined())
        {

            var seg = a.allocate(1024);
            for (int i = 0; i < seg.byteSize(); i++)
            {
                seg.set(ValueLayout.JAVA_BYTE, (long) i, (byte) 0);
            }

            try
            {
                mdNI.getDigestOutputLen(seg.address());
                Assertions.fail("expected exception");
            }
            catch (IllegalStateException e)
            {
                Assertions.assertEquals("not initialized", e.getMessage());
            }


        }
        catch (Throwable t)
        {
            throw new RuntimeException("Error in MD digest operation", t);
        }

    }
}
