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
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.md.MDServiceNI;
import org.openssl.jostle.test.crypto.TestNISelector;

import java.lang.foreign.Arena;
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


    /** A zero-filled struct carries the kind a freed context is left with, so every entry refuses it. */
    @Test
    public void aZeroFilledHandleIsNotADigestContext()
    {
        int wrong = ErrorCode.JO_MD_CTX_WRONG_KIND.getCode();
        try (var a = Arena.ofConfined())
        {
            var seg = a.allocate(1024);
            seg.fill((byte) 0);
            long ref = seg.address();
            Assertions.assertEquals(wrong, mdNI.ni_getDigestOutputLen(ref), "getDigestOutputLen");
            Assertions.assertEquals(wrong, mdNI.ni_updateByte(ref, (byte) 1), "updateByte");
            Assertions.assertEquals(wrong, mdNI.ni_digest(ref, new byte[32], 0, 32), "digest");
            Assertions.assertEquals(wrong, mdNI.ni_reset(ref), "reset");
            IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> mdNI.getDigestOutputLen(ref));
            Assertions.assertEquals("handle is not a digest context", e.getMessage());
            mdNI.ni_dispose(ref);
        }
    }
}
