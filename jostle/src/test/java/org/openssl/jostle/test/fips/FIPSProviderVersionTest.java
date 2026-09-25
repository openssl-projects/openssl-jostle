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

package org.openssl.jostle.test.fips;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.Version;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;

/**
 * JSLFIPS reports the version and info Version gives it.
 */
public class FIPSProviderVersionTest
{
    private static JostleFIPSProvider fips;

    @BeforeAll
    static void before()
    {
        fips = FIPSTestUtil.assumeFipsProvider();
    }

    @Test
    @SuppressWarnings("deprecation")
    public void jslFipsReportsVersionFromTheVersionClass()
    {
        Assertions.assertEquals(Version.getVersionDouble(), fips.getVersion(), 0.0);
        Assertions.assertEquals("Jostle FIPS Provider for OpenSSL " + Version.getVersionString(), fips.getInfo());
        Assertions.assertEquals(JostleFIPSProvider.INFO, fips.getInfo());
    }
}
