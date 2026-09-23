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

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.test.cache.NativeFactCacheBindingTest;

import java.security.Provider;
import java.security.Security;
import java.util.Map;

/**
 * The binding that matters: a fresh base-library NI and a fresh FIPS-library NI
 * each probe the same fact, and the FIPS probe must reach the module rather than
 * read the base library's answer. A family the loaded module does not serve is
 * reported as such, after asserting the module really does not serve it.
 */
public class FIPSNativeFactCacheBindingTest extends NativeFactCacheBindingTest
{
    @BeforeAll
    public static void requireFipsModule()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        TestUtil.addFipsProvider();
    }

    @Override
    protected Provider secondProvider()
    {
        return Security.getProvider(JostleFIPSProvider.PROVIDER_NAME);
    }

    @Override
    protected Map<String, String[]> secondClasses()
    {
        return FIPS;
    }

    @Override
    protected String pairing()
    {
        return "base-vs-fips";
    }
}
