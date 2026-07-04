/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.fips;

import org.junit.jupiter.api.Assumptions;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;

import java.io.File;
import java.security.Security;

/**
 * Shared bootstrap for the env-gated FIPS tests. All tests construct the
 * provider from the SAME resolved configuration (module from
 * JOSTLE_TEST_FIPS_DIR, default fipsmodule.cnf beside it), so the one-shot
 * native initialisation dedups across test classes sharing a JVM.
 */
final class FIPSTestUtil
{
    private FIPSTestUtil()
    {
    }

    static File findFipsModule(String fipsDir)
    {
        String[] names = {"fips.dylib", "fips.so", "fips.dll"};
        for (String name : names)
        {
            File candidate = new File(fipsDir, name);
            if (candidate.isFile())
            {
                return candidate;
            }
        }
        return null;
    }

    /**
     * Skip the calling test unless a FIPS install is configured; otherwise
     * ensure the JSLFIPS provider is initialised and registered, and return
     * it.
     */
    static synchronized JostleFIPSProvider assumeFipsProvider()
    {
        String fipsDir = System.getenv("JOSTLE_TEST_FIPS_DIR");
        Assumptions.assumeTrue(fipsDir != null && !fipsDir.isEmpty(),
                "JOSTLE_TEST_FIPS_DIR not set (directory containing the FIPS module + fipsmodule.cnf)");
        File module = findFipsModule(fipsDir);
        Assumptions.assumeTrue(module != null, "no fips module found under " + fipsDir);

        JostleFIPSProvider registered =
                (JostleFIPSProvider) Security.getProvider(JostleFIPSProvider.PROVIDER_NAME);
        if (registered != null)
        {
            return registered;
        }

        JostleFIPSProvider provider = new JostleFIPSProvider("fips_module='" + module.getAbsolutePath() + "'");
        Security.addProvider(provider);
        return provider;
    }
}
