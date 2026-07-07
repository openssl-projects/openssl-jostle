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
import org.openssl.jostle.test.TestUtil;

import java.io.File;

/**
 * Shared bootstrap for the env-gated FIPS tests. The single switch is the
 * {@code TEST_FIPS_LIB} environment variable (a full path to the FIPS module
 * library); everything here derives from it via {@link TestUtil}. All tests
 * construct the provider from the SAME resolved configuration, so the
 * one-shot native initialisation dedups across test classes sharing a JVM.
 */
final class FIPSTestUtil
{
    private FIPSTestUtil()
    {
    }

    /**
     * Skip the calling test unless a FIPS module is configured
     * ({@code TEST_FIPS_LIB}); otherwise ensure the JSLFIPS provider is
     * registered and return it.
     */
    static JostleFIPSProvider assumeFipsProvider()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        return TestUtil.addFipsProvider();
    }

    /**
     * The FIPS module library file named by {@code TEST_FIPS_LIB}. Only call
     * after {@link #assumeFipsProvider()} (or an equivalent skip guard) has
     * established the variable is set.
     */
    static File fipsModuleFile()
    {
        return new File(TestUtil.fipsLibPath());
    }

    /**
     * The directory containing the FIPS module (and, by convention, its
     * {@code fipsmodule.cnf}).
     */
    static String fipsModuleDir()
    {
        return fipsModuleFile().getParent();
    }
}
