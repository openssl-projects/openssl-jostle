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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.provider.fips.OpenSSLFIPSNI;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.util.ops.OperationsTestNI;

/**
 * Operations-test fault injection at the FIPS module-init surface
 * ({@code jostle_fips_configure_libctx} in
 * interface/fips/util/rand/jostle_fips_ctx.c). This is the one OPS surface UNIQUE to
 * the FIPS interface library — the base library never calls this code — so
 * unlike the crypto-family FIPS *OpsTests (which re-test C already covered by
 * the base *OpsTests), these sites have no base-test counterpart.
 *
 * <p>Each site's real failure (bad config, missing module, integrity/self-test
 * failure, ...) is impossible to stage reliably from a valid deployment, so
 * each is fault-injected with one {@code OPS_OPENSSL_ERROR_*} flag and asserted
 * to return its distinct {@code JO_FIPS_*} code. The six sites are the config
 * load (NCONF + module activation), fips/base provider availability, the
 * fips=yes default-property pin, and the post-init health-probe fetch.
 *
 * <p>Like {@link OpenSSLFIPSNITest}, this drives the raw
 * {@link OpenSSLFIPSNI#setOSSLFIPSModule} and does NO successful initialisation:
 * every call here fails inside {@code jostle_ctx_init_fips} and rolls back
 * (freeing the fresh lib ctx), so it never consumes the one-shot global init
 * that {@code JostleFIPSProviderTest} owns — the classes are order-independent
 * in a shared JVM. It deliberately does not call {@code addFipsProvider()}.
 *
 * <p>Requires a JOSTLE_OPS_TEST build of the FIPS library: gated on
 * {@code TEST_FIPS_LIB} and per-test on {@code opsTestAvailable()}.
 */
public class FIPSInitOpsTest
{
    @BeforeAll
    public static void beforeAll()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
    }

    private final OpenSSLFIPSNI fipsNI = FIPSNISelector.OpenSSLFIPSNI;
    private final OperationsTestNI operationsTestNI = FIPSNISelector.OperationsTestNI;

    // Forward slashes: this test drives setOSSLFIPSModule directly, bypassing
    // FIPSOpenSSL's path normalisation. OpenSSL's config .include parser treats
    // '\' as an escape, so a Windows backslash config path is mangled and the
    // load fails before the OPS-injected site is reached (returning the config-
    // load code instead of the site's code). '/' is accepted on every platform;
    // a no-op on POSIX.
    private final String fipsDir = FIPSTestUtil.fipsModuleDir().replace('\\', '/');
    private final String cnf = fipsDir + "/fipsmodule.cnf";

    @BeforeEach
    public void beforeEach()
    {
        if (operationsTestNI.opsTestAvailable())
        {
            operationsTestNI.resetFlags();
        }
    }

    /** Arm one flag, run a would-be-successful init, expect it to roll back with {@code expected}. */
    private void assertInitFailsWith(ErrorCode expected, OperationsTestNI.OpsTestFlag flag)
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        try
        {
            operationsTestNI.setFlag(flag);
            int code = fipsNI.setOSSLFIPSModule(fipsDir, "fips", cnf);
            Assertions.assertEquals(expected.getCode(), code);
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void configLoad_nconf_failure()
    {
        // Exercises interface/fips/util/rand/jostle_fips_ctx.c:77
        assertInitFailsWith(ErrorCode.JO_FIPS_CONFIG_LOAD_FAILED,
                OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
    }

    @Test
    public void configLoad_modulesLoad_failure()
    {
        // Exercises interface/fips/util/rand/jostle_fips_ctx.c:81
        assertInitFailsWith(ErrorCode.JO_FIPS_CONFIG_LOAD_FAILED,
                OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
    }

    @Test
    public void fipsProviderUnavailable_failure()
    {
        // Exercises interface/fips/util/rand/jostle_fips_ctx.c:86
        assertInitFailsWith(ErrorCode.JO_FIPS_PROVIDER_UNAVAILABLE,
                OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);
    }

    @Test
    public void baseProviderUnavailable_failure()
    {
        // Exercises interface/fips/util/rand/jostle_fips_ctx.c:90
        assertInitFailsWith(ErrorCode.JO_FIPS_BASE_UNAVAILABLE,
                OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_4);
    }

    @Test
    public void enableFips_failure()
    {
        // Exercises interface/fips/util/rand/jostle_fips_ctx.c:100
        assertInitFailsWith(ErrorCode.JO_FIPS_ENABLE_FAILED,
                OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_5);
    }

    @Test
    public void fetchProbe_failure()
    {
        // Exercises interface/fips/util/rand/jostle_fips_ctx.c:108
        assertInitFailsWith(ErrorCode.JO_FIPS_FETCH_PROBE_FAILED,
                OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_6);
    }
}
