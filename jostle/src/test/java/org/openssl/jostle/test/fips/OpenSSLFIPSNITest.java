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
import org.junit.jupiter.api.Test;
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.provider.fips.OpenSSLFIPSNI;

import java.io.File;

/**
 * NI-surface test of the FIPS interface library loading and the
 * setOSSLFIPSModule argument-validation / rolled-back failure paths. Gated
 * on the JOSTLE_TEST_FIPS_DIR environment variable, which must point at the
 * directory containing the FIPS provider module (fips.dylib / fips.so /
 * fips.dll) and its fipsinstall-generated fipsmodule.cnf - e.g. an OpenSSL
 * 3.1.2 enable-fips build's providers/ directory. Skipped when unset.
 *
 * <p>Deliberately NO successful initialisation here: the native init is
 * one-shot per JVM and {@code JostleFIPSProviderTest} owns it (both classes
 * may share a test JVM in either order). Every path exercised below either
 * rejects at the bridge before touching native state, or fails inside
 * jostle_ctx_init_fips and rolls back - so this test is order-independent.
 */
public class OpenSSLFIPSNITest
{
    @Test
    public void fipsValidationAndRolledBackFailures()
    {
        String fipsDir = System.getenv("JOSTLE_TEST_FIPS_DIR");
        Assumptions.assumeTrue(fipsDir != null && !fipsDir.isEmpty(),
                "JOSTLE_TEST_FIPS_DIR not set (directory containing the FIPS module + fipsmodule.cnf)");

        // First touch of FIPSNISelector lazily extracts/loads the FIPS
        // interface library.
        OpenSSLFIPSNI fipsNI = FIPSNISelector.OpenSSLFIPSNI;
        Assertions.assertTrue(Loader.isFipsLoadAttempted());
        Assertions.assertTrue(Loader.isFipsLoadSuccessful(),
                "FIPS interface library load failed: " + Loader.getFipsMessage());
        Assertions.assertNotNull(Loader.getFipsInterfaceLibPath());

        String cnf = fipsDir + File.separator + "fipsmodule.cnf";

        // Argument validation is rejected at the bridge, before any native
        // state changes.
        Assertions.assertEquals(ErrorCode.JO_FIPS_MODULE_PATH_INVALID.getCode(),
                fipsNI.setOSSLFIPSModule(null, "fips", cnf));
        Assertions.assertEquals(ErrorCode.JO_FIPS_MODULE_PATH_INVALID.getCode(),
                fipsNI.setOSSLFIPSModule("", "fips", cnf));
        Assertions.assertEquals(ErrorCode.JO_PROV_NAME_NULL.getCode(),
                fipsNI.setOSSLFIPSModule(fipsDir, null, cnf));
        Assertions.assertEquals(ErrorCode.JO_PROV_NAME_EMPTY.getCode(),
                fipsNI.setOSSLFIPSModule(fipsDir, "", cnf));
        Assertions.assertEquals(ErrorCode.JO_FIPS_CONFIG_PATH_INVALID.getCode(),
                fipsNI.setOSSLFIPSModule(fipsDir, "fips", null));
        Assertions.assertEquals(ErrorCode.JO_FIPS_CONFIG_PATH_INVALID.getCode(),
                fipsNI.setOSSLFIPSModule(fipsDir, "fips", ""));

        // A missing config fails cleanly, rolled back - does not consume the
        // one-shot global.
        Assertions.assertEquals(ErrorCode.JO_FIPS_CONFIG_LOAD_FAILED.getCode(),
                fipsNI.setOSSLFIPSModule(fipsDir, "fips", cnf + ".does-not-exist"));

        // A wrong provider name fails the activation (module not found by
        // that name on the search path), also rolled back.
        Assertions.assertEquals(ErrorCode.JO_FIPS_PROVIDER_UNAVAILABLE.getCode(),
                fipsNI.setOSSLFIPSModule(fipsDir, "nosuchprovider", cnf));
    }
}
