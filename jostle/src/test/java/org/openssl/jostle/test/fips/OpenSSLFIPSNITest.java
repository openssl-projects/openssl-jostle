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
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.provider.fips.OpenSSLFIPSNI;

import java.io.File;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;

/**
 * End-to-end test of the FIPS interface library loading and the FIPS module
 * initialisation lifecycle. Requires an external FIPS OpenSSL install:
 * gated on the JOSTLE_TEST_FIPS_DIR environment variable, which must point
 * at the directory containing the FIPS provider module (fips.dylib /
 * fips.so / fips.dll) and its fipsinstall-generated fipsmodule.cnf - e.g.
 * an OpenSSL 3.1.2 enable-fips build's providers/ directory. Skipped when
 * unset.
 *
 * <p>The whole lifecycle lives in one test method because the native init is
 * one-shot per JVM: argument-validation rejections (which must not touch
 * native state) run first, then the real init, then the double-init
 * rejection.
 */
public class OpenSSLFIPSNITest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    @Test
    public void fipsModuleLoadLifecycle()
        throws Exception
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
        // state changes - safe to probe ahead of the real init.
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

        // A missing config fails cleanly (rolled back - does not consume the
        // one-shot global).
        Assertions.assertEquals(ErrorCode.JO_FIPS_CONFIG_LOAD_FAILED.getCode(),
                fipsNI.setOSSLFIPSModule(fipsDir, "fips", cnf + ".does-not-exist"));

        // A wrong provider name fails the activation (module not found by
        // that name on the search path), also rolled back.
        Assertions.assertEquals(ErrorCode.JO_FIPS_PROVIDER_UNAVAILABLE.getCode(),
                fipsNI.setOSSLFIPSModule(fipsDir, "nosuchprovider", cnf));

        // The real init: libcrypto dlopens the module, verifies its
        // integrity MAC and runs the self-tests.
        Assertions.assertEquals(ErrorCode.JO_SUCCESS.getCode(),
                fipsNI.setOSSLFIPSModule(fipsDir, "fips", cnf),
                "FIPS module init failed: " + fipsNI.getOSSLErrors());

        // Coexistence: the non-FIPS provider works in the same JVM, on its
        // own interface library and lib ctx.
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        byte[] message = new byte[64];
        RANDOM.nextBytes(message);
        byte[] digest = MessageDigest.getInstance("SHA-256", JostleProvider.PROVIDER_NAME)
                .digest(message);
        Assertions.assertEquals(32, digest.length);

        // The init is one-shot per JVM: a second attempt is rejected and the
        // error queue names the guard.
        Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode(),
                fipsNI.setOSSLFIPSModule(fipsDir, "fips", cnf));
        String errors = fipsNI.getOSSLErrors();
        Assertions.assertTrue(errors != null && errors.contains("set_global_jostle_lib_ctx already called"),
                "expected one-shot guard message, got: " + errors);
    }
}
