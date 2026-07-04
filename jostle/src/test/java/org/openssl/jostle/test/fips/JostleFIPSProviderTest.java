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
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;

import java.io.File;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.Security;

/**
 * Lifecycle test of JostleFIPSProvider ("JSLFIPS"): configuration parsing and
 * path derivation, the one real FIPS module initialisation for this JVM,
 * JCA registration, coexistence with the non-FIPS JostleProvider, and the
 * one-shot semantics. Gated on the JOSTLE_TEST_FIPS_DIR environment variable
 * (the directory containing the FIPS module + fipsmodule.cnf); skipped when
 * unset.
 *
 * <p>This test owns the JVM's single successful FIPS initialisation (the
 * native init is one-shot per JVM); OpenSSLFIPSNITest covers only paths that
 * never consume it, so the two classes may share a JVM in either order.
 */
public class JostleFIPSProviderTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    private static File findFipsModule(String fipsDir)
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

    @Test
    public void fipsProviderLifecycle()
        throws Exception
    {
        String fipsDir = System.getenv("JOSTLE_TEST_FIPS_DIR");
        Assumptions.assumeTrue(fipsDir != null && !fipsDir.isEmpty(),
                "JOSTLE_TEST_FIPS_DIR not set (directory containing the FIPS module + fipsmodule.cnf)");
        File module = findFipsModule(fipsDir);
        Assumptions.assumeTrue(module != null, "no fips module found under " + fipsDir);

        // --- configuration errors (no native state consumed) ---------------

        // Malformed config string rejected by the parser.
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> new JostleFIPSProvider("fips_module='unterminated"));

        // Missing the required fips_module key.
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> new JostleFIPSProvider("fips_config=/somewhere/fipsmodule.cnf"));

        // Module path with no parent directory.
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> new JostleFIPSProvider("fips_module=fips.dylib"));

        // A module that does not exist fails the native init (config load or
        // provider activation) and rolls back - the one-shot is not consumed.
        ProviderException pe = Assertions.assertThrows(ProviderException.class,
                () -> new JostleFIPSProvider("fips_module=" + new File("/does/not/exist", module.getName())));
        Assertions.assertNotNull(pe.getMessage());

        // No-arg construction with no org.openssl.jostle.fips.config property
        // stays unconfigured (and registers no services).
        JostleFIPSProvider unconfigured = new JostleFIPSProvider();
        Assertions.assertFalse(unconfigured.isConfigured());

        // --- the real initialisation ---------------------------------------

        // file:// scheme for the module path; fips_config omitted so the
        // default (fipsmodule.cnf beside the module) is used. This is the
        // JVM's one successful FIPS module init: libcrypto dlopens the
        // module, verifies its integrity MAC and runs the self-tests.
        String config = "fips_module='" + module.toURI() + "'";
        JostleFIPSProvider provider = (JostleFIPSProvider) unconfigured.configure(config);
        Assertions.assertTrue(provider.isConfigured());
        Assertions.assertEquals(JostleFIPSProvider.PROVIDER_NAME, provider.getName());

        if (Security.getProvider(JostleFIPSProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(provider);
        }
        Provider registered = Security.getProvider(JostleFIPSProvider.PROVIDER_NAME);
        Assertions.assertNotNull(registered);
        Assertions.assertEquals("JSLFIPS", registered.getName());

        // --- coexistence -----------------------------------------------------

        // The non-FIPS provider works in the same JVM, on its own interface
        // library and lib ctx.
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        byte[] message = new byte[64];
        RANDOM.nextBytes(message);
        byte[] digest = MessageDigest.getInstance("SHA-256", JostleProvider.PROVIDER_NAME)
                .digest(message);
        Assertions.assertEquals(32, digest.length);

        // --- one-shot semantics ---------------------------------------------

        // Identical configuration again: dedup'd, no exception.
        JostleFIPSProvider again = new JostleFIPSProvider(config);
        Assertions.assertTrue(again.isConfigured());

        // A different configuration is rejected.
        Assertions.assertThrows(IllegalStateException.class,
                () -> new JostleFIPSProvider(config + ", fips_config='" + fipsDir
                        + File.separator + "some-other.cnf'"));

        // The raw NI double-init is rejected by the native one-shot guard.
        int rc = FIPSNISelector.OpenSSLFIPSNI.setOSSLFIPSModule(
                fipsDir, "fips", fipsDir + File.separator + "fipsmodule.cnf");
        Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode(), rc);
        String errors = FIPSNISelector.OpenSSLFIPSNI.getOSSLErrors();
        Assertions.assertTrue(errors != null && errors.contains("set_global_jostle_lib_ctx already called"),
                "expected one-shot guard message, got: " + errors);
    }
}
