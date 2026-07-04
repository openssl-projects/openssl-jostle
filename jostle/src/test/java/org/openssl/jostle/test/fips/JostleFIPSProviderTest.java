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
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;

import java.io.File;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;

/**
 * Lifecycle test of JostleFIPSProvider ("JSLFIPS"): configuration parsing and
 * path derivation, the FIPS module initialisation, JCA registration,
 * coexistence with the non-FIPS JostleProvider, and the one-shot semantics.
 * Gated on the JOSTLE_TEST_FIPS_DIR environment variable (the directory
 * containing the FIPS module + fipsmodule.cnf); skipped when unset.
 *
 * <p>All env-gated FIPS tests share the one-shot native initialisation
 * through {@link FIPSTestUtil#assumeFipsProvider()} (identical resolved
 * configuration, so the native init dedups whichever test class runs first).
 * This test therefore initialises FIRST and probes the post-init guarantees;
 * native failure paths that require an UNinitialised state are covered
 * order-independently at the NI surface by OpenSSLFIPSNITest.
 */
public class JostleFIPSProviderTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    @Test
    public void fipsProviderLifecycle()
        throws Exception
    {
        // The good initialisation (dedup'd if another FIPS test got there
        // first) - also skips the test when no FIPS install is configured.
        JostleFIPSProvider provider = FIPSTestUtil.assumeFipsProvider();
        String fipsDir = System.getenv("JOSTLE_TEST_FIPS_DIR");
        File module = FIPSTestUtil.findFipsModule(fipsDir);

        Assertions.assertTrue(provider.isConfigured());
        Assertions.assertEquals(JostleFIPSProvider.PROVIDER_NAME, provider.getName());

        Provider registered = Security.getProvider(JostleFIPSProvider.PROVIDER_NAME);
        Assertions.assertNotNull(registered);
        Assertions.assertEquals("JSLFIPS", registered.getName());

        // --- configuration errors (rejected before any native call) --------

        // Malformed config string rejected by the parser.
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> new JostleFIPSProvider("fips_module='unterminated"));

        // Missing the required fips_module key.
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> new JostleFIPSProvider("fips_config=/somewhere/fipsmodule.cnf"));

        // Module path with no parent directory.
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> new JostleFIPSProvider("fips_module=fips.dylib"));

        // No-arg construction with no org.openssl.jostle.fips.config property
        // stays unconfigured (and registers no services).
        JostleFIPSProvider unconfigured = new JostleFIPSProvider();
        Assertions.assertFalse(unconfigured.isConfigured());
        Assertions.assertNull(unconfigured.getService("MessageDigest", "SHA-256"));

        // --- one-shot semantics ---------------------------------------------

        // Identical configuration again: dedup'd, no exception - including
        // through the file:// scheme (same resolved module path) and through
        // Provider.configure.
        JostleFIPSProvider again = new JostleFIPSProvider("fips_module='" + module.getAbsolutePath() + "'");
        Assertions.assertTrue(again.isConfigured());
        JostleFIPSProvider viaUri = (JostleFIPSProvider) unconfigured.configure(
                "fips_module='" + module.toURI() + "'");
        Assertions.assertTrue(viaUri.isConfigured());

        // Any DIFFERENT resolved configuration is rejected: a different
        // module location and a different config file both differ from the
        // initialised triple.
        Assertions.assertThrows(IllegalStateException.class,
                () -> new JostleFIPSProvider("fips_module=" + new File("/does/not/exist", module.getName())));
        Assertions.assertThrows(IllegalStateException.class,
                () -> new JostleFIPSProvider("fips_module='" + module.getAbsolutePath()
                        + "', fips_config='" + fipsDir + File.separator + "some-other.cnf'"));

        // The raw NI double-init is rejected by the native one-shot guard.
        int rc = FIPSNISelector.OpenSSLFIPSNI.setOSSLFIPSModule(
                fipsDir, "fips", fipsDir + File.separator + "fipsmodule.cnf");
        Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode(), rc);
        String errors = FIPSNISelector.OpenSSLFIPSNI.getOSSLErrors();
        Assertions.assertTrue(errors != null && errors.contains("set_global_jostle_lib_ctx already called"),
                "expected one-shot guard message, got: " + errors);

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
    }
}
