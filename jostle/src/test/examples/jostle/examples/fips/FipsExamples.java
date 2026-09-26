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
package jostle.examples.fips;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.security.Security;

/**
 * JSLFIPS backs its services with an externally supplied OpenSSL FIPS module, loaded and self-tested by
 * OpenSSL itself; until it is configured it registers nothing. These examples describe the 3.5.x module. The
 * configuration names the module file, here from an environment variable (`env:`; `file:`, `prop:` and
 * `str:` also work, and `fips_config` can name the fipsinstall configuration if it is not next to the module).
 * Initialisation is once per JVM, so reuse a registered JSLFIPS. JSL is registered too, for the examples that
 * move keys between the two. Each example skips when the loaded module does not serve what it uses.
 */
public abstract class FipsExamples
{
    /**
     * Register JSLFIPS, configured from `TEST_FIPS_LIB`, and JSL, once per JVM.
     */
    @BeforeAll
    public static void addProviders()
    {
        Assumptions.assumeTrue(System.getenv("TEST_FIPS_LIB") != null, "TEST_FIPS_LIB names no FIPS module");
        if (Security.getProvider("JSLFIPS") == null)
        {
            Security.addProvider(new JostleFIPSProvider("fips_module=env:TEST_FIPS_LIB"));
        }
        if (Security.getProvider("JSL") == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }
}
