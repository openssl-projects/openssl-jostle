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
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.test.examples.ExamplesCoverage;

import java.util.Set;
import java.util.TreeSet;

/**
 * Every primary, non-OID service name JSLFIPS registers is exercised by at least one worked example; the rule
 * is {@link ExamplesCoverage}.
 * <p>
 * Runs only where the loaded module serves the 3.5.x surface, signalled by ML-KEM being registered: the guide
 * describes that module, and a module without it registers a different set.
 */
public class FIPSExamplesCoverageTest
{
    private static JostleFIPSProvider fips;

    /**
     * JSLFIPS service types whose examples have not landed yet; same rules as the JSL list in
     * {@code ExamplesCoverageTest}.
     */
    private static final Set<String> FIPS_PENDING = new TreeSet<String>();

    @BeforeAll
    static void before()
    {
        fips = FIPSTestUtil.assumeFipsProvider();
    }

    @Test
    public void everyJslFipsServiceHasAnExample()
            throws Exception
    {
        Assumptions.assumeTrue(fips.getService("KeyPairGenerator", "ML-KEM-768") != null,
                "the loaded module does not register ML-KEM-768, "
                        + "so it is not the 3.5.x module the guide describes");
        ExamplesCoverage.check("fips", fips, FIPS_PENDING);
    }
}
