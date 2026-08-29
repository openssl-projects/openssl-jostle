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

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.test.util.ServiceClassNameAudit;

import java.security.Provider;

/**
 * Every service JSLFIPS registers reports the class it actually constructs.
 *
 * <p>Base twin: {@code ServiceClassNameParityTest}. Both are needed — this one
 * drives the FIPS interface library and the FIPS lib ctx, and its registered
 * set is gated by what the loaded module can serve.
 */
public class FIPSServiceClassNameParityTest
{
    /**
     * Below the 187 registered against a 3.1.2 module, with room for a module
     * that serves fewer. Separate from the base floor on purpose: a single
     * shared threshold either passes vacuously here or fails spuriously there.
     */
    private static final int FLOOR = 140;

    @BeforeAll
    public static void gate()
    {
        FIPSTestUtil.assumeFipsProvider();
    }

    @Test
    public void everyRegisteredClassNameNamesItsOwnClass()
    {
        Provider provider = FIPSTestUtil.assumeFipsProvider();
        ServiceClassNameAudit.assertEveryClassNameNamesItsOwnClass(provider, FLOOR);
    }
}
