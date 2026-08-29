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

package org.openssl.jostle.test.provider;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.test.util.ServiceClassNameAudit;

import java.security.Security;

/**
 * Every service JSL registers reports the class it actually constructs.
 *
 * <p>The FIPS twin is {@code FIPSServiceClassNameParityTest} — it drives a
 * different provider over a different native library, so neither substitutes
 * for the other.
 */
public class ServiceClassNameParityTest
{
    /**
     * Floor is well below the 334 registered when this was written, so an
     * added algorithm does not fail it, while a provider that registered
     * almost nothing cannot pass vacuously.
     */
    private static final int FLOOR = 300;

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    @Test
    public void everyRegisteredClassNameNamesItsOwnClass()
    {
        ServiceClassNameAudit.assertEveryClassNameNamesItsOwnClass(
                Security.getProvider(JostleProvider.PROVIDER_NAME), FLOOR);
    }
}
