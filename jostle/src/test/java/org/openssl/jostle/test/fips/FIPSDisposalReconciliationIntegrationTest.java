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
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.test.disposal.DisposalReconciliationIntegrationTest;

import java.security.Provider;
import java.security.Security;

/**
 * The JSLFIPS half of the disposal reconciliation.
 *
 * <p>Neither class substitutes for the other: they drive different native
 * libraries through different lib ctxs, and a handle allocated by one library
 * must be freed by that same library. The families JSLFIPS does not register
 * yield no driver, which is why its handle count is legitimately smaller.
 */
public class FIPSDisposalReconciliationIntegrationTest
        extends DisposalReconciliationIntegrationTest
{
    @BeforeAll
    public static void requireFipsModule()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        TestUtil.addFipsProvider();
    }

    @Override
    protected Provider provider()
    {
        return Security.getProvider(JostleFIPSProvider.PROVIDER_NAME);
    }

    /** Measured: 12 families on the 3.1.2 module, 14 on 3.5.8. */
    @Override
    protected int minimumFamiliesReached()
    {
        return 12;
    }
}
