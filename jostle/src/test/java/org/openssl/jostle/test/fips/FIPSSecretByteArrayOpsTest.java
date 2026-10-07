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
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.test.marshalling.SecretByteArrayOpsTest;
import org.openssl.jostle.util.ops.OperationsTestNI;

/**
 * The same round trip through the FIPS interface library's copy of the secret contexts.
 */
public class FIPSSecretByteArrayOpsTest extends SecretByteArrayOpsTest
{
    @BeforeAll
    public static void requireFipsModule()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        TestUtil.addFipsProvider();
    }

    @Override
    protected OperationsTestNI ops()
    {
        return FIPSNISelector.OperationsTestNI;
    }

    @Override
    protected String library()
    {
        return "fips";
    }
}
