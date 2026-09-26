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
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.test.spec.KemSharedSecretLengths;

/**
 * The JSLFIPS twin of {@code KemSharedSecretLengthTest}: the module's encapsulation-side shared-secret length
 * query agrees with its decapsulation query and a real encapsulation, for every KEM the module serves.
 */
public class FIPSKemSharedSecretLengthTest
{
    private static JostleFIPSProvider fips;

    @BeforeAll
    static void before()
    {
        fips = FIPSTestUtil.assumeFipsProvider();
    }

    @Test
    public void theEncapQueryAgreesWithDecapAndARealEncapsulation() throws Exception
    {
        Assumptions.assumeTrue(FIPSTestUtil.moduleServesKeyMgmt("ML-KEM-768"),
                "the loaded FIPS module implements no ML-KEM (3.1.2)");
        String table = KemSharedSecretLengths.check(fips, KemSharedSecretLengths.ALL, TestUtil.RNDSrc);
        System.out.println("[kem-secret-length] JSLFIPS\n  " + table);
    }
}
