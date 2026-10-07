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
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.provider.fips.OpenSSLFIPSNI;

/**
 * Bridge input validation for {@code OpenSSLFIPSNI.canFetch} and {@code implementingProvider}, driven at the NI
 * surface on whichever bridge the run selected. The FIPS twin of BaseCapabilityGateLimitTest: neither may let a
 * caller-supplied value reach the util {@code jo_assert}.
 */
public class FIPSCapabilityGateLimitTest
{
    @BeforeAll
    static void before()
    {
        FIPSTestUtil.assumeFipsProvider();
    }

    private static OpenSSLFIPSNI ni()
    {
        return FIPSNISelector.OpenSSLFIPSNI;
    }

    @Test
    public void canFetch_nullName_rejectedTyped()
    {
        Assertions.assertEquals(ErrorCode.JO_NAME_IS_NULL.getCode(), ni().canFetch(OpenSSLFIPSNI.OP_MD, null));
    }

    @Test
    public void canFetch_opTypeBelowRange_rejectedTyped()
    {
        Assertions.assertEquals(ErrorCode.JO_UNEXPECTED_STATE.getCode(), ni().canFetch(0, "SHA2-256"));
    }

    @Test
    public void canFetch_opTypeAboveRange_rejectedTyped()
    {
        Assertions.assertEquals(ErrorCode.JO_UNEXPECTED_STATE.getCode(),
                ni().canFetch(OpenSSLFIPSNI.OP_RAND + 1, "SHA2-256"));
    }

    @Test
    public void canFetch_negativeOpType_rejectedTyped()
    {
        Assertions.assertEquals(ErrorCode.JO_UNEXPECTED_STATE.getCode(), ni().canFetch(-1, "SHA2-256"));
        Assertions.assertEquals(ErrorCode.JO_UNEXPECTED_STATE.getCode(),
                ni().canFetch(Integer.MIN_VALUE, "SHA2-256"));
    }

    @Test
    public void canFetch_nameCheckedBeforeOpType()
    {
        Assertions.assertEquals(ErrorCode.JO_NAME_IS_NULL.getCode(), ni().canFetch(0, null));
    }

    @Test
    public void canFetch_boundaryOpTypesAreAccepted()
    {
        // The module serves both, so the ends of the range answer 1, not merely a non-negative code.
        Assertions.assertEquals(1, ni().canFetch(OpenSSLFIPSNI.OP_KEYMGMT, "RSA"));
        Assertions.assertEquals(1, ni().canFetch(OpenSSLFIPSNI.OP_RAND, "CTR-DRBG"));
    }

    @Test
    public void implementingProvider_unusableArgumentsAnswerNull()
    {
        Assertions.assertNull(ni().implementingProvider(OpenSSLFIPSNI.OP_MD, null));
        Assertions.assertNull(ni().implementingProvider(0, "SHA2-256"));
        Assertions.assertNull(ni().implementingProvider(OpenSSLFIPSNI.OP_RAND + 1, "SHA2-256"));
        Assertions.assertNull(ni().implementingProvider(Integer.MIN_VALUE, "SHA2-256"));
    }

    @Test
    public void implementingProvider_boundaryOpTypesAnswer()
    {
        // A refused-everything implementation would pass the null cells; these show the same calls can answer.
        Assertions.assertNotNull(ni().implementingProvider(OpenSSLFIPSNI.OP_KEYMGMT, "RSA"));
        Assertions.assertNotNull(ni().implementingProvider(OpenSSLFIPSNI.OP_RAND, "CTR-DRBG"));
    }
}
