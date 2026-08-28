/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.provider;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.OpenSSLNI;
import org.openssl.jostle.test.crypto.TestNISelector;

import java.security.Security;

/**
 * Bridge input validation for {@code OpenSSLNI.canFetch}, driven at the NI
 * surface on whichever bridge the run selected.
 *
 * <p>Both bridges must return identical codes for identical inputs, and
 * neither may let a caller-supplied value reach the util {@code jo_assert}
 * — which would abort the JVM rather than return a code.
 */
public class BaseCapabilityGateLimitTest
{
    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    @Test
    public void canFetch_nullName_rejectedTyped()
    {
        Assertions.assertEquals(ErrorCode.JO_NAME_IS_NULL.getCode(),
                TestNISelector.getOpenSSLNI().canFetch(OpenSSLNI.OP_KEYMGMT, null));
    }

    @Test
    public void canFetch_opTypeBelowRange_rejectedTyped()
    {
        // JO_CAP_OP_MIN is 1, so 0 is the smallest rejected value.
        Assertions.assertEquals(ErrorCode.JO_UNEXPECTED_STATE.getCode(),
                TestNISelector.getOpenSSLNI().canFetch(0, "ML-KEM-768"));
    }

    @Test
    public void canFetch_opTypeAboveRange_rejectedTyped()
    {
        // JO_CAP_OP_MAX is OP_RAND, so OP_RAND + 1 is the smallest rejected
        // value above the range.
        Assertions.assertEquals(ErrorCode.JO_UNEXPECTED_STATE.getCode(),
                TestNISelector.getOpenSSLNI().canFetch(OpenSSLNI.OP_RAND + 1, "ML-KEM-768"));
    }

    @Test
    public void canFetch_negativeOpType_rejectedTyped()
    {
        Assertions.assertEquals(ErrorCode.JO_UNEXPECTED_STATE.getCode(),
                TestNISelector.getOpenSSLNI().canFetch(-1, "ML-KEM-768"));
        Assertions.assertEquals(ErrorCode.JO_UNEXPECTED_STATE.getCode(),
                TestNISelector.getOpenSSLNI().canFetch(Integer.MIN_VALUE, "ML-KEM-768"));
    }

    @Test
    public void canFetch_nameCheckedBeforeOpType()
    {
        // Only a BOTH-invalid input distinguishes the order, and the two
        // bridges must agree on it. Name first, matching the FIPS twin.
        Assertions.assertEquals(ErrorCode.JO_NAME_IS_NULL.getCode(),
                TestNISelector.getOpenSSLNI().canFetch(0, null));
    }

    @Test
    public void canFetch_boundaryOpTypesAreAccepted()
    {
        // The rejections above are only meaningful if the ends of the range
        // are NOT rejected. Both answer 0 or 1, never a negative code.
        Assertions.assertTrue(
                TestNISelector.getOpenSSLNI().canFetch(OpenSSLNI.OP_KEYMGMT, "RSA") >= 0);
        Assertions.assertTrue(
                TestNISelector.getOpenSSLNI().canFetch(OpenSSLNI.OP_RAND, "CTR-DRBG") >= 0);
    }
}
