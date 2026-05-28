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

package org.openssl.jostle.test.rand;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.rand.RandAlgorithm;
import org.openssl.jostle.jcajce.provider.rand.RandServiceNI;
import org.openssl.jostle.test.crypto.TestNISelector;

import java.security.Security;

public class RandServiceLimitTest
{
    private static final int DRBG_STRENGTH = RandAlgorithm.DRBG.getStrength();
    private final RandServiceNI randServiceNI = TestNISelector.getRandNI();

    @BeforeAll
    public static void beforeAll()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    @Test
    public void randomBytesRejectsNullOutput()
    {
        Assertions.assertThrows(NullPointerException.class, () -> randServiceNI.randomBytes(null, 1, DRBG_STRENGTH));
    }

    @Test
    public void randomBytesRejectsNegativeLength()
    {
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> randServiceNI.randomBytes(new byte[1], -1, DRBG_STRENGTH));
    }

    @Test
    public void randomBytesRejectsMinimumNegativeLength()
    {
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> randServiceNI.randomBytes(new byte[1], Integer.MIN_VALUE, DRBG_STRENGTH));
    }

    @Test
    public void randomBytesRejectsNegativeStrength()
    {
        Assertions.assertThrows(IllegalArgumentException.class, () -> randServiceNI.randomBytes(new byte[1], 1, -1));
    }

    @Test
    public void randomBytesRejectsMinimumNegativeStrength()
    {
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> randServiceNI.randomBytes(new byte[1], 1, Integer.MIN_VALUE));
    }

    @Test
    public void randomBytesRejectsLengthPastOutput()
    {
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> randServiceNI.randomBytes(new byte[8], 9, DRBG_STRENGTH));
    }

    @Test
    public void randomBytesAcceptsZeroLengthAtBoundary()
    {
        randServiceNI.randomBytes(new byte[0], 0, DRBG_STRENGTH);
    }

    @Test
    public void randomBytesAcceptsExactLength()
    {
        byte[] output = new byte[8];

        randServiceNI.randomBytes(output, output.length, DRBG_STRENGTH);
    }
}
