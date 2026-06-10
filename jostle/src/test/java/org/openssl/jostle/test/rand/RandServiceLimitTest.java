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
        assertNullPointer("output is null", () -> randServiceNI.randomBytes(null, 1, DRBG_STRENGTH));
    }

    @Test
    public void randomBytesRejectsNegativeLength()
    {
        assertIllegalArgument("output len negative",
                () -> randServiceNI.randomBytes(new byte[1], -1, DRBG_STRENGTH));
    }

    @Test
    public void randomBytesRejectsMinimumNegativeLength()
    {
        assertIllegalArgument("output len negative",
                () -> randServiceNI.randomBytes(new byte[1], Integer.MIN_VALUE, DRBG_STRENGTH));
    }

    @Test
    public void randomBytesRejectsNegativeStrength()
    {
        assertIllegalArgument("insufficient random strength", () -> randServiceNI.randomBytes(new byte[1], 1, -1));
    }

    @Test
    public void randomBytesRejectsMinimumNegativeStrength()
    {
        assertIllegalArgument("insufficient random strength",
                () -> randServiceNI.randomBytes(new byte[1], 1, Integer.MIN_VALUE));
    }

    @Test
    public void randomBytesRejectsInsufficientStrength()
    {
        assertIllegalArgument("insufficient random strength",
                () -> randServiceNI.randomBytes(new byte[1], 1, Integer.MAX_VALUE));
    }

    @Test
    public void randomBytesRejectsInsufficientStrengthWithZeroLength()
    {
        assertIllegalArgument("insufficient random strength",
                () -> randServiceNI.randomBytes(new byte[0], 0, Integer.MAX_VALUE));
    }

    @Test
    public void instantiateRejectsNegativeStrength()
    {
        assertIllegalArgument("insufficient random strength", () -> randServiceNI.instantiate(-1, false));
    }

    @Test
    public void instantiateRejectsMinimumNegativeStrength()
    {
        assertIllegalArgument("insufficient random strength",
                () -> randServiceNI.instantiate(Integer.MIN_VALUE, false));
    }

    @Test
    public void instantiateRejectsInsufficientStrength()
    {
        assertIllegalArgument("insufficient random strength",
                () -> randServiceNI.instantiate(Integer.MAX_VALUE, false));
    }

    @Test
    public void instantiateAcceptsZeroStrength()
    {
        randServiceNI.instantiate(0, false);
    }

    @Test
    public void instantiateAcceptsAlgorithmStrength()
    {
        randServiceNI.instantiate(DRBG_STRENGTH, false);
    }

    @Test
    public void reseedRejectsNegativeStrength()
    {
        assertIllegalArgument("insufficient random strength", () -> randServiceNI.reseed(-1, false));
    }

    @Test
    public void reseedRejectsInsufficientStrength()
    {
        assertIllegalArgument("insufficient random strength", () -> randServiceNI.reseed(Integer.MAX_VALUE, false));
    }

    @Test
    public void reseedAcceptsAlgorithmStrength()
    {
        randServiceNI.reseed(DRBG_STRENGTH, false);
    }

    @Test
    public void randomBytesRejectsLengthPastOutput()
    {
        assertIllegalArgument("output offset + length is out of range",
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

    @Test
    public void contextRandomBytesRejectsUninitializedBeforeZeroLength()
    {
        assertIllegalState("not initialized",
                () -> randServiceNI.contextRandomBytes(0, new byte[0], 0, 0, false, null));
    }

    private static void assertIllegalArgument(String message, Runnable action)
    {
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class, action::run);
        Assertions.assertEquals(message, e.getMessage());
    }

    private static void assertIllegalState(String message, Runnable action)
    {
        IllegalStateException e = Assertions.assertThrows(IllegalStateException.class, action::run);
        Assertions.assertEquals(message, e.getMessage());
    }

    private static void assertNullPointer(String message, Runnable action)
    {
        NullPointerException e = Assertions.assertThrows(NullPointerException.class, action::run);
        Assertions.assertEquals(message, e.getMessage());
    }
}
