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
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.rand.RandServiceNI;
import org.openssl.jostle.test.crypto.TestNISelector;

import java.security.Security;
import java.util.function.LongConsumer;

public class RandServiceLimitTest
{
    // DRBG (= CTR-DRBG / AES-256) provides 256-bit strength. Kept as a literal
    // so this class-level constant does not trigger a native strength query at
    // static-init time, before the provider/native layer is initialised.
    private static final int DRBG_STRENGTH = 256;
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
    public void contextRandomBytesRejectsUninitializedBeforeZeroLength()
    {
        assertIllegalState("not initialized",
                () -> randServiceNI.contextRandomBytes(0, new byte[0], 0, 0, false, null));
    }

    @Test
    public void contextRandomBytesRejectsUninitializedWithLength()
    {
        assertIllegalState("not initialized",
                () -> randServiceNI.contextRandomBytes(0, new byte[1], 1, DRBG_STRENGTH, false, null));
    }

    @Test
    public void contextRandomBytesRejectsNullOutput()
    {
        withContext(ref -> assertNullPointer("output is null",
                () -> randServiceNI.contextRandomBytes(ref, null, 1, DRBG_STRENGTH, false, null)));
    }

    @Test
    public void contextRandomBytesRejectsNegativeLength()
    {
        withContext(ref -> assertIllegalArgument("output len negative",
                () -> randServiceNI.contextRandomBytes(ref, new byte[1], -1, DRBG_STRENGTH, false, null)));
    }

    @Test
    public void contextRandomBytesRejectsMinimumNegativeLength()
    {
        withContext(ref -> assertIllegalArgument("output len negative",
                () -> randServiceNI.contextRandomBytes(ref, new byte[1], Integer.MIN_VALUE, DRBG_STRENGTH, false, null)));
    }

    @Test
    public void contextRandomBytesRejectsNegativeStrength()
    {
        withContext(ref -> assertIllegalArgument("insufficient random strength",
                () -> randServiceNI.contextRandomBytes(ref, new byte[1], 1, -1, false, null)));
    }

    @Test
    public void contextRandomBytesRejectsMinimumNegativeStrength()
    {
        withContext(ref -> assertIllegalArgument("insufficient random strength",
                () -> randServiceNI.contextRandomBytes(ref, new byte[1], 1, Integer.MIN_VALUE, false, null)));
    }

    @Test
    public void contextRandomBytesRejectsInsufficientStrength()
    {
        withContext(ref -> assertIllegalArgument("insufficient random strength",
                () -> randServiceNI.contextRandomBytes(ref, new byte[1], 1, Integer.MAX_VALUE, false, null)));
    }

    @Test
    public void contextRandomBytesRejectsInsufficientStrengthWithZeroLength()
    {
        withContext(ref -> assertIllegalArgument("insufficient random strength",
                () -> randServiceNI.contextRandomBytes(ref, new byte[0], 0, Integer.MAX_VALUE, false, null)));
    }

    @Test
    public void contextRandomBytesRejectsLengthPastOutput()
    {
        withContext(ref -> assertIllegalArgument("output offset + length is out of range",
                () -> randServiceNI.contextRandomBytes(ref, new byte[8], 9, DRBG_STRENGTH, false, null)));
    }

    @Test
    public void contextRandomBytesAcceptsZeroLengthAtBoundary()
    {
        withContext(ref -> randServiceNI.contextRandomBytes(ref, new byte[0], 0, DRBG_STRENGTH, false, null));
    }

    @Test
    public void contextRandomBytesAcceptsExactLength()
    {
        withContext(ref -> randServiceNI.contextRandomBytes(ref, new byte[8], 8, DRBG_STRENGTH, false, null));
    }

    @Test
    public void contextReseedRejectsUninitialized()
    {
        assertIllegalState("not initialized",
                () -> randServiceNI.contextReseed(0, DRBG_STRENGTH, false, null));
    }

    @Test
    public void contextReseedRejectsNegativeStrength()
    {
        withContext(ref -> assertIllegalArgument("insufficient random strength",
                () -> randServiceNI.contextReseed(ref, -1, false, null)));
    }

    @Test
    public void contextReseedRejectsMinimumNegativeStrength()
    {
        withContext(ref -> assertIllegalArgument("insufficient random strength",
                () -> randServiceNI.contextReseed(ref, Integer.MIN_VALUE, false, null)));
    }

    @Test
    public void contextReseedRejectsInsufficientStrength()
    {
        withContext(ref -> assertIllegalArgument("insufficient random strength",
                () -> randServiceNI.contextReseed(ref, Integer.MAX_VALUE, false, null)));
    }

    @Test
    public void contextReseedAcceptsAlgorithmStrength()
    {
        withContext(ref -> randServiceNI.contextReseed(ref, DRBG_STRENGTH, false, null));
    }

    @Test
    public void createContextRejectsNullMechanism()
    {
        assertNullPointer("name is null",
                () -> randServiceNI.createContext(null, "AES-256-CTR", true, DRBG_STRENGTH, false, null));
    }

    @Test
    public void createContextRejectsNullVariant()
    {
        assertNullPointer("name is null",
                () -> randServiceNI.createContext("CTR-DRBG", null, true, DRBG_STRENGTH, false, null));
    }

    @Test
    public void createContextRejectsUnknownMechanism()
    {
        assertOpenSSLError(
                () -> randServiceNI.createContext("BOGUS-DRBG", "AES-256-CTR", true, DRBG_STRENGTH, false, null));
    }

    @Test
    public void createContextRejectsUnknownVariant()
    {
        assertOpenSSLError(
                () -> randServiceNI.createContext("CTR-DRBG", "AES-999-CTR", true, DRBG_STRENGTH, false, null));
    }

    @Test
    public void createContextRejectsStrengthAboveVariantCeiling()
    {
        // AES-128-CTR caps at 128-bit strength; OpenSSL rejects an over-strength
        // instantiation at the NI surface (the precise gate when the Java-side
        // strength cap is bypassed).
        assertOpenSSLError(
                () -> randServiceNI.createContext("CTR-DRBG", "AES-128-CTR", true, 256, false, null));
    }

    private static void assertOpenSSLError(Runnable action)
    {
        OpenSSLException e = Assertions.assertThrows(OpenSSLException.class, action::run);
        Assertions.assertTrue(e.getMessage().startsWith("OpenSSL Error:"), e.getMessage());
    }

    private void withContext(LongConsumer action)
    {
        long ref = randServiceNI.createContext("CTR-DRBG", "AES-256-CTR", true, DRBG_STRENGTH, false, null);
        try
        {
            action.accept(ref);
        }
        finally
        {
            randServiceNI.disposeContext(ref);
        }
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
