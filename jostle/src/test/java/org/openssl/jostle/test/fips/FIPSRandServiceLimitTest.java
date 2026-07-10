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
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.rand.RandServiceNI;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.test.TestUtil;

import java.util.function.LongConsumer;

/**
 * Input-validation limit tests at the FIPS RAND NI surface
 * ({@link FIPSNISelector#RandServiceNI}). The FIPS JNI glue is the base
 * rand_ni_jni.c re-included under renamed symbols, so the bridge's
 * null/range/strength checks and typed-error mapping are identical by
 * construction — this pins that they survived into the FIPS interface library
 * with the same JO_* codes and messages.
 *
 * <p>Runs under the {@code integrationTest*} tasks; gated on
 * {@code TEST_FIPS_LIB} (whole class skips when unset).
 *
 * <p>Unlike Mac (where Poly1305 is unavailable under FIPS), every DRBG
 * mechanism the base test exercises is FIPS-approved — CTR-DRBG (AES-128/256),
 * HASH-DRBG (SHA1, SHA2-256) and HMAC-DRBG all fetch and report the same
 * strengths under the FIPS lib ctx (verified by probe). So the validation
 * surface here is a direct mirror of the base {@code RandServiceLimitTest}.
 *
 * <p>{@code contextRandomBytes} has no output-offset parameter and reads no
 * user-supplied input buffer, so there is no offset-write or aliased-buffer
 * surface to exercise (contrast the block-cipher / MAC limit tests).
 *
 * <p>Discipline (testing.md): exact-message assertions, strength/length fed
 * {@code -1} AND {@code Integer.MIN_VALUE}, and the strength ceiling probed at
 * exactly {@code boundary + 1} (257 above the 256 cap) with accepted-boundary
 * companions.
 */
public class FIPSRandServiceLimitTest
{
    // DRBG (= CTR-DRBG / AES-256) provides 256-bit strength. Kept as a literal
    // so this class-level constant does not trigger a native strength query at
    // static-init time, before the provider/native layer is initialised.
    private static final int DRBG_STRENGTH = 256;

    @BeforeAll
    public static void beforeAll()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        TestUtil.addFipsProvider();
    }

    private final RandServiceNI randServiceNI = FIPSNISelector.RandServiceNI;

    // ---------------------------------------------------------------------
    // contextRandomBytes: state / null / negative / range / strength.
    // ---------------------------------------------------------------------

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
        // 257 = boundary+1: the strength ceiling is 256 (JO_RAND_MAX_STRENGTH),
        // so 257 is the smallest rejected value above it. The accepted-boundary
        // companion (256) is contextRandomBytesAcceptsExactLength below.
        withContext(ref -> assertIllegalArgument("insufficient random strength",
                () -> randServiceNI.contextRandomBytes(ref, new byte[1], 1, 257, false, null)));
    }

    @Test
    public void contextRandomBytesRejectsInsufficientStrengthWithZeroLength()
    {
        // 257 = boundary+1; strength is checked before the zero-length short-circuit.
        withContext(ref -> assertIllegalArgument("insufficient random strength",
                () -> randServiceNI.contextRandomBytes(ref, new byte[0], 0, 257, false, null)));
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

    // ---------------------------------------------------------------------
    // contextReseed: state / negative / strength.
    // ---------------------------------------------------------------------

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
        // 257 = boundary+1 (256 ceiling); contextReseedAcceptsAlgorithmStrength is the 256 companion.
        withContext(ref -> assertIllegalArgument("insufficient random strength",
                () -> randServiceNI.contextReseed(ref, 257, false, null)));
    }

    @Test
    public void contextReseedAcceptsAlgorithmStrength()
    {
        withContext(ref -> randServiceNI.contextReseed(ref, DRBG_STRENGTH, false, null));
    }

    // ---------------------------------------------------------------------
    // createContext: null / unknown mechanism+variant / over-strength.
    // ---------------------------------------------------------------------

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
        // AES-128-CTR caps at 128-bit strength; the FIPS module rejects an
        // over-strength instantiation ("insufficient drbg strength") at the NI
        // surface — the precise gate when the Java-side strength cap is bypassed.
        assertOpenSSLError(
                () -> randServiceNI.createContext("CTR-DRBG", "AES-128-CTR", true, 256, false, null));
    }

    // ---------------------------------------------------------------------
    // drbgStrength: null / unknown + positive companions.
    // ---------------------------------------------------------------------

    @Test
    public void drbgStrengthRejectsNullMechanism()
    {
        assertNullPointer("name is null",
                () -> randServiceNI.drbgStrength(null, "AES-256-CTR"));
    }

    @Test
    public void drbgStrengthRejectsNullVariant()
    {
        assertNullPointer("name is null",
                () -> randServiceNI.drbgStrength("CTR-DRBG", null));
    }

    @Test
    public void drbgStrengthRejectsUnknownMechanism()
    {
        assertOpenSSLError(() -> randServiceNI.drbgStrength("BOGUS-DRBG", "AES-256-CTR"));
    }

    @Test
    public void drbgStrengthRejectsUnknownVariant()
    {
        assertOpenSSLError(() -> randServiceNI.drbgStrength("CTR-DRBG", "AES-999-CTR"));
    }

    @Test
    public void drbgStrengthReturnsVariantStrength()
    {
        // Positive companion: the FIPS module reports the same strengths as the
        // non-FIPS provider for these approved DRBGs. Mirrors
        // RandServiceParameterTest.variantStrengthsAreDerivedFromOpenSSL — locks
        // that the strengths stay queried from OpenSSL, never transcribed
        // (java-spi "OpenSSL is the single source of truth"). Truncated variants
        // are excluded (unregistered under FIPS).
        Assertions.assertEquals(256, randServiceNI.drbgStrength("CTR-DRBG", "AES-256-CTR"));
        Assertions.assertEquals(192, randServiceNI.drbgStrength("CTR-DRBG", "AES-192-CTR"));
        Assertions.assertEquals(128, randServiceNI.drbgStrength("CTR-DRBG", "AES-128-CTR"));
        Assertions.assertEquals(128, randServiceNI.drbgStrength("HASH-DRBG", "SHA1"));
        Assertions.assertEquals(256, randServiceNI.drbgStrength("HASH-DRBG", "SHA2-512"));
        Assertions.assertEquals(128, randServiceNI.drbgStrength("HMAC-DRBG", "SHA1"));
        Assertions.assertEquals(256, randServiceNI.drbgStrength("HMAC-DRBG", "SHA2-512"));
    }

    // ---------------------------------------------------------------------

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

    private static void assertOpenSSLError(Runnable action)
    {
        OpenSSLException e = Assertions.assertThrows(OpenSSLException.class, action::run);
        Assertions.assertTrue(e.getMessage().startsWith("OpenSSL Error:"), e.getMessage());
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
