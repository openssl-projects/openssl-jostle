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

package org.openssl.jostle.test.kdf;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.kdf.MemoryHardKdfNI;
import org.openssl.jostle.test.crypto.TestNISelector;

import java.security.Security;

/**
 * Input-validation limits of the Argon2 NI entry point, driven directly at the
 * {@code KdfNI} surface so the C bridge's own checks are exercised rather than
 * the SPI's.
 *
 * <p>Every rejection is asserted by exact message: the code→exception mapping in
 * {@code KdfNI.handleErrorCodes} is the only place a {@code JO_*} code becomes a
 * typed exception, and a type-only assertion would pass if a case moved to a
 * different arm with the same type. Both bridges (JNI and FFI) must return the
 * same code for the same input — the {@code integrationTest25JNI} /
 * {@code integrationTest25FFI} tasks run this class against each.</p>
 */
public class Argon2LimitTest
{
    private final MemoryHardKdfNI kdfNI = TestNISelector.getMemoryHardKDFNI();

    /** Valid baseline: Argon2id, v1.3, 1 iteration, 8 KiB, 1 lane. */
    private static final int TYPE = 2;
    private static final int VERSION = 0x13;
    private static final int ITER = 1;
    private static final int MEMORY = 8;
    private static final int LANES = 1;

    @BeforeAll
    public static void beforeAll()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    private void assertRejected(Runnable call, String expectedMessage)
    {
        try
        {
            call.run();
            Assertions.fail("expected rejection: " + expectedMessage);
        }
        catch (IllegalArgumentException iae)
        {
            Assertions.assertEquals(expectedMessage, iae.getMessage());
        }
    }

    private int argon2(byte[] password, byte[] salt, int type, int version, int iterations,
                       int memory, int lanes, byte[] out, int outOffset, int outLen)
    {
        return kdfNI.handleErrorCodes(
                kdfNI.argon2(password, salt, type, version, iterations, memory, lanes, out, outOffset, outLen)) >= 0
                ? 0 : -1;
    }

    // -----------------------------------------------------------------
    // Null / empty array inputs
    // -----------------------------------------------------------------

    /**
     * A null input array with {@code off == len == 0} is the combination that
     * slips past the offset/length range checks — the bridge must null-check the
     * loaded pointer explicitly or the call reaches a util-layer assert (a JVM
     * abort, not an exception).
     */
    @Test
    public void nullPassword_zeroLengthOutput_rejectedTyped()
    {
        assertRejected(() -> argon2(null, new byte[16], TYPE, VERSION, ITER, MEMORY, LANES, new byte[0], 0, 0),
                "password is null");
    }

    @Test
    public void nullPassword_rejectedTyped()
    {
        assertRejected(() -> argon2(null, new byte[16], TYPE, VERSION, ITER, MEMORY, LANES, new byte[32], 0, 32),
                "password is null");
    }

    @Test
    public void nullSalt_zeroLengthOutput_rejectedTyped()
    {
        assertRejected(() -> argon2(new byte[8], null, TYPE, VERSION, ITER, MEMORY, LANES, new byte[0], 0, 0),
                "salt is null");
    }

    @Test
    public void nullSalt_rejectedTyped()
    {
        assertRejected(() -> argon2(new byte[8], null, TYPE, VERSION, ITER, MEMORY, LANES, new byte[32], 0, 32),
                "salt is null");
    }

    @Test
    public void emptySalt_rejectedTyped()
    {
        assertRejected(() -> argon2(new byte[8], new byte[0], TYPE, VERSION, ITER, MEMORY, LANES, new byte[32], 0, 32),
                "salt is empty");
    }

    @Test
    public void nullOutput_rejectedTyped()
    {
        try
        {
            argon2(new byte[8], new byte[16], TYPE, VERSION, ITER, MEMORY, LANES, null, 0, 0);
            Assertions.fail("expected rejection for a null output array");
        }
        catch (NullPointerException | IllegalArgumentException expected)
        {
            Assertions.assertEquals("output is null", expected.getMessage());
        }
    }

    // -----------------------------------------------------------------
    // Argon2 parameter boundaries — each probed at exactly the boundary
    // -----------------------------------------------------------------

    @Test
    public void type_belowAndAboveRange_rejectedTyped()
    {
        // Valid range is 0..2; probe exactly one either side.
        assertRejected(() -> argon2(new byte[8], new byte[16], -1, VERSION, ITER, MEMORY, LANES, new byte[32], 0, 32),
                "type is not a known Argon2 type");
        assertRejected(() -> argon2(new byte[8], new byte[16], 3, VERSION, ITER, MEMORY, LANES, new byte[32], 0, 32),
                "type is not a known Argon2 type");
        assertRejected(() -> argon2(new byte[8], new byte[16], Integer.MIN_VALUE, VERSION, ITER, MEMORY, LANES,
                        new byte[32], 0, 32),
                "type is not a known Argon2 type");
    }

    /** Positive-side companion: all three valid types are accepted. */
    @Test
    public void type_allValidValuesAccepted()
    {
        for (int type = 0; type <= 2; type++)
        {
            Assertions.assertEquals(0,
                    argon2(new byte[8], new byte[16], type, VERSION, ITER, MEMORY, LANES, new byte[32], 0, 32),
                    "type " + type + " should be accepted");
        }
    }

    @Test
    public void version_unknownValues_rejectedTyped()
    {
        // 0x10 and 0x13 are the only defined versions; 0x12 sits between them.
        assertRejected(() -> argon2(new byte[8], new byte[16], TYPE, 0x12, ITER, MEMORY, LANES, new byte[32], 0, 32),
                "version is not a known Argon2 version");
        assertRejected(() -> argon2(new byte[8], new byte[16], TYPE, 0, ITER, MEMORY, LANES, new byte[32], 0, 32),
                "version is not a known Argon2 version");
        assertRejected(() -> argon2(new byte[8], new byte[16], TYPE, -1, ITER, MEMORY, LANES, new byte[32], 0, 32),
                "version is not a known Argon2 version");
        assertRejected(() -> argon2(new byte[8], new byte[16], TYPE, Integer.MIN_VALUE, ITER, MEMORY, LANES,
                        new byte[32], 0, 32),
                "version is not a known Argon2 version");
    }

    @Test
    public void version_bothValidValuesAccepted()
    {
        for (int version : new int[]{0x10, 0x13})
        {
            Assertions.assertEquals(0,
                    argon2(new byte[8], new byte[16], TYPE, version, ITER, MEMORY, LANES, new byte[32], 0, 32),
                    "version 0x" + Integer.toHexString(version) + " should be accepted");
        }
    }

    @Test
    public void iterations_belowOne_rejectedTyped()
    {
        assertRejected(() -> argon2(new byte[8], new byte[16], TYPE, VERSION, 0, MEMORY, LANES, new byte[32], 0, 32),
                "iterations is less than 1");
        assertRejected(() -> argon2(new byte[8], new byte[16], TYPE, VERSION, -1, MEMORY, LANES, new byte[32], 0, 32),
                "iterations is less than 1");
        assertRejected(() -> argon2(new byte[8], new byte[16], TYPE, VERSION, Integer.MIN_VALUE, MEMORY, LANES,
                        new byte[32], 0, 32),
                "iterations is less than 1");
    }

    @Test
    public void lanes_belowOne_rejectedTyped()
    {
        assertRejected(() -> argon2(new byte[8], new byte[16], TYPE, VERSION, ITER, MEMORY, 0, new byte[32], 0, 32),
                "lanes is less than 1");
        assertRejected(() -> argon2(new byte[8], new byte[16], TYPE, VERSION, ITER, MEMORY, -1, new byte[32], 0, 32),
                "lanes is less than 1");
        assertRejected(() -> argon2(new byte[8], new byte[16], TYPE, VERSION, ITER, MEMORY, Integer.MIN_VALUE,
                        new byte[32], 0, 32),
                "lanes is less than 1");
    }

    /**
     * The RFC 9106 floor is {@code 8 * lanes} KiB. Probed at exactly one below
     * for two different lane counts, with the accepting boundary as the
     * positive-side companion.
     */
    @Test
    public void memory_belowEightTimesLanes_rejectedTyped()
    {
        assertRejected(() -> argon2(new byte[8], new byte[16], TYPE, VERSION, ITER, 7, 1, new byte[32], 0, 32),
                "memory is less than 8*lanes KiB");
        assertRejected(() -> argon2(new byte[8], new byte[16], TYPE, VERSION, ITER, 31, 4, new byte[32], 0, 32),
                "memory is less than 8*lanes KiB");
        assertRejected(() -> argon2(new byte[8], new byte[16], TYPE, VERSION, ITER, 0, 1, new byte[32], 0, 32),
                "memory is less than 8*lanes KiB");
        assertRejected(() -> argon2(new byte[8], new byte[16], TYPE, VERSION, ITER, -1, 1, new byte[32], 0, 32),
                "memory is less than 8*lanes KiB");
        assertRejected(() -> argon2(new byte[8], new byte[16], TYPE, VERSION, ITER, Integer.MIN_VALUE, 1,
                        new byte[32], 0, 32),
                "memory is less than 8*lanes KiB");
    }

    @Test
    public void memory_exactlyEightTimesLanes_accepted()
    {
        Assertions.assertEquals(0,
                argon2(new byte[8], new byte[16], TYPE, VERSION, ITER, 8, 1, new byte[32], 0, 32),
                "memory == 8*lanes is the floor and must be accepted");
        Assertions.assertEquals(0,
                argon2(new byte[8], new byte[16], TYPE, VERSION, ITER, 32, 4, new byte[32], 0, 32),
                "memory == 8*lanes is the floor and must be accepted");
    }

    // -----------------------------------------------------------------
    // Output offset / length range checks, probed at boundary + 1
    // -----------------------------------------------------------------

    @Test
    public void outputOffset_negative_rejectedTyped()
    {
        assertRejected(() -> argon2(new byte[8], new byte[16], TYPE, VERSION, ITER, MEMORY, LANES,
                        new byte[32], -1, 32),
                "output offset is negative");
        assertRejected(() -> argon2(new byte[8], new byte[16], TYPE, VERSION, ITER, MEMORY, LANES,
                        new byte[32], Integer.MIN_VALUE, 32),
                "output offset is negative");
    }

    @Test
    public void outputLength_negative_rejectedTyped()
    {
        assertRejected(() -> argon2(new byte[8], new byte[16], TYPE, VERSION, ITER, MEMORY, LANES,
                        new byte[32], 0, -1),
                "output len negative");
        assertRejected(() -> argon2(new byte[8], new byte[16], TYPE, VERSION, ITER, MEMORY, LANES,
                        new byte[32], 0, Integer.MIN_VALUE),
                "output len negative");
    }

    /** For a 32-byte buffer the smallest rejected length at offset 0 is 33. */
    @Test
    public void outputLength_oneBeyondBuffer_rejectedTyped()
    {
        assertRejected(() -> argon2(new byte[8], new byte[16], TYPE, VERSION, ITER, MEMORY, LANES,
                        new byte[32], 0, 33),
                "output offset + length is out of range");
    }

    /** offset + len exceeding the buffer by exactly one. */
    @Test
    public void outputOffsetPlusLength_oneBeyondBuffer_rejectedTyped()
    {
        assertRejected(() -> argon2(new byte[8], new byte[16], TYPE, VERSION, ITER, MEMORY, LANES,
                        new byte[32], 1, 32),
                "output offset + length is out of range");
    }

    /**
     * Positive-side companion to the two range probes: writing exactly to the
     * end of the buffer at a non-zero offset is accepted, proving the boundary
     * sits where the rejections say it does.
     */
    @Test
    public void outputExactlyFillsBufferFromOffset_accepted()
    {
        Assertions.assertEquals(0,
                argon2(new byte[8], new byte[16], TYPE, VERSION, ITER, MEMORY, LANES, new byte[32], 16, 16),
                "offset+len == buffer length must be accepted");
    }

    /**
     * Offset at exactly the buffer length with a zero length passes the
     * bridge's range check (it is the degenerate "write nothing at the end"
     * case) and is then rejected by OpenSSL itself: RFC 9106 requires a tag of
     * at least 4 bytes, so a zero-length derive has no meaning. Pinned here
     * because the distinction matters — the rejection is a real OpenSSL error
     * surfaced typed, not a bridge range failure and not a crash. The queue
     * text varies with OpenSSL version, so only the wrapper prefix is matched.
     */
    @Test
    public void outputZeroLength_rejectedByOpenSsl()
    {
        try
        {
            argon2(new byte[8], new byte[16], TYPE, VERSION, ITER, MEMORY, LANES, new byte[32], 32, 0);
            Assertions.fail("expected OpenSSL to reject a zero-length Argon2 output");
        }
        catch (OpenSSLException e)
        {
            Assertions.assertTrue(e.getMessage().startsWith("OpenSSL Error:"),
                    "unexpected message: " + e.getMessage());
        }
    }

    /**
     * The derive writes at the requested offset and nowhere else — the same
     * offset-write contract the guides require of every buffer-writing entry
     * point, verified against a separately-derived reference rather than a
     * sentinel byte.
     */
    @Test
    public void writesAtOffsetWithoutClobberingPrefix()
    {
        byte[] password = new byte[8];
        byte[] salt = new byte[16];

        byte[] reference = new byte[32];
        Assertions.assertEquals(0,
                argon2(password, salt, TYPE, VERSION, ITER, MEMORY, LANES, reference, 0, 32));

        byte[] big = new byte[80];
        new java.security.SecureRandom().nextBytes(big);
        byte[] expectedPrefix = new byte[24];
        System.arraycopy(big, 0, expectedPrefix, 0, expectedPrefix.length);
        byte[] expectedSuffix = new byte[big.length - 24 - 32];
        System.arraycopy(big, 24 + 32, expectedSuffix, 0, expectedSuffix.length);

        Assertions.assertEquals(0,
                argon2(password, salt, TYPE, VERSION, ITER, MEMORY, LANES, big, 24, 32));

        byte[] actualPrefix = new byte[24];
        System.arraycopy(big, 0, actualPrefix, 0, actualPrefix.length);
        Assertions.assertArrayEquals(expectedPrefix, actualPrefix, "bytes before the offset were modified");

        byte[] actualSuffix = new byte[expectedSuffix.length];
        System.arraycopy(big, 24 + 32, actualSuffix, 0, actualSuffix.length);
        Assertions.assertArrayEquals(expectedSuffix, actualSuffix, "bytes after the written region were modified");

        byte[] written = new byte[32];
        System.arraycopy(big, 24, written, 0, 32);
        Assertions.assertArrayEquals(reference, written, "the derived key did not land at the requested offset");

        byte[] shifted = new byte[32];
        System.arraycopy(big, 23, shifted, 0, 32);
        Assertions.assertFalse(org.openssl.jostle.util.Arrays.areEqual(reference, shifted),
                "the derive wrote one byte early");
    }
}
