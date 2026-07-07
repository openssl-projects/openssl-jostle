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
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.provider.md.MDServiceNI;
import org.openssl.jostle.test.TestUtil;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Input-validation limit tests at the FIPS MessageDigest NI surface
 * ({@link FIPSNISelector#MDServiceNI}). The FIPS JNI glue is the base
 * md_ni_jni.c re-included under renamed symbols, so the bridge's range
 * checks and typed-error mapping are identical by construction — this test
 * pins that the FIPS interface library was built with those checks intact
 * and that each JO_* code maps to the same typed exception + message through
 * the FIPS NI classes.
 *
 * <p>Runs under the {@code integrationTest*} tasks (the base {@code test}
 * task excludes {@code *LimitTest}). Gated on {@code TEST_FIPS_LIB}; the
 * whole class skips when unset.
 *
 * <p>Discipline (testing.md): every rejection asserts the exact message, not
 * just the type; range checks are probed at exactly {@code boundary + 1} with
 * positive-side companions; every {@code int} offset/length is also fed
 * {@code -1} and {@code Integer.MIN_VALUE}; and the offset-write contract is
 * verified functionally (prefix untouched, output region round-trips, a
 * window shifted one byte earlier does not).
 */
public class FIPSMDLimitTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    @BeforeAll
    public static void beforeAll()
    {
        // Skip the whole class when no FIPS module is configured; otherwise
        // register JSLFIPS so the FIPS interface library's lib ctx is
        // initialised (allocateDigest needs it). Assumption in @BeforeAll
        // aborts before any test instance is constructed, so the mdNI field
        // initialiser below only runs when the module is present.
        org.junit.jupiter.api.Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        TestUtil.addFipsProvider();
    }

    private final MDServiceNI mdNI = FIPSNISelector.MDServiceNI;

    // ---------------------------------------------------------------------
    // allocateDigest: name + xof-length validation (bridge-level).
    // ---------------------------------------------------------------------

    @Test
    public void allocateDigest_nameNull()
    {
        NullPointerException e = Assertions.assertThrows(NullPointerException.class,
                () -> mdNI.allocateDigest(null, 0));
        Assertions.assertEquals("name is null", e.getMessage());
    }

    @Test
    public void allocateDigest_nameNotFound()
    {
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                () -> mdNI.allocateDigest("SHA-255", 0));
        Assertions.assertEquals("name not found", e.getMessage());
    }

    @Test
    public void allocateDigest_xofLenForNonXofAlgorithm()
    {
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                () -> mdNI.allocateDigest("SHA256", 32));
        Assertions.assertEquals("xof length inconsistent with algorithm", e.getMessage());
    }

    @Test
    public void allocateDigest_xofAlgorithmWithoutXofLen()
    {
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                () -> mdNI.allocateDigest("SHAKE-128", 0));
        Assertions.assertEquals("xof length inconsistent with algorithm", e.getMessage());
    }

    // ---------------------------------------------------------------------
    // engineUpdate(ref, input, off, len): null + negative + range boundary.
    // ---------------------------------------------------------------------

    @Test
    public void updateBytes_inputNull()
    {
        long ref = mdNI.allocateDigest("SHA256", 0);
        try
        {
            NullPointerException e = Assertions.assertThrows(NullPointerException.class,
                    () -> mdNI.engineUpdate(ref, null, 0, 0));
            Assertions.assertEquals("input is null", e.getMessage());
        }
        finally
        {
            dispose(ref);
        }
    }

    @Test
    public void updateBytes_offsetNegative()
    {
        long ref = mdNI.allocateDigest("SHA256", 0);
        try
        {
            for (int off : new int[]{-1, Integer.MIN_VALUE})
            {
                IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                        () -> mdNI.engineUpdate(ref, new byte[0], off, 0), "offset " + off);
                Assertions.assertEquals("input offset is negative", e.getMessage());
            }
        }
        finally
        {
            dispose(ref);
        }
    }

    @Test
    public void updateBytes_lenNegative()
    {
        long ref = mdNI.allocateDigest("SHA256", 0);
        try
        {
            for (int len : new int[]{-1, Integer.MIN_VALUE})
            {
                IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                        () -> mdNI.engineUpdate(ref, new byte[0], 0, len), "len " + len);
                Assertions.assertEquals("input len is negative", e.getMessage());
            }
        }
        finally
        {
            dispose(ref);
        }
    }

    @Test
    public void updateBytes_rangeBoundaryPlusOne()
    {
        long ref = mdNI.allocateDigest("SHA256", 0);
        try
        {
            // Smallest rejected combinations for a 10-byte buffer: len past end,
            // then offset+len past end by exactly one.
            assertUpdateOutOfRange(ref, 10, 0, 11);   // 0 + 11 = 11 > 10
            assertUpdateOutOfRange(ref, 10, 1, 10);   // 1 + 10 = 11 > 10
            assertUpdateOutOfRange(ref, 10, 11, 21);  // offset itself past end

            // Positive-side companion: offset == length, len 0 is accepted.
            mdNI.engineUpdate(ref, new byte[10], 10, 0);
            // And a normal in-range update is accepted.
            mdNI.engineUpdate(ref, new byte[10], 0, 10);
        }
        finally
        {
            dispose(ref);
        }
    }

    private void assertUpdateOutOfRange(long ref, int size, int off, int len)
    {
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                () -> mdNI.engineUpdate(ref, new byte[size], off, len),
                "size=" + size + " off=" + off + " len=" + len);
        Assertions.assertEquals("input offset + length is out of range", e.getMessage());
    }

    // ---------------------------------------------------------------------
    // digest(ref, out, off, len): negative + too-small + range boundary.
    // ---------------------------------------------------------------------

    @Test
    public void digest_outputOffsetNegative()
    {
        long ref = mdNI.allocateDigest("SHA256", 0);
        try
        {
            for (int off : new int[]{-1, Integer.MIN_VALUE})
            {
                IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                        () -> mdNI.digest(ref, new byte[0], off, 0), "offset " + off);
                Assertions.assertEquals("output offset is negative", e.getMessage());
            }
        }
        finally
        {
            dispose(ref);
        }
    }

    @Test
    public void digest_outputLenNegative()
    {
        long ref = mdNI.allocateDigest("SHA256", 0);
        try
        {
            for (int len : new int[]{-1, Integer.MIN_VALUE})
            {
                IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                        () -> mdNI.digest(ref, new byte[0], 0, len), "len " + len);
                Assertions.assertEquals("output len negative", e.getMessage());
            }
        }
        finally
        {
            dispose(ref);
        }
    }

    @Test
    public void digest_outputTooSmall()
    {
        long ref = mdNI.allocateDigest("SHA256", 0);
        try
        {
            // 31 < the 32-byte SHA-256 output.
            IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> mdNI.digest(ref, new byte[31], 0, 31));
            Assertions.assertEquals("output too small", e.getMessage());
        }
        finally
        {
            dispose(ref);
        }
    }

    @Test
    public void digest_rangeBoundaryPlusOne()
    {
        long ref = mdNI.allocateDigest("SHA256", 0);
        try
        {
            assertDigestOutOfRange(ref, 31, 0, 32);  // 0 + 32 = 32 > 31
            assertDigestOutOfRange(ref, 32, 1, 32);  // 1 + 32 = 33 > 32
            assertDigestOutOfRange(ref, 32, 32, 64); // offset itself past end
        }
        finally
        {
            dispose(ref);
        }
    }

    private void assertDigestOutOfRange(long ref, int size, int off, int len)
    {
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                () -> mdNI.digest(ref, new byte[size], off, len),
                "size=" + size + " off=" + off + " len=" + len);
        Assertions.assertEquals("output offset + length is out of range", e.getMessage());
    }

    // ---------------------------------------------------------------------
    // Offset-write contract, verified functionally (testing.md).
    // ---------------------------------------------------------------------

    @Test
    public void digest_writesAtOffsetWithoutClobberingPrefix()
    {
        byte[] input = new byte[257 + RANDOM.nextInt(1024)];
        RANDOM.nextBytes(input);

        // Reference SHA-256 of the input via a separate ref at offset 0.
        byte[] reference = new byte[32];
        long refA = mdNI.allocateDigest("SHA256", 0);
        try
        {
            mdNI.engineUpdate(refA, input, 0, input.length);
            Assertions.assertEquals(32, mdNI.digest(refA, reference, 0, 32));
        }
        finally
        {
            dispose(refA);
        }

        // Write the same digest into a random-filled buffer at a non-zero
        // offset.
        int prefix = 7;
        byte[] big = new byte[prefix + 32];
        RANDOM.nextBytes(big);
        byte[] savedPrefix = Arrays.copyOf(big, prefix);

        long refB = mdNI.allocateDigest("SHA256", 0);
        try
        {
            mdNI.engineUpdate(refB, input, 0, input.length);
            Assertions.assertEquals(32, mdNI.digest(refB, big, prefix, 32));
        }
        finally
        {
            dispose(refB);
        }

        // (1) bytes before the offset are untouched.
        Assertions.assertArrayEquals(savedPrefix, Arrays.copyOf(big, prefix),
                "prefix region was clobbered");
        // (2) the output region is exactly the digest.
        Assertions.assertArrayEquals(reference, Arrays.copyOfRange(big, prefix, prefix + 32),
                "output region is not the expected digest");
        // (3) a window shifted one byte earlier is NOT the digest — proves the
        //     write landed at exactly `prefix`, not prefix-1.
        Assertions.assertFalse(
                Arrays.equals(reference, Arrays.copyOfRange(big, prefix - 1, prefix - 1 + 32)),
                "digest appears one byte before the requested offset");
    }

    // ---------------------------------------------------------------------
    // Length-query paths and reset no-op (contract parity with the base NI).
    // ---------------------------------------------------------------------

    @Test
    public void digest_lengthQueryMatchesGetDigestOutputLen()
    {
        long ref = mdNI.allocateDigest("SHA2-512", 0);
        try
        {
            int viaGetLen = mdNI.getDigestOutputLen(ref);
            int viaNullOut = mdNI.digest(ref, null, 0, 0);
            Assertions.assertEquals(64, viaGetLen);
            Assertions.assertEquals(viaGetLen, viaNullOut);
        }
        finally
        {
            dispose(ref);
        }
    }

    @Test
    public void reset_nullRef_isNoOp()
    {
        // The default reset(long) routes a null ref through ni_reset which
        // returns JO_SUCCESS; no exception escapes.
        mdNI.reset(0);
    }

    private void dispose(long ref)
    {
        if (ref > 0)
        {
            mdNI.dispose(ref);
        }
    }
}
