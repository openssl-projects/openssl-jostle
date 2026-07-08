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
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.provider.kdf.KdfNI;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.util.Arrays;

import java.security.SecureRandom;

/**
 * Input-validation limit tests at the FIPS PBKDF2 NI surface
 * ({@code FIPSNISelector.KdfNI.pbkdf2}). The FIPS JNI glue is the base
 * kdf_ni_jni.c re-included under renamed symbols, so the bridge's null /
 * negative / range rejections and typed-error mapping are identical by
 * construction — this pins that they survived into the FIPS interface library
 * with the same messages. Mirrors the base {@code PBKdf2LimitTest}.
 *
 * <p>PBKDF2 is FIPS-approved (SP 800-132). All rejection tests fail at the
 * bridge before {@code EVP_KDF_derive}, so they never touch the module's
 * FIPS lower-bound checks (salt &ge; 16 bytes, iterations &ge; 1000); the
 * offset-write test uses FIPS-compliant parameters so its derive succeeds.
 *
 * <p>Adds testing.md extras the base lacks: {@code Integer.MIN_VALUE} on the
 * negative-int probes and a functional offset-write test.
 *
 * <p>Runs under the {@code integrationTest*} tasks; gated on
 * {@code TEST_FIPS_LIB} (whole class skips when unset).
 */
public class FIPSPBKdf2LimitTest
{
    @BeforeAll
    public static void beforeAll()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        TestUtil.addFipsProvider();
    }

    private final KdfNI kdfNI = FIPSNISelector.KdfNI;

    @Test
    public void testPBKDF2_null_password()
    {
        IllegalArgumentException iae = Assertions.assertThrows(IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(kdfNI.pbkdf2(null, new byte[1], 100, "SHA-1", new byte[1], 0, 1)));
        Assertions.assertEquals("password is null", iae.getMessage());
    }

    @Test
    public void testPBKDF2_null_salt()
    {
        IllegalArgumentException iae = Assertions.assertThrows(IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(kdfNI.pbkdf2(new byte[1], null, 100, "SHA-1", new byte[1], 0, 1)));
        Assertions.assertEquals("salt is null", iae.getMessage());
    }

    @Test
    public void testPBKDF2_empty_salt()
    {
        IllegalArgumentException iae = Assertions.assertThrows(IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(kdfNI.pbkdf2(new byte[1], new byte[0], 100, "SHA-1", new byte[1], 0, 1)));
        Assertions.assertEquals("salt is empty", iae.getMessage());
    }

    @Test
    public void testPBKDF2_iter_negative()
    {
        for (int iter : new int[]{-1, Integer.MIN_VALUE})
        {
            IllegalArgumentException iae = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> kdfNI.handleErrorCodes(kdfNI.pbkdf2(new byte[1], new byte[1], iter, "SHA-1", new byte[1], 0, 1)));
            Assertions.assertEquals("iter is negative", iae.getMessage());
        }
    }

    @Test
    public void testPBKDF2_null_output()
    {
        NullPointerException npe = Assertions.assertThrows(NullPointerException.class,
                () -> kdfNI.handleErrorCodes(kdfNI.pbkdf2(new byte[1], new byte[1], 100, "SHA-1", null, 0, 0)));
        Assertions.assertEquals("output is null", npe.getMessage());
    }

    @Test
    public void testPBKDF2_output_offset_negative()
    {
        for (int off : new int[]{-1, Integer.MIN_VALUE})
        {
            IllegalArgumentException iae = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> kdfNI.handleErrorCodes(kdfNI.pbkdf2(new byte[1], new byte[1], 100, "SHA-1", new byte[10], off, 0)));
            Assertions.assertEquals("output offset is negative", iae.getMessage());
        }
    }

    @Test
    public void testPBKDF2_output_length_negative()
    {
        for (int len : new int[]{-1, Integer.MIN_VALUE})
        {
            IllegalArgumentException iae = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> kdfNI.handleErrorCodes(kdfNI.pbkdf2(new byte[1], new byte[1], 100, "SHA-1", new byte[10], 0, len)));
            Assertions.assertEquals("output len negative", iae.getMessage());
        }
    }

    @Test
    public void testPBKDF2_output_range_past_end_1()
    {
        // Boundary + 1 on the length side: 0 + 11 > 10.
        IllegalArgumentException iae = Assertions.assertThrows(IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(kdfNI.pbkdf2(new byte[1], new byte[1], 100, "SHA-1", new byte[10], 0, 11)));
        Assertions.assertEquals("output offset + length is out of range", iae.getMessage());
    }

    @Test
    public void testPBKDF2_output_range_past_end_2()
    {
        // Boundary + 1 on the offset side: 1 + 10 > 10.
        IllegalArgumentException iae = Assertions.assertThrows(IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(kdfNI.pbkdf2(new byte[1], new byte[1], 100, "SHA-1", new byte[10], 1, 10)));
        Assertions.assertEquals("output offset + length is out of range", iae.getMessage());
    }

    @Test
    public void testPBKDF2_null_digest()
    {
        IllegalArgumentException iae = Assertions.assertThrows(IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(kdfNI.pbkdf2(new byte[1], new byte[1], 100, null, new byte[10], 0, 10)));
        Assertions.assertEquals("unknown digest", iae.getMessage());
    }

    @Test
    public void testPBKDF2_empty_digest()
    {
        IllegalArgumentException iae = Assertions.assertThrows(IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(kdfNI.pbkdf2(new byte[1], new byte[1], 100, "", new byte[10], 0, 10)));
        Assertions.assertEquals("unknown digest", iae.getMessage());
    }

    @Test
    public void testPBKDF2_unknown_digest()
    {
        // Real-failure path: "!" is not a valid digest; EVP_KDF_derive fails
        // with the real OpenSSL queue content, so prefix-match the message.
        OpenSSLException osex = Assertions.assertThrows(OpenSSLException.class,
                () -> kdfNI.handleErrorCodes(kdfNI.pbkdf2(new byte[1], new byte[1], 100, "!", new byte[10], 0, 10)));
        Assertions.assertTrue(osex.getMessage().startsWith("OpenSSL Error:"),
                "unexpected message: " + osex.getMessage());
    }

    /**
     * Offset-write contract (4-step) using FIPS-compliant parameters (16-byte
     * salt, 2048 iterations, 32-byte output) so the derive succeeds inside the
     * module: random-fill, prefix snapshot, prefix untouched, window at offset
     * equals the zero-offset derivation (PBKDF2 is deterministic),
     * shifted-by-one window does NOT.
     */
    @Test
    public void testPBKDF2_writesAtOffsetWithoutClobberingPrefix()
    {
        SecureRandom sr = new SecureRandom();
        byte[] password = new byte[16];
        byte[] salt = new byte[16];
        sr.nextBytes(password);
        sr.nextBytes(salt);
        int iter = 2048;
        int len = 32;

        byte[] reference = new byte[len];
        Assertions.assertEquals(0, kdfNI.pbkdf2(password, salt, iter, "SHA-256", reference, 0, len));

        int prefix = 7;
        byte[] big = new byte[prefix + len + 4];
        sr.nextBytes(big);
        byte[] expectedPrefix = new byte[prefix];
        System.arraycopy(big, 0, expectedPrefix, 0, prefix);

        Assertions.assertEquals(0, kdfNI.pbkdf2(password, salt, iter, "SHA-256", big, prefix, len));

        // (1) Prefix untouched.
        byte[] actualPrefix = new byte[prefix];
        System.arraycopy(big, 0, actualPrefix, 0, prefix);
        Assertions.assertArrayEquals(expectedPrefix, actualPrefix, "pbkdf2 modified bytes preceding outOffset");

        // (2) The window at the offset equals the reference derivation.
        byte[] window = new byte[len];
        System.arraycopy(big, prefix, window, 0, len);
        Assertions.assertArrayEquals(reference, window,
                "pbkdf2 output at offset differs from the zero-offset derivation");

        // (3) A window shifted one byte into the prefix must NOT match.
        byte[] shifted = new byte[len];
        System.arraycopy(big, prefix - 1, shifted, 0, len);
        Assertions.assertFalse(Arrays.areEqual(reference, shifted),
                "pbkdf2 appears to have written at outOffset - 1");
    }
}
