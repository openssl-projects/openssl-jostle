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

    private static final SecureRandom RANDOM = new SecureRandom();

    private static byte[] randomBytes(int len)
    {
        byte[] b = new byte[len];
        RANDOM.nextBytes(b);
        return b;
    }

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

    // ------------------------------------------------------------------
    // SP 800-132 module-floor probes.
    //
    // These drive kdfNI.pbkdf2 with otherwise-compliant parameters (SHA-256,
    // iter 2048, 16-byte salt, 32-byte output, >=14-byte password) and vary a
    // single parameter to its documented FIPS lower bound minus one. Unlike the
    // bridge-level rejections above, a sub-minimum value passes every bridge
    // null/range check and reaches EVP_KDF_derive, where the module's SP 800-132
    // enforcement (if active) refuses the derivation.
    //
    // Whether the 3.1.2 module actually enforces each floor at derive is
    // UNCERTAIN. Each probe therefore locks the ACTUAL behaviour: the compliant
    // value MUST derive (return 0), and the sub-minimum value is asserted to be
    // refused via OpenSSLException whose message starts "OpenSSL Error:". If a
    // floor is not enforced, the module derives, no exception is thrown, and the
    // assertThrows fails — surfacing the missing enforcement rather than hiding
    // it. Each floor lives in its own @Test so a partial-enforcement result is
    // legible.
    // ------------------------------------------------------------------

    /**
     * SP 800-132 salt floor: with compliant iter/digest/output a 16-byte salt
     * derives, while a 15-byte salt (min - 1) is refused by the module.
     */
    @Test
    public void testPBKDF2_fipsRejectsSaltBelow16Bytes()
    {
        byte[] password = randomBytes(16);

        // Compliant companion: a 16-byte salt derives successfully.
        Assertions.assertEquals(0,
                kdfNI.pbkdf2(password, randomBytes(16), 2048, "SHA-256", new byte[32], 0, 32),
                "16-byte salt should derive under SP 800-132");

        // Sub-minimum: a 15-byte salt is refused at EVP_KDF_derive.
        OpenSSLException osex = Assertions.assertThrows(OpenSSLException.class,
                () -> kdfNI.handleErrorCodes(
                        kdfNI.pbkdf2(password, randomBytes(15), 2048, "SHA-256", new byte[32], 0, 32)));
        Assertions.assertTrue(osex.getMessage().startsWith("OpenSSL Error:"),
                "unexpected message: " + osex.getMessage());
    }

    /**
     * SP 800-132 iteration floor: with compliant salt/digest/output an
     * iteration count of 1000 derives, while 999 (min - 1) is refused.
     */
    @Test
    public void testPBKDF2_fipsRejectsIterationsBelow1000()
    {
        byte[] password = randomBytes(16);
        byte[] salt = randomBytes(16);

        // Compliant companion: 1000 iterations derives successfully.
        Assertions.assertEquals(0,
                kdfNI.pbkdf2(password, salt, 1000, "SHA-256", new byte[32], 0, 32),
                "1000 iterations should derive under SP 800-132");

        // Sub-minimum: 999 iterations is refused at EVP_KDF_derive.
        OpenSSLException osex = Assertions.assertThrows(OpenSSLException.class,
                () -> kdfNI.handleErrorCodes(
                        kdfNI.pbkdf2(password, salt, 999, "SHA-256", new byte[32], 0, 32)));
        Assertions.assertTrue(osex.getMessage().startsWith("OpenSSL Error:"),
                "unexpected message: " + osex.getMessage());
    }

    /**
     * SP 800-132 derived-key floor: with compliant salt/iter/digest a 14-byte
     * (112-bit) output derives, while an 8-byte (64-bit) output is refused.
     */
    @Test
    public void testPBKDF2_fipsRejectsOutputBelow112Bits()
    {
        byte[] password = randomBytes(16);
        byte[] salt = randomBytes(16);

        // Compliant companion: a 14-byte (112-bit) output derives successfully.
        Assertions.assertEquals(0,
                kdfNI.pbkdf2(password, salt, 2048, "SHA-256", new byte[14], 0, 14),
                "14-byte (112-bit) output should derive under SP 800-132");

        // Sub-minimum: an 8-byte (64-bit) output is refused at EVP_KDF_derive.
        OpenSSLException osex = Assertions.assertThrows(OpenSSLException.class,
                () -> kdfNI.handleErrorCodes(
                        kdfNI.pbkdf2(password, salt, 2048, "SHA-256", new byte[8], 0, 8)));
        Assertions.assertTrue(osex.getMessage().startsWith("OpenSSL Error:"),
                "unexpected message: " + osex.getMessage());
    }

    /**
     * Password-length policy — locked to the module's ACTUAL behaviour. The
     * OpenSSL FIPS 3.1.2 PBKDF2 (kdf_pbkdf2) enforces the SP 800-132 salt
     * (>= 16 bytes), iteration (>= 1000) and derived-key (>= 112-bit) floors
     * (see the three tests above) but does NOT enforce a minimum PASSWORD
     * length: a short password derives successfully. This pins that fact so a
     * future module version that DOES add a password floor is flagged for
     * review rather than silently changing behaviour. (SP 800-132's password
     * strength guidance is a caller responsibility, not a module gate — do not
     * assert a floor the module does not enforce; see the "OpenSSL is the
     * single source of truth" rule.)
     */
    @Test
    public void testPBKDF2_passwordLengthNotEnforcedByModule()
    {
        byte[] salt = randomBytes(16);

        // A 13-byte password (and even a single byte) derives successfully with
        // otherwise-compliant salt/iter/output — the module applies no password
        // floor.
        Assertions.assertEquals(0,
                kdfNI.pbkdf2(randomBytes(13), salt, 2048, "SHA-256", new byte[32], 0, 32),
                "13-byte password should derive: the module enforces no password floor");
        Assertions.assertEquals(0,
                kdfNI.pbkdf2(randomBytes(1), salt, 2048, "SHA-256", new byte[32], 0, 32),
                "1-byte password should derive: the module enforces no password floor");
    }
}
