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
 * Input-validation limit tests at the FIPS HKDF NI surface
 * ({@code FIPSNISelector.KdfNI.hkdf}). The FIPS JNI glue is the base
 * kdf_ni_jni.c re-included under renamed symbols, so the bridge's null /
 * negative / range rejections and typed-error mapping are identical by
 * construction — this pins that they survived into the FIPS interface library
 * with the same messages. Mirrors the base {@code HkdfLimitTest}.
 *
 * <p>HKDF is FIPS-approved (SP 800-56C); the successful-derive tests exercise
 * the module's HKDF for real. The {@code RandSource} plays no part here (HKDF
 * consumes no entropy).
 *
 * <p>Runs under the {@code integrationTest*} tasks; gated on
 * {@code TEST_FIPS_LIB} (whole class skips when unset).
 */
public class FIPSHkdfLimitTest
{
    @BeforeAll
    public static void beforeAll()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        TestUtil.addFipsProvider();
    }

    private final KdfNI kdfNI = FIPSNISelector.KdfNI;

    /**
     * IKM that clears the module's HMAC key floor
     * ({@link FIPSTestUtil#HMAC_MIN_KEY_BYTES}). Only the tests that expect a
     * successful derive need it — the rejection tests are refused by the
     * bridge's own validation before the module sees the key.
     */
    private static byte[] conformingIkm()
    {
        byte[] ikm = new byte[FIPSTestUtil.HMAC_MIN_KEY_BYTES];
        java.util.Arrays.fill(ikm, (byte) 0x0b);
        return ikm;
    }

    @Test
    public void testHKDF_null_ikm()
    {
        IllegalArgumentException iae = Assertions.assertThrows(IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(kdfNI.hkdf(null, new byte[1], new byte[1], "SHA-256", new byte[1], 0, 1)));
        Assertions.assertEquals("ikm is null", iae.getMessage());
    }

    @Test
    public void testHKDF_null_salt_and_info_accepted()
    {
        // salt and info are optional at the NI surface: null salt means
        // "HashLen zeros" (RFC 5869), null info means "no context info".
        // The IKM must clear the module's 112-bit key floor.
        byte[] out = new byte[32];
        int code = kdfNI.hkdf(conformingIkm(), null, null, "SHA-256", out, 0, out.length);
        Assertions.assertEquals(0, code, "null salt + null info must derive successfully");
        Assertions.assertFalse(Arrays.areEqual(out, new byte[32]), "derived output is all-zero (stub?)");
    }

    @Test
    public void testHKDF_null_output()
    {
        NullPointerException npe = Assertions.assertThrows(NullPointerException.class,
                () -> kdfNI.handleErrorCodes(kdfNI.hkdf(new byte[1], new byte[1], new byte[1], "SHA-256", null, 0, 0)));
        Assertions.assertEquals("output is null", npe.getMessage());
    }

    @Test
    public void testHKDF_output_offset_negative()
    {
        IllegalArgumentException iae = Assertions.assertThrows(IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(kdfNI.hkdf(new byte[1], new byte[1], new byte[1], "SHA-256", new byte[10], -1, 0)));
        Assertions.assertEquals("output offset is negative", iae.getMessage());
    }

    @Test
    public void testHKDF_output_offset_minValue()
    {
        IllegalArgumentException iae = Assertions.assertThrows(IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(kdfNI.hkdf(new byte[1], new byte[1], new byte[1], "SHA-256", new byte[10], Integer.MIN_VALUE, 0)));
        Assertions.assertEquals("output offset is negative", iae.getMessage());
    }

    @Test
    public void testHKDF_output_length_negative()
    {
        IllegalArgumentException iae = Assertions.assertThrows(IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(kdfNI.hkdf(new byte[1], new byte[1], new byte[1], "SHA-256", new byte[10], 0, -1)));
        Assertions.assertEquals("output len negative", iae.getMessage());
    }

    @Test
    public void testHKDF_output_length_minValue()
    {
        IllegalArgumentException iae = Assertions.assertThrows(IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(kdfNI.hkdf(new byte[1], new byte[1], new byte[1], "SHA-256", new byte[10], 0, Integer.MIN_VALUE)));
        Assertions.assertEquals("output len negative", iae.getMessage());
    }

    @Test
    public void testHKDF_output_range_past_end_1()
    {
        // Boundary + 1 on the length side: 0 + 11 > 10.
        IllegalArgumentException iae = Assertions.assertThrows(IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(kdfNI.hkdf(new byte[1], new byte[1], new byte[1], "SHA-256", new byte[10], 0, 11)));
        Assertions.assertEquals("output offset + length is out of range", iae.getMessage());
    }

    @Test
    public void testHKDF_output_range_past_end_2()
    {
        // Boundary + 1 on the offset side: 1 + 10 > 10.
        IllegalArgumentException iae = Assertions.assertThrows(IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(kdfNI.hkdf(new byte[1], new byte[1], new byte[1], "SHA-256", new byte[10], 1, 10)));
        Assertions.assertEquals("output offset + length is out of range", iae.getMessage());
    }

    @Test
    public void testHKDF_output_range_atEnd_accepted()
    {
        // Positive companion: offset + len == size is exactly in range.
        int code = kdfNI.hkdf(conformingIkm(), new byte[1], new byte[1], "SHA-256", new byte[42], 10, 32);
        Assertions.assertEquals(0, code);
    }

    @Test
    public void testHKDF_null_digest()
    {
        IllegalArgumentException iae = Assertions.assertThrows(IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(kdfNI.hkdf(new byte[1], new byte[1], new byte[1], null, new byte[10], 0, 10)));
        Assertions.assertEquals("unknown digest", iae.getMessage());
    }

    @Test
    public void testHKDF_empty_digest()
    {
        IllegalArgumentException iae = Assertions.assertThrows(IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(kdfNI.hkdf(new byte[1], new byte[1], new byte[1], "", new byte[10], 0, 10)));
        Assertions.assertEquals("unknown digest", iae.getMessage());
    }

    @Test
    public void testHKDF_unknown_digest()
    {
        // Real-failure path: "!" is not a valid digest; EVP_KDF_derive fails
        // with the real OpenSSL queue content, so prefix-match the message.
        OpenSSLException osex = Assertions.assertThrows(OpenSSLException.class,
                () -> kdfNI.handleErrorCodes(kdfNI.hkdf(new byte[1], new byte[1], new byte[1], "!", new byte[10], 0, 10)));
        Assertions.assertTrue(osex.getMessage().startsWith("OpenSSL Error:"),
                "unexpected message: " + osex.getMessage());
    }

    /**
     * Offset-write contract (4-step): random-fill, prefix snapshot, prefix
     * untouched, window at offset equals the zero-offset derivation (HKDF is
     * deterministic), shifted-by-one window does NOT.
     */
    @Test
    public void testHKDF_writesAtOffsetWithoutClobberingPrefix()
    {
        SecureRandom sr = new SecureRandom();
        byte[] ikm = new byte[22];
        byte[] salt = new byte[13];
        byte[] info = new byte[10];
        sr.nextBytes(ikm);
        sr.nextBytes(salt);
        sr.nextBytes(info);
        int len = 42;

        byte[] reference = new byte[len];
        Assertions.assertEquals(0, kdfNI.hkdf(ikm, salt, info, "SHA-256", reference, 0, len));

        int prefix = 7;
        byte[] big = new byte[prefix + len + 4];
        sr.nextBytes(big);
        byte[] expectedPrefix = new byte[prefix];
        System.arraycopy(big, 0, expectedPrefix, 0, prefix);

        Assertions.assertEquals(0, kdfNI.hkdf(ikm, salt, info, "SHA-256", big, prefix, len));

        // (1) Prefix untouched.
        byte[] actualPrefix = new byte[prefix];
        System.arraycopy(big, 0, actualPrefix, 0, prefix);
        Assertions.assertArrayEquals(expectedPrefix, actualPrefix, "hkdf modified bytes preceding outOffset");

        // (2) The window at the offset equals the reference derivation.
        byte[] window = new byte[len];
        System.arraycopy(big, prefix, window, 0, len);
        Assertions.assertArrayEquals(reference, window,
                "hkdf output at offset differs from the zero-offset derivation");

        // (3) A window shifted one byte into the prefix must NOT match.
        byte[] shifted = new byte[len];
        System.arraycopy(big, prefix - 1, shifted, 0, len);
        Assertions.assertFalse(Arrays.areEqual(reference, shifted),
                "hkdf appears to have written at outOffset - 1");
    }
}
