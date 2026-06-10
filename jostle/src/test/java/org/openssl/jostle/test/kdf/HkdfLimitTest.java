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
import org.openssl.jostle.jcajce.provider.kdf.KdfNI;
import org.openssl.jostle.test.crypto.TestNISelector;
import org.openssl.jostle.util.Arrays;

import java.security.SecureRandom;
import java.security.Security;

/**
 * NI-layer input-validation tests for the HKDF bridge ({@code KdfNI.hkdf}),
 * mirroring {@link PBKdf2LimitTest}. Exercises the JNI / FFI bridges' null /
 * negative / range rejections (identical codes on both bridges), the NI-level
 * acceptance of null salt / null info (the only way to reach the C
 * {@code salt == NULL} / {@code info == NULL} paths, since
 * {@code HKDFParameterSpec} normalises before the SPI), and the offset-write
 * contract.
 */
public class HkdfLimitTest
{
    KdfNI kdfNI = TestNISelector.getKDFNI();

    @BeforeAll
    public static void beforeAll()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    @Test
    public void testHKDF_null_ikm() throws Exception
    {
        try
        {
            kdfNI.handleErrorCodes(kdfNI.hkdf(null, new byte[1], new byte[1], "SHA-256", new byte[1], 0, 1));
            Assertions.fail();
        } catch (IllegalArgumentException iae)
        {
            Assertions.assertEquals("ikm is null", iae.getMessage());
        }
    }

    @Test
    public void testHKDF_null_salt_and_info_accepted() throws Exception
    {
        // salt and info are optional at the NI surface: null salt means
        // "HashLen zeros" (RFC 5869), null info means "no context info".
        byte[] out = new byte[32];
        int code = kdfNI.hkdf(new byte[]{0x0b}, null, null, "SHA-256", out, 0, out.length);
        Assertions.assertEquals(0, code, "null salt + null info must derive successfully");
        Assertions.assertFalse(Arrays.areEqual(out, new byte[32]),
                "derived output is all-zero (stub?)");
    }

    @Test
    public void testHKDF_null_output() throws Exception
    {
        try
        {
            kdfNI.handleErrorCodes(kdfNI.hkdf(new byte[1], new byte[1], new byte[1], "SHA-256", null, 0, 0));
            Assertions.fail();
        } catch (NullPointerException npe)
        {
            Assertions.assertEquals("output is null", npe.getMessage());
        }
    }

    @Test
    public void testHKDF_output_offset_negative() throws Exception
    {
        try
        {
            kdfNI.handleErrorCodes(kdfNI.hkdf(new byte[1], new byte[1], new byte[1], "SHA-256", new byte[10], -1, 0));
            Assertions.fail();
        } catch (IllegalArgumentException iae)
        {
            Assertions.assertEquals("output offset is negative", iae.getMessage());
        }
    }

    @Test
    public void testHKDF_output_offset_minValue() throws Exception
    {
        try
        {
            kdfNI.handleErrorCodes(kdfNI.hkdf(new byte[1], new byte[1], new byte[1], "SHA-256", new byte[10], Integer.MIN_VALUE, 0));
            Assertions.fail();
        } catch (IllegalArgumentException iae)
        {
            Assertions.assertEquals("output offset is negative", iae.getMessage());
        }
    }

    @Test
    public void testHKDF_output_length_negative() throws Exception
    {
        try
        {
            kdfNI.handleErrorCodes(kdfNI.hkdf(new byte[1], new byte[1], new byte[1], "SHA-256", new byte[10], 0, -1));
            Assertions.fail();
        } catch (IllegalArgumentException iae)
        {
            Assertions.assertEquals("output len negative", iae.getMessage());
        }
    }

    @Test
    public void testHKDF_output_length_minValue() throws Exception
    {
        try
        {
            kdfNI.handleErrorCodes(kdfNI.hkdf(new byte[1], new byte[1], new byte[1], "SHA-256", new byte[10], 0, Integer.MIN_VALUE));
            Assertions.fail();
        } catch (IllegalArgumentException iae)
        {
            Assertions.assertEquals("output len negative", iae.getMessage());
        }
    }

    @Test
    public void testHKDF_output_range_past_end_1() throws Exception
    {
        // Boundary + 1 on the length side: 0 + 11 > 10.
        try
        {
            kdfNI.handleErrorCodes(kdfNI.hkdf(new byte[1], new byte[1], new byte[1], "SHA-256", new byte[10], 0, 11));
            Assertions.fail();
        } catch (IllegalArgumentException iae)
        {
            Assertions.assertEquals("output offset + length is out of range", iae.getMessage());
        }
    }

    @Test
    public void testHKDF_output_range_past_end_2() throws Exception
    {
        // Boundary + 1 on the offset side: 1 + 10 > 10.
        try
        {
            kdfNI.handleErrorCodes(kdfNI.hkdf(new byte[1], new byte[1], new byte[1], "SHA-256", new byte[10], 1, 10));
            Assertions.fail();
        } catch (IllegalArgumentException iae)
        {
            Assertions.assertEquals("output offset + length is out of range", iae.getMessage());
        }
    }

    @Test
    public void testHKDF_output_range_atEnd_accepted() throws Exception
    {
        // Positive companion to the past-end probes: offset + len == size is
        // exactly in range — proves the boundary sits exactly past the end,
        // not one byte earlier. (A zero-length derive can't serve here:
        // EVP_KDF_derive itself rejects keylen == 0, downstream of the range
        // check under test.)
        int code = kdfNI.hkdf(new byte[]{0x0b}, new byte[1], new byte[1], "SHA-256", new byte[42], 10, 32);
        Assertions.assertEquals(0, code);
    }

    @Test
    public void testHKDF_null_digest() throws Exception
    {
        try
        {
            kdfNI.handleErrorCodes(kdfNI.hkdf(new byte[1], new byte[1], new byte[1], null, new byte[10], 0, 10));
            Assertions.fail();
        } catch (IllegalArgumentException iae)
        {
            Assertions.assertEquals("unknown digest", iae.getMessage());
        }
    }

    @Test
    public void testHKDF_empty_digest() throws Exception
    {
        try
        {
            kdfNI.handleErrorCodes(kdfNI.hkdf(new byte[1], new byte[1], new byte[1], "", new byte[10], 0, 10));
            Assertions.fail();
        } catch (IllegalArgumentException iae)
        {
            Assertions.assertEquals("unknown digest", iae.getMessage());
        }
    }

    @Test
    public void testHKDF_unknown_digest() throws Exception
    {
        // Real-failure path: "!" is not a valid digest; EVP_KDF_derive fails
        // with the real OpenSSL queue content, so prefix-match the message.
        try
        {
            kdfNI.handleErrorCodes(kdfNI.hkdf(new byte[1], new byte[1], new byte[1], "!", new byte[10], 0, 10));
            Assertions.fail();
        } catch (OpenSSLException osex)
        {
            Assertions.assertTrue(osex.getMessage().startsWith("OpenSSL Error:"),
                    "unexpected message: " + osex.getMessage());
        }
    }

    /**
     * Offset-write contract (4-step): random-fill, prefix snapshot, prefix
     * untouched, window at offset equals the zero-offset derivation (HKDF is
     * deterministic), shifted-by-one window does NOT.
     */
    @Test
    public void testHKDF_writesAtOffsetWithoutClobberingPrefix() throws Exception
    {
        SecureRandom sr = new SecureRandom();
        byte[] ikm = new byte[22];
        byte[] salt = new byte[13];
        byte[] info = new byte[10];
        sr.nextBytes(ikm);
        sr.nextBytes(salt);
        sr.nextBytes(info);
        int len = 42;

        // Reference derivation at offset 0.
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
        Assertions.assertArrayEquals(expectedPrefix, actualPrefix,
                "hkdf modified bytes preceding outOffset");

        // (2) The window at the offset equals the reference derivation.
        byte[] window = new byte[len];
        System.arraycopy(big, prefix, window, 0, len);
        Assertions.assertArrayEquals(reference, window,
                "hkdf output at offset differs from the zero-offset derivation");

        // (3) A window shifted one byte into the prefix must NOT match —
        //     catches a write at outOffset - 1.
        byte[] shifted = new byte[len];
        System.arraycopy(big, prefix - 1, shifted, 0, len);
        Assertions.assertFalse(Arrays.areEqual(reference, shifted),
                "hkdf appears to have written at outOffset - 1");
    }
}
