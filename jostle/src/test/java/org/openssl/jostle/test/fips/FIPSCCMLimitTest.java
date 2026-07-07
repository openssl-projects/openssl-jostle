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
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.blockcipher.CCMCipherNI;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.test.TestUtil;

import java.util.Arrays;

/**
 * Input-validation limit tests at the FIPS AES-CCM NI surface
 * ({@link FIPSNISelector#CCMCipherNI}). CCM is one-shot: the bridge validates
 * the null ctx, null key/iv, tag length, and nonce (iv) length before the
 * native call. The FIPS glue is the base ccm_ni_jni.c re-included under
 * renamed symbols, so these checks are identical by construction; this pins
 * that they survived into the FIPS interface library with the same JO_*
 * return codes.
 *
 * <p>Runs under the {@code integrationTest*} tasks; gated on
 * {@code TEST_FIPS_LIB} (whole class skips when unset). Uses the raw
 * {@code ni_*} surface and asserts exact return codes — the tag/nonce
 * membership checks are probed on both sides of every valid value, and the
 * doFinal offset-write is verified functionally.
 */
public class FIPSCCMLimitTest
{
    private static final java.security.SecureRandom RANDOM = new java.security.SecureRandom();

    @BeforeAll
    public static void beforeAll()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        TestUtil.addFipsProvider();
    }

    private final CCMCipherNI ni = FIPSNISelector.CCMCipherNI;

    private long makeInstance()
    {
        int[] err = new int[1];
        long ref = ni.ni_makeInstance(CCMCipherNI.AES128, err);
        Assertions.assertEquals(0, err[0], "ni_makeInstance(AES128) should succeed");
        Assertions.assertNotEquals(0, ref);
        return ref;
    }

    @Test
    public void init_nullRef()
    {
        Assertions.assertEquals(ErrorCode.JO_FAIL.getCode(),
                ni.ni_init(0L, CCMCipherNI.OP_ENCRYPT, new byte[16], new byte[12], 16));
    }

    @Test
    public void init_nullKey()
    {
        long ref = makeInstance();
        try
        {
            Assertions.assertEquals(ErrorCode.JO_KEY_IS_NULL.getCode(),
                    ni.ni_init(ref, CCMCipherNI.OP_ENCRYPT, null, new byte[12], 16));
        }
        finally
        {
            ni.ni_dispose(ref);
        }
    }

    @Test
    public void init_nullIv()
    {
        long ref = makeInstance();
        try
        {
            Assertions.assertEquals(ErrorCode.JO_IV_IS_NULL.getCode(),
                    ni.ni_init(ref, CCMCipherNI.OP_ENCRYPT, new byte[16], null, 16));
        }
        finally
        {
            ni.ni_dispose(ref);
        }
    }

    @Test
    public void init_negativeTagLen()
    {
        long ref = makeInstance();
        try
        {
            for (int tagLen : new int[]{-1, Integer.MIN_VALUE})
            {
                Assertions.assertEquals(ErrorCode.JO_INVALID_TAG_LEN.getCode(),
                        ni.ni_init(ref, CCMCipherNI.OP_ENCRYPT, new byte[16], new byte[12], tagLen),
                        "tagLen=" + tagLen);
            }
        }
        finally
        {
            ni.ni_dispose(ref);
        }
    }

    @Test
    public void init_tagLenSetMembership()
    {
        long ref = makeInstance();
        try
        {
            for (int tagLen : new int[]{4, 6, 8, 10, 12, 14, 16})
            {
                Assertions.assertEquals(0,
                        ni.ni_init(ref, CCMCipherNI.OP_ENCRYPT, new byte[16], new byte[12], tagLen),
                        "tagLen=" + tagLen + " (valid) must be accepted");
            }
            // Both neighbours of every valid even, plus below-min and above-max.
            for (int tagLen : new int[]{3, 5, 7, 9, 11, 13, 15, 17})
            {
                Assertions.assertEquals(ErrorCode.JO_INVALID_TAG_LEN.getCode(),
                        ni.ni_init(ref, CCMCipherNI.OP_ENCRYPT, new byte[16], new byte[12], tagLen),
                        "tagLen=" + tagLen + " (invalid) must be rejected");
            }
        }
        finally
        {
            ni.ni_dispose(ref);
        }
    }

    @Test
    public void init_ivLenBoundary()
    {
        long ref = makeInstance();
        try
        {
            for (int ivLen : new int[]{7, 13})
            {
                Assertions.assertEquals(0,
                        ni.ni_init(ref, CCMCipherNI.OP_ENCRYPT, new byte[16], new byte[ivLen], 16),
                        "ivLen=" + ivLen + " (valid) must be accepted");
            }
            for (int ivLen : new int[]{0, 6, 14})
            {
                Assertions.assertEquals(ErrorCode.JO_INVALID_IV_LEN.getCode(),
                        ni.ni_init(ref, CCMCipherNI.OP_ENCRYPT, new byte[16], new byte[ivLen], 16),
                        "ivLen=" + ivLen + " (invalid) must be rejected");
            }
        }
        finally
        {
            ni.ni_dispose(ref);
        }
    }

    // ---------------------------------------------------------------------
    // Offset-write contract for ni_doFinal, verified functionally.
    // ---------------------------------------------------------------------

    @Test
    public void doFinal_writesAtOffsetWithoutClobberingPrefix()
    {
        byte[] key = new byte[16];
        byte[] iv = new byte[12];
        byte[] pt = new byte[24];
        RANDOM.nextBytes(key);
        RANDOM.nextBytes(iv);
        RANDOM.nextBytes(pt);
        int tagLen = 16;

        byte[] reference = encrypt(key, iv, pt, tagLen, 0);

        int prefix = 5;
        int outLen = pt.length + tagLen;
        byte[] big = new byte[prefix + outLen + 8];
        RANDOM.nextBytes(big);
        byte[] savedPrefix = Arrays.copyOf(big, prefix);

        long ref = makeInstance();
        try
        {
            Assertions.assertEquals(0, ni.ni_init(ref, CCMCipherNI.OP_ENCRYPT, key, iv, tagLen));
            int written = ni.ni_doFinal(ref, null, 0, pt, 0, pt.length, big, prefix);
            Assertions.assertEquals(outLen, written, "ct+tag length");

            // (1) prefix untouched.
            Assertions.assertArrayEquals(savedPrefix, Arrays.copyOf(big, prefix),
                    "prefix region was clobbered");
            // (2) output region equals the reference ct+tag.
            Assertions.assertArrayEquals(reference, Arrays.copyOfRange(big, prefix, prefix + outLen),
                    "output region is not the expected ciphertext+tag");
            // (3) a window one byte earlier does not.
            Assertions.assertFalse(
                    Arrays.equals(reference, Arrays.copyOfRange(big, prefix - 1, prefix - 1 + outLen)),
                    "ciphertext appears one byte before the offset");
        }
        finally
        {
            ni.ni_dispose(ref);
        }
    }

    private byte[] encrypt(byte[] key, byte[] iv, byte[] pt, int tagLen, int outOff)
    {
        long ref = makeInstance();
        try
        {
            Assertions.assertEquals(0, ni.ni_init(ref, CCMCipherNI.OP_ENCRYPT, key, iv, tagLen));
            byte[] out = new byte[outOff + pt.length + tagLen];
            int n = ni.ni_doFinal(ref, null, 0, pt, 0, pt.length, out, outOff);
            return Arrays.copyOfRange(out, outOff, outOff + n);
        }
        finally
        {
            ni.ni_dispose(ref);
        }
    }
}
