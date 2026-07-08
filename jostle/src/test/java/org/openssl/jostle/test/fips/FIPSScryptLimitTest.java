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
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.provider.kdf.KdfNI;
import org.openssl.jostle.test.TestUtil;

/**
 * Input-validation limit tests at the FIPS scrypt NI surface
 * ({@code FIPSNISelector.KdfNI.scrypt}). The FIPS JNI glue is the base
 * kdf_ni_jni.c re-included under renamed symbols, so the bridge's null /
 * negative / range / parameter-shape rejections and typed-error mapping are
 * identical by construction — this pins that they survived into the FIPS
 * interface library with the same messages. Mirrors the base
 * {@code ScryptLimitTest}.
 *
 * <p>FIPS note: scrypt is NOT a FIPS-approved KDF and the JSLFIPS provider does
 * not register it, but the scrypt bridge is still compiled into the FIPS
 * interface library (the kdf glue is re-included whole). Every test here
 * rejects at the bridge before {@code EVP_KDF_derive}, so none exercises a real
 * scrypt derivation — the coverage is pure bridge-validation parity and does
 * not depend on the module serving the algorithm.
 *
 * <p>Adds {@code Integer.MIN_VALUE} alongside {@code -1} on the negative-int
 * output probes (testing.md).
 *
 * <p>Runs under the {@code integrationTest*} tasks; gated on
 * {@code TEST_FIPS_LIB} (whole class skips when unset).
 */
public class FIPSScryptLimitTest
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
    public void testSCRYPT_null_password()
    {
        IllegalArgumentException iae = Assertions.assertThrows(IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(kdfNI.scrypt(null, new byte[1], 8, 10, 1, new byte[1], 0, 1)));
        Assertions.assertEquals("password is null", iae.getMessage());
    }

    @Test
    public void testSCRYPT_null_salt()
    {
        IllegalArgumentException iae = Assertions.assertThrows(IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(kdfNI.scrypt(new byte[1], null, 8, 10, 1, new byte[1], 0, 1)));
        Assertions.assertEquals("salt is null", iae.getMessage());
    }

    @Test
    public void testSCRYPT_empty_salt()
    {
        IllegalArgumentException iae = Assertions.assertThrows(IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(kdfNI.scrypt(new byte[1], new byte[0], 8, 10, 10, new byte[1], 0, 1)));
        Assertions.assertEquals("salt is empty", iae.getMessage());
    }

    @Test
    public void testSCRYPT_n_too_small()
    {
        for (int n : new int[]{1, 0, -1})
        {
            IllegalArgumentException iae = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> kdfNI.handleErrorCodes(kdfNI.scrypt(new byte[1], new byte[1], n, 10, 10, new byte[1], 0, 1)));
            Assertions.assertEquals("n is less than 2", iae.getMessage());
        }
    }

    @Test
    public void testSCRYPT_n_not_pow2()
    {
        for (int n : new int[]{3, 5, 65537})
        {
            IllegalArgumentException iae = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> kdfNI.handleErrorCodes(kdfNI.scrypt(new byte[1], new byte[1], n, 10, 10, new byte[1], 0, 1)));
            Assertions.assertEquals("n not power of 2", iae.getMessage());
        }
    }

    @Test
    public void testSCRYPT_r_negative()
    {
        IllegalArgumentException iae = Assertions.assertThrows(IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(kdfNI.scrypt(new byte[1], new byte[1], 8, -1, 10, new byte[1], 0, 1)));
        Assertions.assertEquals("r is negative", iae.getMessage());
    }

    @Test
    public void testSCRYPT_p_negative()
    {
        IllegalArgumentException iae = Assertions.assertThrows(IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(kdfNI.scrypt(new byte[1], new byte[1], 8, 10, -1, new byte[1], 0, 1)));
        Assertions.assertEquals("p is negative", iae.getMessage());
    }

    @Test
    public void testSCRYPT_null_output()
    {
        NullPointerException npe = Assertions.assertThrows(NullPointerException.class,
                () -> kdfNI.handleErrorCodes(kdfNI.scrypt(new byte[1], new byte[1], 8, 10, 1, null, 0, 0)));
        Assertions.assertEquals("output is null", npe.getMessage());
    }

    @Test
    public void testSCRYPT_output_offset_negative()
    {
        for (int off : new int[]{-1, Integer.MIN_VALUE})
        {
            IllegalArgumentException iae = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> kdfNI.handleErrorCodes(kdfNI.scrypt(new byte[1], new byte[1], 8, 10, 1, new byte[10], off, 0)));
            Assertions.assertEquals("output offset is negative", iae.getMessage());
        }
    }

    @Test
    public void testSCRYPT_output_length_negative()
    {
        for (int len : new int[]{-1, Integer.MIN_VALUE})
        {
            IllegalArgumentException iae = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> kdfNI.handleErrorCodes(kdfNI.scrypt(new byte[1], new byte[1], 8, 10, 1, new byte[10], 0, len)));
            Assertions.assertEquals("output len negative", iae.getMessage());
        }
    }

    @Test
    public void testSCRYPT_output_range_past_end_1()
    {
        // Boundary + 1 on the length side: 0 + 11 > 10.
        IllegalArgumentException iae = Assertions.assertThrows(IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(kdfNI.scrypt(new byte[1], new byte[1], 8, 10, 1, new byte[10], 0, 11)));
        Assertions.assertEquals("output offset + length is out of range", iae.getMessage());
    }

    @Test
    public void testSCRYPT_output_range_past_end_2()
    {
        // Boundary + 1 on the offset side: 1 + 10 > 10.
        IllegalArgumentException iae = Assertions.assertThrows(IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(kdfNI.scrypt(new byte[1], new byte[1], 8, 10, 1, new byte[10], 1, 10)));
        Assertions.assertEquals("output offset + length is out of range", iae.getMessage());
    }
}
