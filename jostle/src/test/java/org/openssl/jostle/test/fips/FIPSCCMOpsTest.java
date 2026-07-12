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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.blockcipher.CCMCipherNI;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.util.ops.OperationsTestNI;

/**
 * Fault-injection tests for the FIPS CCM authenticated-encryption NI. AES-CCM
 * is FIPS-approved, so this is a straight mirror of {@code CCMOpsTest} driving
 * {@link FIPSNISelector#CCMCipherNI}. The fault sites (interface/fips/util/ccm_ctx.c
 * and the JNI access points in interface/fips/jni/ccm_ni_jni.c) are re-included into
 * the FIPS library, so the per-site {@code OPS_OFFSET_*}-disambiguated codes
 * (CCM 4000-block; {@code JO_OPENSSL_ERROR (-2)} minus the offset) are
 * identical. Pinning the exact code catches a silent offset renumber.
 *
 * <p>Requires a JOSTLE_OPS_TEST build of the FIPS library: gated on
 * {@code TEST_FIPS_LIB} and per-test on {@code opsTestAvailable()}. The
 * FAILED_ACCESS tests are JNI-only (the FFI bridge takes raw pointers).
 */
public class FIPSCCMOpsTest
{
    @BeforeAll
    public static void beforeAll()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        TestUtil.addFipsProvider();
    }

    private final CCMCipherNI ccmCipherNI = FIPSNISelector.CCMCipherNI;
    private final OperationsTestNI operationsTestNI = FIPSNISelector.OperationsTestNI;

    @BeforeEach
    public void beforeEach()
    {
        if (operationsTestNI.opsTestAvailable())
        {
            operationsTestNI.resetFlags();
        }
    }

    /** Fresh AES-128-CCM ctx; create never fetches, so no OPS flag fires here. */
    private long newCtx()
    {
        int[] err = new int[1];
        long ref = ccmCipherNI.ni_makeInstance(CCMCipherNI.AES128, err);
        Assertions.assertEquals(0, err[0], "ni_makeInstance(AES128) should succeed");
        return ref;
    }

    private void initOk(long ref, int opMode)
    {
        Assertions.assertEquals(0,
                ccmCipherNI.ni_init(ref, opMode, new byte[16], new byte[12], 16),
                "ni_init should succeed before the OPS flag is armed");
    }

    @Test
    public void ccm_makeInstance_ctxNew_failure()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        int[] err = new int[1];
        try
        {
            // Exercises interface/fips/util/ccm_ctx.c:105
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_CREATE_2);
            ref = ccmCipherNI.ni_makeInstance(CCMCipherNI.AES128, err);
            Assertions.assertEquals(-4019, err[0]);
            Assertions.assertEquals(0L, ref, "failed makeInstance must return a null ref");
        }
        finally
        {
            operationsTestNI.resetFlags();
            ccmCipherNI.ni_dispose(ref);
        }
    }

    @Test
    public void ccm_fetchCipher_failure()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = newCtx();
            // Exercises interface/fips/util/ccm_ctx.c:74
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_CREATE_1);
            int code = ccmCipherNI.ni_init(ref, CCMCipherNI.OP_ENCRYPT, new byte[16], new byte[12], 16);
            Assertions.assertEquals(-4003, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            ccmCipherNI.ni_dispose(ref);
        }
    }

    @Test
    public void ccm_encryptBind_failure()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = newCtx();
            initOk(ref, CCMCipherNI.OP_ENCRYPT);
            // Exercises interface/fips/util/ccm_ctx.c:246
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            int code = ccmCipherNI.ni_doFinal(ref, null, 0, new byte[16], 0, 16, new byte[32], 0);
            Assertions.assertEquals(-4004, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            ccmCipherNI.ni_dispose(ref);
        }
    }

    @Test
    public void ccm_decryptBind_failure()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = newCtx();
            initOk(ref, CCMCipherNI.OP_DECRYPT);
            // Exercises interface/fips/util/ccm_ctx.c:324
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            int code = ccmCipherNI.ni_doFinal(ref, null, 0, new byte[32], 0, 32, new byte[16], 0);
            Assertions.assertEquals(-4005, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            ccmCipherNI.ni_dispose(ref);
        }
    }

    @Test
    public void ccm_setIvLen_failure()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = newCtx();
            initOk(ref, CCMCipherNI.OP_ENCRYPT);
            // Exercises interface/fips/util/ccm_ctx.c:251
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            int code = ccmCipherNI.ni_doFinal(ref, null, 0, new byte[16], 0, 16, new byte[32], 0);
            Assertions.assertEquals(-4006, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            ccmCipherNI.ni_dispose(ref);
        }
    }

    @Test
    public void ccm_decryptSetIvLen_failure()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = newCtx();
            initOk(ref, CCMCipherNI.OP_DECRYPT);
            // Exercises interface/fips/util/ccm_ctx.c:329
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            int code = ccmCipherNI.ni_doFinal(ref, null, 0, new byte[32], 0, 32, new byte[16], 0);
            Assertions.assertEquals(-4018, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            ccmCipherNI.ni_dispose(ref);
        }
    }

    @Test
    public void ccm_encryptSetTag_failure()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = newCtx();
            initOk(ref, CCMCipherNI.OP_ENCRYPT);
            // Exercises interface/fips/util/ccm_ctx.c:258
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);
            int code = ccmCipherNI.ni_doFinal(ref, null, 0, new byte[16], 0, 16, new byte[32], 0);
            Assertions.assertEquals(-4007, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            ccmCipherNI.ni_dispose(ref);
        }
    }

    @Test
    public void ccm_decryptSetTag_failure()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = newCtx();
            initOk(ref, CCMCipherNI.OP_DECRYPT);
            // Exercises interface/fips/util/ccm_ctx.c:336
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);
            int code = ccmCipherNI.ni_doFinal(ref, null, 0, new byte[32], 0, 32, new byte[16], 0);
            Assertions.assertEquals(-4008, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            ccmCipherNI.ni_dispose(ref);
        }
    }

    @Test
    public void ccm_encryptKeyIv_failure()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = newCtx();
            initOk(ref, CCMCipherNI.OP_ENCRYPT);
            // Exercises interface/fips/util/ccm_ctx.c:264
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_4);
            int code = ccmCipherNI.ni_doFinal(ref, null, 0, new byte[16], 0, 16, new byte[32], 0);
            Assertions.assertEquals(-4009, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            ccmCipherNI.ni_dispose(ref);
        }
    }

    @Test
    public void ccm_decryptKeyIv_failure()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = newCtx();
            initOk(ref, CCMCipherNI.OP_DECRYPT);
            // Exercises interface/fips/util/ccm_ctx.c:343
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_4);
            int code = ccmCipherNI.ni_doFinal(ref, null, 0, new byte[32], 0, 32, new byte[16], 0);
            Assertions.assertEquals(-4010, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            ccmCipherNI.ni_dispose(ref);
        }
    }

    @Test
    public void ccm_encryptLenDeclare_failure()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = newCtx();
            initOk(ref, CCMCipherNI.OP_ENCRYPT);
            // Exercises interface/fips/util/ccm_ctx.c:270
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_5);
            int code = ccmCipherNI.ni_doFinal(ref, null, 0, new byte[16], 0, 16, new byte[32], 0);
            Assertions.assertEquals(-4011, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            ccmCipherNI.ni_dispose(ref);
        }
    }

    @Test
    public void ccm_decryptLenDeclare_failure()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = newCtx();
            initOk(ref, CCMCipherNI.OP_DECRYPT);
            // Exercises interface/fips/util/ccm_ctx.c:349
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_5);
            int code = ccmCipherNI.ni_doFinal(ref, null, 0, new byte[32], 0, 32, new byte[16], 0);
            Assertions.assertEquals(-4012, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            ccmCipherNI.ni_dispose(ref);
        }
    }

    @Test
    public void ccm_encryptAad_failure()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = newCtx();
            initOk(ref, CCMCipherNI.OP_ENCRYPT);
            // The AAD step only runs when aad_len > 0.
            // Exercises interface/fips/util/ccm_ctx.c:276
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_6);
            int code = ccmCipherNI.ni_doFinal(ref, new byte[8], 8, new byte[16], 0, 16, new byte[32], 0);
            Assertions.assertEquals(-4013, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            ccmCipherNI.ni_dispose(ref);
        }
    }

    @Test
    public void ccm_decryptAad_failure()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = newCtx();
            initOk(ref, CCMCipherNI.OP_DECRYPT);
            // Exercises interface/fips/util/ccm_ctx.c:355
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_6);
            int code = ccmCipherNI.ni_doFinal(ref, new byte[8], 8, new byte[32], 0, 32, new byte[16], 0);
            Assertions.assertEquals(-4014, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            ccmCipherNI.ni_dispose(ref);
        }
    }

    @Test
    public void ccm_encryptPayload_failure()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = newCtx();
            initOk(ref, CCMCipherNI.OP_ENCRYPT);
            // Exercises interface/fips/util/ccm_ctx.c:282
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_7);
            int code = ccmCipherNI.ni_doFinal(ref, null, 0, new byte[16], 0, 16, new byte[32], 0);
            Assertions.assertEquals(-4015, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            ccmCipherNI.ni_dispose(ref);
        }
    }

    @Test
    public void ccm_encryptFinal_failure()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = newCtx();
            initOk(ref, CCMCipherNI.OP_ENCRYPT);
            // Exercises interface/fips/util/ccm_ctx.c:287
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_8);
            int code = ccmCipherNI.ni_doFinal(ref, null, 0, new byte[16], 0, 16, new byte[32], 0);
            Assertions.assertEquals(-4016, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            ccmCipherNI.ni_dispose(ref);
        }
    }

    @Test
    public void ccm_encryptGetTag_failure()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = newCtx();
            initOk(ref, CCMCipherNI.OP_ENCRYPT);
            // Exercises interface/fips/util/ccm_ctx.c:292
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_9);
            int code = ccmCipherNI.ni_doFinal(ref, null, 0, new byte[16], 0, 16, new byte[32], 0);
            Assertions.assertEquals(-4017, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            ccmCipherNI.ni_dispose(ref);
        }
    }

    // -----------------------------------------------------------------
    // JNI access faults (load_bytearray_ctx). JNI-only.
    // -----------------------------------------------------------------

    @Test
    public void ccm_init_accessKey_failure()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        Assumptions.assumeFalse(Loader.isFFI());
        long ref = 0;
        try
        {
            ref = newCtx();
            // Exercises interface/fips/jni/ccm_ni_jni.c:93
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            int code = ccmCipherNI.ni_init(ref, CCMCipherNI.OP_ENCRYPT, new byte[16], new byte[12], 16);
            Assertions.assertEquals(ErrorCode.JO_FAILED_ACCESS_KEY.getCode(), code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            ccmCipherNI.ni_dispose(ref);
        }
    }

    @Test
    public void ccm_init_accessIv_failure()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        Assumptions.assumeFalse(Loader.isFFI());
        long ref = 0;
        try
        {
            ref = newCtx();
            // Exercises interface/fips/jni/ccm_ni_jni.c:97
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_2);
            int code = ccmCipherNI.ni_init(ref, CCMCipherNI.OP_ENCRYPT, new byte[16], new byte[12], 16);
            Assertions.assertEquals(ErrorCode.JO_FAILED_ACCESS_IV.getCode(), code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            ccmCipherNI.ni_dispose(ref);
        }
    }

    @Test
    public void ccm_doFinal_accessAad_failure()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        Assumptions.assumeFalse(Loader.isFFI());
        long ref = 0;
        try
        {
            ref = newCtx();
            initOk(ref, CCMCipherNI.OP_ENCRYPT);
            // Exercises interface/fips/jni/ccm_ni_jni.c:185
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            int code = ccmCipherNI.ni_doFinal(ref, new byte[8], 8, new byte[16], 0, 16, new byte[32], 0);
            Assertions.assertEquals(ErrorCode.JO_FAILED_ACCESS_INPUT.getCode(), code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            ccmCipherNI.ni_dispose(ref);
        }
    }

    @Test
    public void ccm_doFinal_accessInput_failure()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        Assumptions.assumeFalse(Loader.isFFI());
        long ref = 0;
        try
        {
            ref = newCtx();
            initOk(ref, CCMCipherNI.OP_ENCRYPT);
            // Exercises interface/fips/jni/ccm_ni_jni.c:194
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_2);
            int code = ccmCipherNI.ni_doFinal(ref, null, 0, new byte[16], 0, 16, new byte[32], 0);
            Assertions.assertEquals(ErrorCode.JO_FAILED_ACCESS_INPUT.getCode(), code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            ccmCipherNI.ni_dispose(ref);
        }
    }

    @Test
    public void ccm_doFinal_accessOutput_failure()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        Assumptions.assumeFalse(Loader.isFFI());
        long ref = 0;
        try
        {
            ref = newCtx();
            initOk(ref, CCMCipherNI.OP_ENCRYPT);
            // Exercises interface/fips/jni/ccm_ni_jni.c:202
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_3);
            int code = ccmCipherNI.ni_doFinal(ref, null, 0, new byte[16], 0, 16, new byte[32], 0);
            Assertions.assertEquals(ErrorCode.JO_FAILED_ACCESS_OUTPUT.getCode(), code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            ccmCipherNI.ni_dispose(ref);
        }
    }
}
