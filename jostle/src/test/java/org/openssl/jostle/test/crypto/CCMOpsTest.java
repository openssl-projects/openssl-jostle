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

package org.openssl.jostle.test.crypto;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.blockcipher.CCMCipherNI;
import org.openssl.jostle.util.ops.OperationsTestNI;

import java.security.Security;

/**
 * Fault-injection tests for the CCM authenticated-encryption NI. Each
 * test arms one {@code OPS_*} flag, drives the matching native call via
 * the raw {@code ni_*} surface, and asserts the exact return code.
 *
 * <p>Unlike {@link BlockCipherOpsTest} (which pins the formatted
 * exception message), the CCM sites in {@code interface/util/ccm_ctx.c}
 * carry per-site {@code OPS_OFFSET_*} suffixes so each fault-injection
 * point returns a distinct, disambiguated code. The offsets live in the
 * CCM-private 4000-block; the code is {@code JO_OPENSSL_ERROR (-2)} minus
 * the offset (e.g. offset 4002 → -4004). Pinning the exact code catches a
 * silent renumber of an offset in C without the corresponding test
 * update — the gap the OPS infrastructure exists to detect.
 *
 * <p>The {@code OPS_OPENSSL_ERROR_*}/{@code OPS_FAILED_CREATE_1} sites
 * live in the shared util layer, so these tests run identically on JNI
 * and FFI. The {@code FAILED_ACCESS} tests at the bottom are JNI-only and
 * guard via {@link Loader#isFFI()} because the FFI bridge takes raw
 * pointers rather than {@code load_bytearray_ctx}, so it has no
 * buffer-access fault-injection point.
 */
public class CCMOpsTest
{
    CCMCipherNI ccmCipherNI = TestNISelector.getCCMCipher();
    OperationsTestNI operationsTestNI = TestNISelector.getOperationsTestNI();

    @BeforeAll
    public static void beforeAll()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

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

    /** Init AES-128-CCM (16-byte key, 12-byte nonce, 16-byte tag); must precede arming the flag. */
    private void initOk(long ref, int opMode)
    {
        Assertions.assertEquals(0,
                ccmCipherNI.ni_init(ref, opMode, new byte[16], new byte[12], 16),
                "ni_init should succeed before the OPS flag is armed");
    }

    // -----------------------------------------------------------------
    // ccm_ctx_create — EVP_CIPHER_CTX_new allocation failure
    // -----------------------------------------------------------------

    /**
     * ccm_ctx_create's EVP_CIPHER_CTX_new() failure path. The flag is armed
     * BEFORE ni_makeInstance because create is the only call that allocates
     * the EVP_CIPHER_CTX. Shared util site, so this runs on JNI and FFI.
     */
    @Test
    public void ccm_makeInstance_ctxNew_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        int[] err = new int[1];
        try
        {
            // Exercises interface/util/ccm_ctx.c:105
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

    // -----------------------------------------------------------------
    // ccm_fetch_evp_cipher — fetch failure (init probe-fetch path)
    // -----------------------------------------------------------------

    @Test
    public void ccm_fetchCipher_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = newCtx();
            // Exercises interface/util/ccm_ctx.c:74
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

    // -----------------------------------------------------------------
    // ccm_do_one_shot — EVP sequence, encrypt + decrypt sites
    // -----------------------------------------------------------------

    @Test
    public void ccm_encryptBind_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = newCtx();
            initOk(ref, CCMCipherNI.OP_ENCRYPT);
            // Exercises interface/util/ccm_ctx.c:246
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
    public void ccm_decryptBind_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = newCtx();
            initOk(ref, CCMCipherNI.OP_DECRYPT);
            // Exercises interface/util/ccm_ctx.c:324
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
    public void ccm_setIvLen_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = newCtx();
            initOk(ref, CCMCipherNI.OP_ENCRYPT);
            // Exercises interface/util/ccm_ctx.c:251
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
    public void ccm_decryptSetIvLen_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = newCtx();
            initOk(ref, CCMCipherNI.OP_DECRYPT);
            // Exercises interface/util/ccm_ctx.c:329
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
    public void ccm_encryptSetTag_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = newCtx();
            initOk(ref, CCMCipherNI.OP_ENCRYPT);
            // Exercises interface/util/ccm_ctx.c:258
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
    public void ccm_decryptSetTag_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = newCtx();
            initOk(ref, CCMCipherNI.OP_DECRYPT);
            // Exercises interface/util/ccm_ctx.c:336
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
    public void ccm_encryptKeyIv_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = newCtx();
            initOk(ref, CCMCipherNI.OP_ENCRYPT);
            // Exercises interface/util/ccm_ctx.c:264
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
    public void ccm_decryptKeyIv_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = newCtx();
            initOk(ref, CCMCipherNI.OP_DECRYPT);
            // Exercises interface/util/ccm_ctx.c:343
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
    public void ccm_encryptLenDeclare_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = newCtx();
            initOk(ref, CCMCipherNI.OP_ENCRYPT);
            // Exercises interface/util/ccm_ctx.c:270
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
    public void ccm_decryptLenDeclare_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = newCtx();
            initOk(ref, CCMCipherNI.OP_DECRYPT);
            // Exercises interface/util/ccm_ctx.c:349
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
    public void ccm_encryptAad_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = newCtx();
            initOk(ref, CCMCipherNI.OP_ENCRYPT);
            // The AAD step only runs when aad_len > 0.
            // Exercises interface/util/ccm_ctx.c:276
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
    public void ccm_decryptAad_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = newCtx();
            initOk(ref, CCMCipherNI.OP_DECRYPT);
            // Exercises interface/util/ccm_ctx.c:355
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
    public void ccm_encryptPayload_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = newCtx();
            initOk(ref, CCMCipherNI.OP_ENCRYPT);
            // Exercises interface/util/ccm_ctx.c:282
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
    public void ccm_encryptFinal_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = newCtx();
            initOk(ref, CCMCipherNI.OP_ENCRYPT);
            // Exercises interface/util/ccm_ctx.c:287
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
    public void ccm_encryptGetTag_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = newCtx();
            initOk(ref, CCMCipherNI.OP_ENCRYPT);
            // Exercises interface/util/ccm_ctx.c:292
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
    // JNI access faults (load_bytearray_ctx). JNI-only — the FFI bridge
    // receives raw pointers and has no such fault-injection point.
    // These sites have no OPS_OFFSET macro, so they return the base
    // JO_FAILED_ACCESS_* code rather than an offset-disambiguated one.
    // -----------------------------------------------------------------

    @Test
    public void ccm_init_accessKey_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        Assumptions.assumeFalse(Loader.isFFI());
        long ref = 0;
        try
        {
            ref = newCtx();
            // Exercises interface/jni/ccm_ni_jni.c:88
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
    public void ccm_init_accessIv_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        Assumptions.assumeFalse(Loader.isFFI());
        long ref = 0;
        try
        {
            ref = newCtx();
            // Exercises interface/jni/ccm_ni_jni.c:92
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
    public void ccm_doFinal_accessAad_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        Assumptions.assumeFalse(Loader.isFFI());
        long ref = 0;
        try
        {
            ref = newCtx();
            initOk(ref, CCMCipherNI.OP_ENCRYPT);
            // AAD must be non-null to reach the aad load.
            // Exercises interface/jni/ccm_ni_jni.c:174
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
    public void ccm_doFinal_accessInput_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        Assumptions.assumeFalse(Loader.isFFI());
        long ref = 0;
        try
        {
            ref = newCtx();
            initOk(ref, CCMCipherNI.OP_ENCRYPT);
            // aad null so the aad load is skipped; the input load fires.
            // Exercises interface/jni/ccm_ni_jni.c:183
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
    public void ccm_doFinal_accessOutput_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        Assumptions.assumeFalse(Loader.isFFI());
        long ref = 0;
        try
        {
            ref = newCtx();
            initOk(ref, CCMCipherNI.OP_ENCRYPT);
            // aad null, input valid; the output load fires.
            // Exercises interface/jni/ccm_ni_jni.c:191
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
