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

package org.openssl.jostle.test.ec;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.OpenSSL;
import org.openssl.jostle.jcajce.provider.ec.ECServiceNI;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.test.crypto.TestNISelector;
import org.openssl.jostle.util.ops.OperationsTestNI;

import java.security.Security;

/**
 * Fault-injection tests for the EC NI layer.
 *
 * <p>Each test sets exactly one {@code OPS_*} flag in the C-side
 * instrumentation, drives the matching native function through the
 * raw {@code ni_*} entry points (so the integer error code is observable
 * directly rather than wrapped in an exception), and asserts the
 * resulting code matches the expected
 * {@code JO_OPENSSL_ERROR + (-offset)} value.
 *
 * <p>All tests are guarded by {@link OperationsTestNI#opsTestAvailable()}
 * so they no-op on a release native build.
 *
 * <h2>Target map: offset → {@code interface/util/ec.c} fault-injection line</h2>
 *
 * <p>Each test method's Javadoc names the exact C line of its target —
 * the line containing the {@code OPS_OPENSSL_ERROR_N} macro that the
 * test trips. The summary below lets you cross-reference offset numbers
 * against the C source without opening each test:
 *
 * <pre>
 *   Offset  ec.c line  Function                          Trigger
 *   ----------------------------------------------------------------------------
 *   3000    127        ec_generate_key                   EVP_PKEY_CTX_new_from_name == NULL
 *   3001    132        ec_generate_key                   EVP_PKEY_keygen_init failed
 *   3002    142        ec_generate_key                   EVP_PKEY_CTX_set_params failed
 *   3003    151        ec_generate_key                   EVP_PKEY_keygen failed
 *   3004    156        ec_generate_key                   spec-&gt;key == NULL after keygen
 *
 *   3010    333        ec_make_private_from_components   BN_bin2bn == NULL
 *   3011    339        ec_make_private_from_components   OSSL_PARAM_BLD_new == NULL
 *   3012    344        ec_make_private_from_components   OSSL_PARAM_BLD_push_utf8_string failed
 *   3013    349        ec_make_private_from_components   OSSL_PARAM_BLD_push_BN failed
 *   3014    356        ec_make_private_from_components   OSSL_PARAM_BLD_to_param == NULL
 *   3015    363        ec_make_private_from_components   EVP_PKEY_CTX_new_from_name == NULL
 *   3016    368        ec_make_private_from_components   EVP_PKEY_fromdata_init failed
 *   3017    379        ec_make_private_from_components   EVP_PKEY_fromdata failed
 *   3018    385        ec_make_private_from_components   pkey == NULL after fromdata
 *
 *   3020    469        ec_ctx_init_sign                  EVP_MD_CTX_new == NULL
 *   3021    474        ec_ctx_init_sign                  EVP_DigestSignInit_ex failed
 *
 *   3030    525        ec_ctx_init_verify                EVP_MD_CTX_new == NULL
 *   3031    530        ec_ctx_init_verify                EVP_DigestVerifyInit_ex failed
 *
 *   3040    567        ec_ctx_update (sign mode)         EVP_DigestSignUpdate failed
 *   3041    572        ec_ctx_update (verify mode)       EVP_DigestVerifyUpdate failed
 *
 *   3050    602        ec_ctx_sign (NULL-buffer probe)   EVP_DigestSignFinal failed
 *   3051    626        ec_ctx_sign (real-buffer fetch)   EVP_DigestSignFinal failed
 *
 *   3060    667        ec_ctx_verify                     forced EVP_DigestVerifyFinal == 0
 *
 *   3070    739        ec_kex_init                       EVP_PKEY_CTX_new == NULL
 *   3071    743        ec_kex_init                       EVP_PKEY_derive_init failed
 *
 *   3080    786        ec_kex_set_peer                   EVP_PKEY_derive_set_peer failed
 *
 *   3090    819        ec_kex_derive (NULL-buffer probe) EVP_PKEY_derive failed (flag _2)
 *   3091    836        ec_kex_derive (real-buffer fetch) EVP_PKEY_derive failed (flag _3)
 *
 *   3100    180        get_curve_name_component          EVP_PKEY_get_utf8_string_param probe failed
 *   3101    200        get_curve_name_component          OPENSSL_malloc == NULL
 *   3102    205        get_curve_name_component          EVP_PKEY_get_utf8_string_param fetch failed
 *
 *   3110    228        get_bn_component                  EVP_PKEY_get_bn_param failed
 *   3111    233        get_bn_component                  defensive BN_num_bytes &lt; 0
 *   3112    249        get_bn_component                  defensive BN_bn2bin &lt; 0
 *
 *   --      187        get_curve_name_component          name_len &gt; INT32_MAX (flag INT32_OVERFLOW_1, returns JO_OUTPUT_TOO_LONG_INT32)
 *   --      607        ec_ctx_sign                       sig_len &gt; INT32_MAX  (flag INT32_OVERFLOW_1, returns JO_OUTPUT_TOO_LONG_INT32)
 *   --      823        ec_kex_derive (probe path)        need    &gt; INT32_MAX (flag INT32_OVERFLOW_1, returns JO_OUTPUT_TOO_LONG_INT32)
 *   --      840        ec_kex_derive (fetch path)        written &gt; INT32_MAX (flag INT32_OVERFLOW_2, returns JO_OUTPUT_TOO_LONG_INT32)
 *
 * INT32_OVERFLOW sites return a fixed {@code JO_OUTPUT_TOO_LONG_INT32} (-20)
 * with no offset multiplexing; tests distinguish sites by which flag is set
 * and which call path was driven. The "offset" column is "--" for these
 * because there's no error-code offset to assert.
 * </pre>
 */
public class ECOpsTest
{
    private static final int JO_OPENSSL_ERROR = -2;
    private static final int JO_OUTPUT_TOO_LONG_INT32 = -20;
    private static final int JO_UNABLE_TO_ACCESS_NAME = -89;

    private final ECServiceNI ec = TestNISelector.getECNi();
    private final SpecNI specNI = TestNISelector.getSpecNI();
    private final OperationsTestNI ops = TestNISelector.getOperationsTestNI();


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
        if (ops.opsTestAvailable())
        {
            ops.resetFlags();
        }
    }

    /** Expected code when a fault site at {@code offset} fires. */
    private static int errorAt(int offset)
    {
        return JO_OPENSSL_ERROR - offset;
    }


    // -----------------------------------------------------------------
    // ec_generate_key
    // -----------------------------------------------------------------

    /**
     * Target: {@code interface/util/ec.c:127} (offset 3000) — fault-injects the
     * {@code EVP_PKEY_CTX_new_from_name == NULL} branch inside
     * {@code ec_generate_key} (defined at {@code ec.c:112}).
     */
    @Test
    public void ec_generateKeyPair_ctxNewFromName_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);

        int[] err = new int[1];
        long ref = ec.ni_generateKeyPair("P-256", err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(3000), err[0]);
    }

    /**
     * Target: {@code interface/util/ec.c:132} (offset 3001) — fault-injects the
     * {@code EVP_PKEY_keygen_init} failure branch inside {@code ec_generate_key}
     * (defined at {@code ec.c:112}).
     */
    @Test
    public void ec_generateKeyPair_keygenInit_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);

        int[] err = new int[1];
        long ref = ec.ni_generateKeyPair("P-256", err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(3001), err[0]);
    }

    /**
     * Target: {@code interface/util/ec.c:142} (offset 3002) — fault-injects the
     * {@code EVP_PKEY_CTX_set_params} failure branch inside
     * {@code ec_generate_key} (defined at {@code ec.c:112}).
     */
    @Test
    public void ec_generateKeyPair_setParams_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);

        int[] err = new int[1];
        long ref = ec.ni_generateKeyPair("P-256", err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(3002), err[0]);
    }

    /**
     * Target: {@code interface/util/ec.c:151} (offset 3003) — fault-injects the
     * {@code EVP_PKEY_keygen} failure branch inside {@code ec_generate_key}
     * (defined at {@code ec.c:112}).
     */
    @Test
    public void ec_generateKeyPair_keygen_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_4);

        int[] err = new int[1];
        long ref = ec.ni_generateKeyPair("P-256", err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(3003), err[0]);
    }

    /**
     * Target: {@code interface/util/ec.c:156} (offset 3004) — fault-injects the
     * post-keygen {@code spec->key == NULL} sanity check inside
     * {@code ec_generate_key} (defined at {@code ec.c:112}).
     */
    @Test
    public void ec_generateKeyPair_specKeyNull_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_5);

        int[] err = new int[1];
        long ref = ec.ni_generateKeyPair("P-256", err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(3004), err[0]);
    }


    // -----------------------------------------------------------------
    // ec_make_private_from_components
    // -----------------------------------------------------------------

    private static byte[] sampleScalar()
    {
        // Any non-zero 32-byte scalar (smaller than P-256 order); the
        // value doesn't matter — the OPS flag forces failure before
        // OpenSSL evaluates whether the scalar is in range.
        byte[] s = new byte[32];
        s[31] = 0x01;
        return s;
    }

    /**
     * Target: {@code interface/util/ec.c:333} (offset 3010) — fault-injects the
     * {@code BN_bin2bn == NULL} branch (scalar conversion) inside
     * {@code ec_make_private_from_components} (defined at {@code ec.c:302}).
     */
    @Test
    public void ec_makePrivate_bnBin2bn_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_6);

        int[] err = new int[1];
        long ref = ec.ni_makePrivateFromComponents("P-256", sampleScalar(),
                err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(3010), err[0]);
    }

    /**
     * Target: {@code interface/util/ec.c:339} (offset 3011) — fault-injects the
     * {@code OSSL_PARAM_BLD_new == NULL} branch inside
     * {@code ec_make_private_from_components} (defined at {@code ec.c:302}).
     */
    @Test
    public void ec_makePrivate_paramBldNew_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_7);

        int[] err = new int[1];
        long ref = ec.ni_makePrivateFromComponents("P-256", sampleScalar(),
                err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(3011), err[0]);
    }

    /**
     * Target: {@code interface/util/ec.c:344} (offset 3012) — fault-injects the
     * {@code OSSL_PARAM_BLD_push_utf8_string} failure branch (push of
     * {@code OSSL_PKEY_PARAM_GROUP_NAME}) inside
     * {@code ec_make_private_from_components} (defined at {@code ec.c:302}).
     */
    @Test
    public void ec_makePrivate_pushUtf8String_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_8);

        int[] err = new int[1];
        long ref = ec.ni_makePrivateFromComponents("P-256", sampleScalar(),
                err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(3012), err[0]);
    }

    /**
     * Target: {@code interface/util/ec.c:349} (offset 3013) — fault-injects the
     * {@code OSSL_PARAM_BLD_push_BN} failure branch (push of
     * {@code OSSL_PKEY_PARAM_PRIV_KEY}) inside
     * {@code ec_make_private_from_components} (defined at {@code ec.c:302}).
     */
    @Test
    public void ec_makePrivate_pushBN_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_9);

        int[] err = new int[1];
        long ref = ec.ni_makePrivateFromComponents("P-256", sampleScalar(),
                err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(3013), err[0]);
    }

    /**
     * Target: {@code interface/util/ec.c:356} (offset 3014) — fault-injects the
     * {@code OSSL_PARAM_BLD_to_param == NULL} branch inside
     * {@code ec_make_private_from_components} (defined at {@code ec.c:302}).
     */
    @Test
    public void ec_makePrivate_bldToParam_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_10);

        int[] err = new int[1];
        long ref = ec.ni_makePrivateFromComponents("P-256", sampleScalar(),
                err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(3014), err[0]);
    }

    /**
     * Target: {@code interface/util/ec.c:363} (offset 3015) — fault-injects the
     * {@code EVP_PKEY_CTX_new_from_name == NULL} branch (fromdata ctx alloc)
     * inside {@code ec_make_private_from_components} (defined at
     * {@code ec.c:302}).
     */
    @Test
    public void ec_makePrivate_ctxNewFromName_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_11);

        int[] err = new int[1];
        long ref = ec.ni_makePrivateFromComponents("P-256", sampleScalar(),
                err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(3015), err[0]);
    }

    /**
     * Target: {@code interface/util/ec.c:368} (offset 3016) — fault-injects the
     * {@code EVP_PKEY_fromdata_init} failure branch inside
     * {@code ec_make_private_from_components} (defined at {@code ec.c:302}).
     */
    @Test
    public void ec_makePrivate_fromdataInit_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_12);

        int[] err = new int[1];
        long ref = ec.ni_makePrivateFromComponents("P-256", sampleScalar(),
                err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(3016), err[0]);
    }

    /**
     * Target: {@code interface/util/ec.c:379} (offset 3017) — fault-injects the
     * {@code EVP_PKEY_fromdata} failure branch inside
     * {@code ec_make_private_from_components} (defined at {@code ec.c:302}).
     * Reuses flag {@code OPS_OPENSSL_ERROR_1}; the same flag would fire at
     * offset 3000 in {@code ec_generate_key} but that function isn't entered
     * here.
     */
    @Test
    public void ec_makePrivate_fromdata_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);

        int[] err = new int[1];
        long ref = ec.ni_makePrivateFromComponents("P-256", sampleScalar(),
                err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        // OPS_OPENSSL_ERROR_1 here fires at make_private offset 3017,
        // not the ec_generate_key 3000 site (different function entered).
        Assertions.assertEquals(errorAt(3017), err[0]);
    }

    /**
     * Target: {@code interface/util/ec.c:385} (offset 3018) — fault-injects the
     * post-fromdata {@code pkey == NULL} sanity check inside
     * {@code ec_make_private_from_components} (defined at {@code ec.c:302}).
     */
    @Test
    public void ec_makePrivate_pkeyNull_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);

        int[] err = new int[1];
        long ref = ec.ni_makePrivateFromComponents("P-256", sampleScalar(),
                err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(3018), err[0]);
    }


    // -----------------------------------------------------------------
    // ec_ctx_init_sign / init_verify
    // -----------------------------------------------------------------

    /**
     * Target: {@code interface/util/ec.c:469} (offset 3020) — fault-injects the
     * {@code EVP_MD_CTX_new == NULL} branch inside {@code ec_ctx_init_sign}
     * (defined at {@code ec.c:434}).
     */
    @Test
    public void ec_initSign_mdCtxNew_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        long sigRef = ec.allocateSigner();
        long keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
        try
        {
            OpenSSL.getOpenSSLErrors();
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);
            int code = ec.ni_initSign(sigRef, keyRef, "SHA-256", TestUtil.RNDSrc);
            Assertions.assertEquals(errorAt(3020), code);
        }
        finally
        {
            ec.disposeSigner(sigRef);
            specNI.dispose(keyRef);
        }
    }

    /**
     * Target: {@code interface/util/ec.c:474} (offset 3021) — fault-injects the
     * {@code EVP_DigestSignInit_ex} failure branch inside {@code ec_ctx_init_sign}
     * (defined at {@code ec.c:434}).
     */
    @Test
    public void ec_initSign_digestSignInit_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        long sigRef = ec.allocateSigner();
        long keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
        try
        {
            OpenSSL.getOpenSSLErrors();
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_4);
            int code = ec.ni_initSign(sigRef, keyRef, "SHA-256", TestUtil.RNDSrc);
            Assertions.assertEquals(errorAt(3021), code);
        }
        finally
        {
            ec.disposeSigner(sigRef);
            specNI.dispose(keyRef);
        }
    }

    /**
     * Target: {@code interface/util/ec.c:525} (offset 3030) — fault-injects the
     * {@code EVP_MD_CTX_new == NULL} branch inside {@code ec_ctx_init_verify}
     * (defined at {@code ec.c:495}).
     */
    @Test
    public void ec_initVerify_mdCtxNew_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        long sigRef = ec.allocateSigner();
        long keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
        try
        {
            OpenSSL.getOpenSSLErrors();
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_5);
            int code = ec.ni_initVerify(sigRef, keyRef, "SHA-256");
            Assertions.assertEquals(errorAt(3030), code);
        }
        finally
        {
            ec.disposeSigner(sigRef);
            specNI.dispose(keyRef);
        }
    }

    /**
     * Target: {@code interface/util/ec.c:530} (offset 3031) — fault-injects the
     * {@code EVP_DigestVerifyInit_ex} failure branch inside
     * {@code ec_ctx_init_verify} (defined at {@code ec.c:495}).
     */
    @Test
    public void ec_initVerify_digestVerifyInit_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        long sigRef = ec.allocateSigner();
        long keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
        try
        {
            OpenSSL.getOpenSSLErrors();
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_6);
            int code = ec.ni_initVerify(sigRef, keyRef, "SHA-256");
            Assertions.assertEquals(errorAt(3031), code);
        }
        finally
        {
            ec.disposeSigner(sigRef);
            specNI.dispose(keyRef);
        }
    }


    // -----------------------------------------------------------------
    // ec_ctx_update / sign / verify
    // -----------------------------------------------------------------

    /**
     * Target: {@code interface/util/ec.c:567} (offset 3040) — fault-injects the
     * {@code EVP_DigestSignUpdate} failure branch in the sign-mode arm of
     * {@code ec_ctx_update} (defined at {@code ec.c:549}). Driven by an
     * {@code ec_ctx_init_sign}-initialised context.
     */
    @Test
    public void ec_update_signMode_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        long sigRef = ec.allocateSigner();
        long keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
        try
        {
            ec.initSign(sigRef, keyRef, "SHA-256", TestUtil.RNDSrc);
            OpenSSL.getOpenSSLErrors();
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_7);
            int code = ec.ni_update(sigRef, new byte[]{0x01, 0x02}, 0, 2);
            Assertions.assertEquals(errorAt(3040), code);
        }
        finally
        {
            ec.disposeSigner(sigRef);
            specNI.dispose(keyRef);
        }
    }

    /**
     * Target: {@code interface/util/ec.c:572} (offset 3041) — fault-injects the
     * {@code EVP_DigestVerifyUpdate} failure branch in the verify-mode arm of
     * {@code ec_ctx_update} (defined at {@code ec.c:549}). Driven by an
     * {@code ec_ctx_init_verify}-initialised context (same OPS flag as the
     * sign-mode test; the active mode picks the branch).
     */
    @Test
    public void ec_update_verifyMode_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        long sigRef = ec.allocateSigner();
        long keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
        try
        {
            ec.initVerify(sigRef, keyRef, "SHA-256");
            OpenSSL.getOpenSSLErrors();
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_7);
            int code = ec.ni_update(sigRef, new byte[]{0x01, 0x02}, 0, 2);
            Assertions.assertEquals(errorAt(3041), code);
        }
        finally
        {
            ec.disposeSigner(sigRef);
            specNI.dispose(keyRef);
        }
    }

    /**
     * Target: {@code interface/util/ec.c:602} (offset 3050) — fault-injects the
     * {@code EVP_DigestSignFinal} failure branch on the NULL-buffer length
     * probe call inside {@code ec_ctx_sign} (defined at {@code ec.c:584}).
     * Caller passes {@code out == NULL} so the probe is the only call made.
     */
    @Test
    public void ec_sign_digestSignFinalProbe_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        long sigRef = ec.allocateSigner();
        long keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
        try
        {
            ec.initSign(sigRef, keyRef, "SHA-256", TestUtil.RNDSrc);
            ec.update(sigRef, new byte[]{0x01}, 0, 1);
            OpenSSL.getOpenSSLErrors();
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_8);
            // First call (probe with NULL out) hits the flag.
            int code = ec.ni_sign(sigRef, null, 0, TestUtil.RNDSrc);
            Assertions.assertEquals(errorAt(3050), code);
        }
        finally
        {
            ec.disposeSigner(sigRef);
            specNI.dispose(keyRef);
        }
    }

    /**
     * Target: {@code interface/util/ec.c:626} (offset 3051) — fault-injects the
     * {@code EVP_DigestSignFinal} failure branch on the real-buffer write call
     * inside {@code ec_ctx_sign} (defined at {@code ec.c:584}). The probe call
     * at {@code ec.c:602} succeeds because its flag ({@code _8}) is not set;
     * the fetch flag ({@code _9}) only fires the second time round.
     */
    @Test
    public void ec_sign_digestSignFinalFetch_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        long sigRef = ec.allocateSigner();
        long keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
        try
        {
            ec.initSign(sigRef, keyRef, "SHA-256", TestUtil.RNDSrc);
            ec.update(sigRef, new byte[]{0x01}, 0, 1);
            OpenSSL.getOpenSSLErrors();
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_9);
            // Real-buffer call: probe (flag _8) succeeds normally,
            // fetch (flag _9) faults.
            int code = ec.ni_sign(sigRef, new byte[128], 0, TestUtil.RNDSrc);
            Assertions.assertEquals(errorAt(3051), code);
        }
        finally
        {
            ec.disposeSigner(sigRef);
            specNI.dispose(keyRef);
        }
    }

    /**
     * Target: {@code interface/util/ec.c:667} (offset 3060) — fault-injects the
     * forced {@code EVP_DigestVerifyFinal == 0} branch (impossible-to-trigger
     * verify failure on a valid-signature input path) inside
     * {@code ec_ctx_verify} (defined at {@code ec.c:635}). Unlike the other
     * sites the macro forces the success-by-zero return path, exercising the
     * "verify returned false" code rather than a hard OpenSSL error.
     */
    @Test
    public void ec_verify_digestVerifyFinal_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        long sigRef = ec.allocateSigner();
        long keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
        try
        {
            ec.initVerify(sigRef, keyRef, "SHA-256");
            ec.update(sigRef, new byte[]{0x01}, 0, 1);
            OpenSSL.getOpenSSLErrors();
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_10);
            int code = ec.ni_verify(sigRef, new byte[64], 64, TestUtil.RNDSrc);
            Assertions.assertEquals(errorAt(3060), code);
        }
        finally
        {
            ec.disposeSigner(sigRef);
            specNI.dispose(keyRef);
        }
    }


    // -----------------------------------------------------------------
    // ec_kex_init / set_peer / derive
    // -----------------------------------------------------------------

    /**
     * Target: {@code interface/util/ec.c:739} (offset 3070) — fault-injects the
     * {@code EVP_PKEY_CTX_new == NULL} branch (kex ctx allocation) inside
     * {@code ec_kex_init} (defined at {@code ec.c:711}).
     */
    @Test
    public void ec_kexInit_ctxNewFromPkey_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        long kexRef = ec.allocateKex();
        long keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
        try
        {
            OpenSSL.getOpenSSLErrors();
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_11);
            int code = ec.ni_kexInit(kexRef, keyRef, TestUtil.RNDSrc);
            Assertions.assertEquals(errorAt(3070), code);
        }
        finally
        {
            ec.disposeKex(kexRef);
            specNI.dispose(keyRef);
        }
    }

    /**
     * Target: {@code interface/util/ec.c:743} (offset 3071) — fault-injects the
     * {@code EVP_PKEY_derive_init} failure branch inside {@code ec_kex_init}
     * (defined at {@code ec.c:711}).
     */
    @Test
    public void ec_kexInit_deriveInit_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        long kexRef = ec.allocateKex();
        long keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
        try
        {
            OpenSSL.getOpenSSLErrors();
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_12);
            int code = ec.ni_kexInit(kexRef, keyRef, TestUtil.RNDSrc);
            Assertions.assertEquals(errorAt(3071), code);
        }
        finally
        {
            ec.disposeKex(kexRef);
            specNI.dispose(keyRef);
        }
    }

    /**
     * Target: {@code interface/util/ec.c:786} (offset 3080) — fault-injects the
     * {@code EVP_PKEY_derive_set_peer} failure branch inside
     * {@code ec_kex_set_peer} (defined at {@code ec.c:753}). Reuses flag
     * {@code OPS_OPENSSL_ERROR_1}; earlier sites (e.g. {@code ec_generate_key}
     * offset 3000) have already returned by the time the flag is set.
     */
    @Test
    public void ec_kexSetPeer_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        long kexRef = ec.allocateKex();
        long keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
        long peerRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
        try
        {
            ec.kexInit(kexRef, keyRef, TestUtil.RNDSrc);
            OpenSSL.getOpenSSLErrors();
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            int code = ec.ni_kexSetPeer(kexRef, peerRef, TestUtil.RNDSrc);
            // OPS_OPENSSL_ERROR_1 fires at kex_set_peer offset 3080
            // (not at the ec_generate_key sites — those have already
            // returned by the time this flag is set).
            Assertions.assertEquals(errorAt(3080), code);
        }
        finally
        {
            ec.disposeKex(kexRef);
            specNI.dispose(keyRef);
            specNI.dispose(peerRef);
        }
    }

    /**
     * Target: {@code interface/util/ec.c:819} (offset 3090) — fault-injects the
     * {@code EVP_PKEY_derive} failure branch on the NULL-buffer length probe
     * inside {@code ec_kex_derive} (defined at {@code ec.c:796}). Caller passes
     * {@code out == NULL} so only the probe runs.
     */
    @Test
    public void ec_kexDerive_probe_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        long kexRef = ec.allocateKex();
        long keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
        long peerRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
        try
        {
            ec.kexInit(kexRef, keyRef, TestUtil.RNDSrc);
            ec.kexSetPeer(kexRef, peerRef, TestUtil.RNDSrc);
            OpenSSL.getOpenSSLErrors();
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            int code = ec.ni_kexDerive(kexRef, null, 0, TestUtil.RNDSrc);
            Assertions.assertEquals(errorAt(3090), code);
        }
        finally
        {
            ec.disposeKex(kexRef);
            specNI.dispose(keyRef);
            specNI.dispose(peerRef);
        }
    }

    /**
     * Target: {@code interface/util/ec.c:836} (offset 3091) — fault-injects the
     * fetch-side {@code EVP_PKEY_derive} call inside {@code ec_kex_derive}
     * (defined at {@code ec.c:796}). Probe (flag {@code _2}) is not set so
     * the probe at offset 3090 runs normally; the fetch flag ({@code _3})
     * fires the second derive call. This mirrors the {@code _8} / {@code _9}
     * split used by {@code ec_ctx_sign}'s pair of {@code EVP_DigestSignFinal}
     * calls.
     */
    @Test
    public void ec_kexDerive_fetch_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        long kexRef = ec.allocateKex();
        long keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
        long peerRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
        try
        {
            ec.kexInit(kexRef, keyRef, TestUtil.RNDSrc);
            ec.kexSetPeer(kexRef, peerRef, TestUtil.RNDSrc);
            OpenSSL.getOpenSSLErrors();
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);
            int code = ec.ni_kexDerive(kexRef, new byte[64], 0, TestUtil.RNDSrc);
            Assertions.assertEquals(errorAt(3091), code);
        }
        finally
        {
            ec.disposeKex(kexRef);
            specNI.dispose(keyRef);
            specNI.dispose(peerRef);
        }
    }


    // -----------------------------------------------------------------
    // ec_get_component — internal helpers get_curve_name_component
    //                    and get_bn_component
    // -----------------------------------------------------------------

    /**
     * Target: {@code interface/util/ec.c:180} (offset 3100) — fault-injects the
     * length-probe call to {@code EVP_PKEY_get_utf8_string_param} inside
     * {@code get_curve_name_component} (defined at {@code ec.c:177}). This is
     * the first OpenSSL call in the curve-name getter; it fires regardless of
     * whether the caller passed a NULL or real output buffer.
     */
    @Test
    public void ec_getComponent_curveName_probe_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        long keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
        try
        {
            OpenSSL.getOpenSSLErrors();
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            int code = ec.ni_getComponent(keyRef, ECServiceNI.COMP_CURVE_NAME,
                    new byte[64]);
            Assertions.assertEquals(errorAt(3100), code);
        }
        finally
        {
            specNI.dispose(keyRef);
        }
    }

    /**
     * Target: {@code interface/util/ec.c:200} (offset 3101) — fault-injects the
     * {@code OPENSSL_malloc == NULL} branch (temp buffer for the curve-name
     * UTF-8 fetch) inside {@code get_curve_name_component} (defined at
     * {@code ec.c:177}). Only reachable when the caller passes a non-NULL
     * output buffer at least as large as the curve name itself.
     */
    @Test
    public void ec_getComponent_curveName_malloc_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        long keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
        try
        {
            OpenSSL.getOpenSSLErrors();
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            int code = ec.ni_getComponent(keyRef, ECServiceNI.COMP_CURVE_NAME,
                    new byte[64]);
            Assertions.assertEquals(errorAt(3101), code);
        }
        finally
        {
            specNI.dispose(keyRef);
        }
    }

    /**
     * Target: {@code interface/util/ec.c:205} (offset 3102) — fault-injects the
     * fetch-side call to {@code EVP_PKEY_get_utf8_string_param} (the one that
     * actually copies the curve name into the temp buffer) inside
     * {@code get_curve_name_component} (defined at {@code ec.c:177}). The probe
     * call at offset 3100 succeeds because its flag ({@code _1}) is not set;
     * only the fetch flag ({@code _3}) fires.
     */
    @Test
    public void ec_getComponent_curveName_fetch_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        long keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
        try
        {
            OpenSSL.getOpenSSLErrors();
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);
            int code = ec.ni_getComponent(keyRef, ECServiceNI.COMP_CURVE_NAME,
                    new byte[64]);
            Assertions.assertEquals(errorAt(3102), code);
        }
        finally
        {
            specNI.dispose(keyRef);
        }
    }

    /**
     * Target: {@code interface/util/ec.c:228} (offset 3110) — fault-injects the
     * {@code EVP_PKEY_get_bn_param} failure branch inside
     * {@code get_bn_component} (defined at {@code ec.c:223}). The first
     * OpenSSL call in the BIGNUM-component path; fires for any of
     * {@code COMP_PUBLIC_X / _Y / PRIVATE_VALUE}. We drive the public-X branch.
     */
    @Test
    public void ec_getComponent_bn_getBnParam_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        long keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
        try
        {
            OpenSSL.getOpenSSLErrors();
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_4);
            int code = ec.ni_getComponent(keyRef, ECServiceNI.COMP_PUBLIC_X,
                    new byte[64]);
            Assertions.assertEquals(errorAt(3110), code);
        }
        finally
        {
            specNI.dispose(keyRef);
        }
    }

    /**
     * Target: {@code interface/util/ec.c:233} (offset 3111) — fault-injects the
     * defensive {@code BN_num_bytes < 0} branch inside {@code get_bn_component}
     * (defined at {@code ec.c:223}). The real call can't return negative for
     * a valid BIGNUM, but the defensive check is OPS-instrumented so the
     * failure path is reachable from a test.
     */
    @Test
    public void ec_getComponent_bn_bnNumBytes_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        long keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
        try
        {
            OpenSSL.getOpenSSLErrors();
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_5);
            int code = ec.ni_getComponent(keyRef, ECServiceNI.COMP_PUBLIC_X,
                    new byte[64]);
            Assertions.assertEquals(errorAt(3111), code);
        }
        finally
        {
            specNI.dispose(keyRef);
        }
    }

    /**
     * Target: {@code interface/util/ec.c:249} (offset 3112) — fault-injects the
     * defensive {@code BN_bn2bin < 0} branch (real-buffer write) inside
     * {@code get_bn_component} (defined at {@code ec.c:223}). Only reachable
     * with a non-NULL, sufficiently-large output buffer.
     */
    @Test
    public void ec_getComponent_bn_bn2bin_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        long keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
        try
        {
            OpenSSL.getOpenSSLErrors();
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_6);
            int code = ec.ni_getComponent(keyRef, ECServiceNI.COMP_PUBLIC_X,
                    new byte[64]);
            Assertions.assertEquals(errorAt(3112), code);
        }
        finally
        {
            specNI.dispose(keyRef);
        }
    }


    // -----------------------------------------------------------------
    // INT32_MAX defensive checks on OpenSSL-returned sizes.
    // These sites all return JO_OUTPUT_TOO_LONG_INT32 (-20) unmultiplexed;
    // the test names identify which site fired by the flag used and the
    // call-path driven.
    // -----------------------------------------------------------------

    /**
     * Target: {@code interface/util/ec.c:187} — fault-injects the
     * {@code name_len > INT32_MAX} defensive check inside
     * {@code get_curve_name_component} (defined at {@code ec.c:177}).
     * Reached only on the NULL-buffer length-probe path
     * ({@code out == NULL || out_len == 0}). Driven here by passing a
     * zero-length output buffer.
     */
    @Test
    public void ec_getComponent_curveName_int32Overflow_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        long keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
        try
        {
            OpenSSL.getOpenSSLErrors();
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);
            // Zero-length buffer enters the "length probe" branch in
            // get_curve_name_component, which is the only path that hits
            // the INT32_MAX check at line 187.
            int code = ec.ni_getComponent(keyRef, ECServiceNI.COMP_CURVE_NAME,
                    new byte[0]);
            Assertions.assertEquals(JO_OUTPUT_TOO_LONG_INT32, code);
        }
        finally
        {
            specNI.dispose(keyRef);
        }
    }

    /**
     * Target: {@code interface/util/ec.c:607} — fault-injects the
     * {@code sig_len > INT32_MAX} defensive check applied to the
     * {@code EVP_DigestSignFinal} probe-returned upper-bound inside
     * {@code ec_ctx_sign} (defined at {@code ec.c:584}). Reachable on every
     * sign call regardless of whether the caller passed a NULL or real
     * buffer (the check runs after the probe, before the out-handling
     * branches).
     */
    @Test
    public void ec_sign_int32Overflow_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        long sigRef = ec.allocateSigner();
        long keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
        try
        {
            ec.initSign(sigRef, keyRef, "SHA-256", TestUtil.RNDSrc);
            ec.update(sigRef, new byte[]{0x01}, 0, 1);
            OpenSSL.getOpenSSLErrors();
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);
            int code = ec.ni_sign(sigRef, null, 0, TestUtil.RNDSrc);
            Assertions.assertEquals(JO_OUTPUT_TOO_LONG_INT32, code);
        }
        finally
        {
            ec.disposeSigner(sigRef);
            specNI.dispose(keyRef);
        }
    }

    /**
     * Target: {@code interface/util/ec.c:823} — fault-injects the
     * {@code need > INT32_MAX} defensive check applied to the probe-returned
     * upper-bound from {@code EVP_PKEY_derive} (NULL out) inside
     * {@code ec_kex_derive} (defined at {@code ec.c:796}). Reachable on every
     * derive call: runs immediately after the probe and before the
     * out-buffer branches. Driven here with a NULL out buffer so site 840
     * (the fetch-side INT32 check) isn't entered.
     */
    @Test
    public void ec_kexDerive_probe_int32Overflow_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        long kexRef = ec.allocateKex();
        long keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
        long peerRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
        try
        {
            ec.kexInit(kexRef, keyRef, TestUtil.RNDSrc);
            ec.kexSetPeer(kexRef, peerRef, TestUtil.RNDSrc);
            OpenSSL.getOpenSSLErrors();
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);
            int code = ec.ni_kexDerive(kexRef, null, 0, TestUtil.RNDSrc);
            Assertions.assertEquals(JO_OUTPUT_TOO_LONG_INT32, code);
        }
        finally
        {
            ec.disposeKex(kexRef);
            specNI.dispose(keyRef);
            specNI.dispose(peerRef);
        }
    }

    /**
     * Target: {@code interface/util/ec.c:840} — fault-injects the
     * {@code written > INT32_MAX} defensive check applied to the fetch-side
     * {@code EVP_PKEY_derive}'s returned length inside {@code ec_kex_derive}
     * (defined at {@code ec.c:796}). Reachable only when a real output
     * buffer is supplied AND large enough for the actual secret. Uses
     * {@code OPS_INT32_OVERFLOW_2} so the probe-side check at line 823
     * doesn't fire first.
     */
    @Test
    public void ec_kexDerive_fetch_int32Overflow_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        long kexRef = ec.allocateKex();
        long keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
        long peerRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
        try
        {
            ec.kexInit(kexRef, keyRef, TestUtil.RNDSrc);
            ec.kexSetPeer(kexRef, peerRef, TestUtil.RNDSrc);
            OpenSSL.getOpenSSLErrors();
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_2);
            // 64-byte buffer is comfortably larger than the 32-byte P-256
            // secret, so the fetch path runs to its INT32 check.
            int code = ec.ni_kexDerive(kexRef, new byte[64], 0, TestUtil.RNDSrc);
            Assertions.assertEquals(JO_OUTPUT_TOO_LONG_INT32, code);
        }
        finally
        {
            ec.disposeKex(kexRef);
            specNI.dispose(keyRef);
            specNI.dispose(peerRef);
        }
    }


    // -----------------------------------------------------------------
    // JNI access faults (OPS_FAILED_ACCESS_*) — JNI-only
    //
    // These tests fault-inject GetStringUTFChars failure on curve / digest
    // name strings at the JNI bridge layer. FFI doesn't take a JVM access
    // path so the tests are guarded by Loader.isFFI().
    // -----------------------------------------------------------------

    /**
     * Target: {@code interface/jni/ec_ni_jni.c:42} — fault-injects the
     * {@code GetStringUTFChars(curveName)} failure inside {@code ni_curveSupported}.
     */
    @Test
    public void ec_curveSupported_accessCurveName_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        try
        {
            // Exercises interface/jni/ec_ni_jni.c:42
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            int code = ec.ni_curveSupported("P-256");
            Assertions.assertEquals(JO_UNABLE_TO_ACCESS_NAME, code);
        }
        finally
        {
            ops.resetFlags();
        }
    }

    /**
     * Target: {@code interface/jni/ec_ni_jni.c:77} — fault-injects the
     * {@code GetStringUTFChars(curveName)} failure inside {@code ni_generateKeyPair}.
     */
    @Test
    public void ec_generateKeyPair_accessCurveName_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        try
        {
            // Exercises interface/jni/ec_ni_jni.c:77
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            int[] err = new int[1];
            long ref = ec.ni_generateKeyPair("P-256", err, TestUtil.RNDSrc);
            Assertions.assertEquals(0L, ref);
            Assertions.assertEquals(JO_UNABLE_TO_ACCESS_NAME, err[0]);
        }
        finally
        {
            ops.resetFlags();
        }
    }

    /**
     * Target: {@code interface/jni/ec_ni_jni.c:136} — fault-injects the
     * {@code GetStringUTFChars(curveName)} failure inside
     * {@code ni_makePrivateFromComponents}. Uses {@code OPS_FAILED_ACCESS_2}
     * because slot {@code _1} is used by the scalar byte-array load further
     * down the same function.
     */
    @Test
    public void ec_makePrivateFromComponents_accessCurveName_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        // Any non-zero 32-byte scalar — OPS short-circuits before validation.
        byte[] scalar = new byte[32];
        scalar[31] = 0x01;
        try
        {
            // Exercises interface/jni/ec_ni_jni.c:136
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_2);
            int[] err = new int[1];
            long ref = ec.ni_makePrivateFromComponents("P-256", scalar, err, TestUtil.RNDSrc);
            Assertions.assertEquals(0L, ref);
            Assertions.assertEquals(JO_UNABLE_TO_ACCESS_NAME, err[0]);
        }
        finally
        {
            ops.resetFlags();
        }
    }

    /**
     * Target: {@code interface/jni/ec_ni_jni.c:270} — fault-injects the
     * {@code GetStringUTFChars(digest)} failure inside {@code ni_initSign}.
     */
    @Test
    public void ec_initSign_accessDigestName_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        long sigRef = ec.allocateSigner();
        long keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
        try
        {
            // Exercises interface/jni/ec_ni_jni.c:270
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            int code = ec.ni_initSign(sigRef, keyRef, "SHA-256", TestUtil.RNDSrc);
            Assertions.assertEquals(JO_UNABLE_TO_ACCESS_NAME, code);
        }
        finally
        {
            ops.resetFlags();
            ec.disposeSigner(sigRef);
            specNI.dispose(keyRef);
        }
    }

    /**
     * Target: {@code interface/jni/ec_ni_jni.c:302} — fault-injects the
     * {@code GetStringUTFChars(digest)} failure inside {@code ni_initVerify}.
     */
    @Test
    public void ec_initVerify_accessDigestName_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        long sigRef = ec.allocateSigner();
        long keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
        try
        {
            // Exercises interface/jni/ec_ni_jni.c:302
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            int code = ec.ni_initVerify(sigRef, keyRef, "SHA-256");
            Assertions.assertEquals(JO_UNABLE_TO_ACCESS_NAME, code);
        }
        finally
        {
            ops.resetFlags();
            ec.disposeSigner(sigRef);
            specNI.dispose(keyRef);
        }
    }


    // -----------------------------------------------------------------
    // Raw ECDSA (NoneWithECDSA, digest name "NONE") — ec_raw_init / sign / verify
    // -----------------------------------------------------------------

    @Test
    public void ec_noneRawInitSign_opensslError()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        long sigRef = ec.allocateSigner();
        long keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
        try
        {
            OpenSSL.getOpenSSLErrors();
            // Exercises interface/util/ec.c:494
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_11);
            int code = ec.ni_initSign(sigRef, keyRef, "NONE", TestUtil.RNDSrc);
            Assertions.assertEquals(errorAt(3100), code);
        }
        finally
        {
            ops.resetFlags();
            ec.disposeSigner(sigRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void ec_noneRawSign_opensslError()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        long sigRef = ec.allocateSigner();
        long keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
        try
        {
            ec.initSign(sigRef, keyRef, "NONE", TestUtil.RNDSrc);
            ec.ni_update(sigRef, new byte[32], 0, 32);
            OpenSSL.getOpenSSLErrors();
            // Exercises interface/util/ec.c:721
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_12);
            int code = ec.ni_sign(sigRef, null, 0, TestUtil.RNDSrc);
            Assertions.assertEquals(errorAt(3101), code);
        }
        finally
        {
            ops.resetFlags();
            ec.disposeSigner(sigRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void ec_noneRawVerify_opensslError()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        long sigRef = ec.allocateSigner();
        long keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
        try
        {
            ec.initVerify(sigRef, keyRef, "NONE");
            ec.ni_update(sigRef, new byte[32], 0, 32);
            OpenSSL.getOpenSSLErrors();
            // Exercises interface/util/ec.c:811
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_11);
            int code = ec.ni_verify(sigRef, new byte[72], 72, TestUtil.RNDSrc);
            Assertions.assertEquals(errorAt(3102), code);
        }
        finally
        {
            ops.resetFlags();
            ec.disposeSigner(sigRef);
            specNI.dispose(keyRef);
        }
    }
}
