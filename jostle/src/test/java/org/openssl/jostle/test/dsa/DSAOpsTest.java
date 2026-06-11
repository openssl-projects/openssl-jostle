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

package org.openssl.jostle.test.dsa;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.OpenSSL;
import org.openssl.jostle.jcajce.provider.dsa.DSAServiceNI;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.test.crypto.TestNISelector;
import org.openssl.jostle.util.ops.OperationsTestNI;

import java.security.SecureRandom;
import java.security.Security;

/**
 * Fault-injection tests for the DSA NI layer.
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
 * <h2>Target map: offset → {@code interface/util/dsa.c} fault-injection line</h2>
 *
 * <pre>
 *   Offset  dsa.c line  Function                          Trigger
 *   ----------------------------------------------------------------------------
 *   5000    75          dsa_generate_parameters           EVP_PKEY_CTX_new_from_name == NULL
 *   5001    80          dsa_generate_parameters           EVP_PKEY_paramgen_init failed
 *   5002    90          dsa_generate_parameters           EVP_PKEY_CTX_set_params failed
 *   5003    95          dsa_generate_parameters           EVP_PKEY_paramgen failed
 *   5004    100         dsa_generate_parameters           spec-&gt;key == NULL after paramgen
 *
 *   5010    153         dsa_fromdata                      BN_bin2bn(p/q/g) == NULL
 *   5019    160         dsa_fromdata (public path)        BN_bin2bn(y) == NULL
 *   5020    169         dsa_fromdata (private path)       BN_bin2bn(x) == NULL
 *   5021    186         dsa_fromdata (private path)       BN_CTX_new / BN_new == NULL
 *   5011    190         dsa_fromdata (private path)       BN_mod_exp failed
 *   5012    199         dsa_fromdata                      OSSL_PARAM_BLD_new == NULL
 *   5013    204         dsa_fromdata                      OSSL_PARAM_BLD_push_BN(p/q/g) failed
 *   5014    212         dsa_fromdata (public/private)     OSSL_PARAM_BLD_push_BN(pub) failed
 *   5015    219         dsa_fromdata (private path)       OSSL_PARAM_BLD_push_BN(priv) failed
 *   5016    227         dsa_fromdata                      OSSL_PARAM_BLD_to_param == NULL
 *   5017    234         dsa_fromdata                      EVP_PKEY_CTX_new_from_name == NULL
 *   5018    239         dsa_fromdata                      EVP_PKEY_fromdata_init failed
 *   5022    247         dsa_fromdata                      EVP_PKEY_fromdata failed (flag FAILED_INIT_1)
 *
 *   5030    367         dsa_generate_key                  EVP_PKEY_CTX_new_from_pkey == NULL
 *   5031    372         dsa_generate_key                  EVP_PKEY_keygen_init failed
 *   5032    377         dsa_generate_key                  EVP_PKEY_keygen failed
 *   5033    382         dsa_generate_key                  spec-&gt;key == NULL after keygen
 *
 *   5110    409         get_bn_component                  EVP_PKEY_get_bn_param failed
 *   5111    415         get_bn_component                  defensive BN_num_bytes &lt; 0
 *   5112    431         get_bn_component                  defensive BN_bn2bin &lt; 0
 *
 *   5090    546         dsa_raw_init                      EVP_PKEY_CTX_new_from_pkey == NULL
 *   5093    553         dsa_raw_init                      EVP_PKEY_sign/verify_init failed (flag FAILED_INIT_2)
 *
 *   5040    633         dsa_ctx_init_sign                 EVP_MD_CTX_new == NULL
 *   5041    638         dsa_ctx_init_sign                 EVP_DigestSignInit_ex failed
 *
 *   5050    690         dsa_ctx_init_verify               EVP_MD_CTX_new == NULL
 *   5051    695         dsa_ctx_init_verify               EVP_DigestVerifyInit_ex failed
 *
 *   5060    740         dsa_ctx_update (sign mode)        EVP_DigestSignUpdate failed
 *   5061    745         dsa_ctx_update (verify mode)      EVP_DigestVerifyUpdate failed
 *
 *   5091    773         dsa_ctx_sign (raw probe)          EVP_PKEY_sign failed (flag _12)
 *   5070    807         dsa_ctx_sign (NULL-buffer probe)  EVP_DigestSignFinal failed
 *   5071    831         dsa_ctx_sign (real-buffer fetch)  EVP_DigestSignFinal failed
 *
 *   5092    863         dsa_ctx_verify (raw path)         forced EVP_PKEY_verify structural error (flag _11)
 *   5080    900         dsa_ctx_verify                    forced EVP_DigestVerifyFinal structural error (flag _10)
 *
 *   --      812         dsa_ctx_sign                      sig_len &gt; INT32_MAX (flag INT32_OVERFLOW_1, returns JO_OUTPUT_TOO_LONG_INT32)
 * </pre>
 */
public class DSAOpsTest
{
    private static final int JO_OPENSSL_ERROR = -2;
    private static final int JO_OUTPUT_TOO_LONG_INT32 = -20;
    private static final int JO_FAILED_ACCESS_INPUT = -22;
    private static final int JO_FAILED_ACCESS_OUTPUT = -23;
    private static final int JO_FAILED_ACCESS_SIG = -47;
    private static final int JO_UNABLE_TO_ACCESS_NAME = -89;

    private static DSAServiceNI dsa;
    private static SpecNI specNI;
    private static OperationsTestNI ops;

    /** Class-wide 1024/160 domain parameters and keypair (no flags set). */
    private static long paramsRef = 0;
    private static long keyRef = 0;


    @BeforeAll
    public static void beforeAll()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        dsa = TestNISelector.getDSANi();
        specNI = TestNISelector.getSpecNI();
        ops = TestNISelector.getOperationsTestNI();
        if (ops.opsTestAvailable())
        {
            ops.resetFlags();
        }
        paramsRef = dsa.generateParameters(1024, 160, TestUtil.RNDSrc);
        keyRef = dsa.generateKeyPair(paramsRef, TestUtil.RNDSrc);
    }

    @AfterAll
    public static void afterAll()
    {
        if (ops != null && ops.opsTestAvailable())
        {
            ops.resetFlags();
        }
        if (keyRef != 0)
        {
            specNI.dispose(keyRef);
            keyRef = 0;
        }
        if (paramsRef != 0)
        {
            specNI.dispose(paramsRef);
            paramsRef = 0;
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

    /** Components of the class keypair, fetched with no flags set. */
    private static byte[] component(int selector)
    {
        byte[] out = new byte[dsa.getComponent(keyRef, selector, null)];
        dsa.getComponent(keyRef, selector, out);
        return out;
    }


    // -----------------------------------------------------------------
    // dsa_generate_parameters
    // -----------------------------------------------------------------

    @Test
    public void dsa_generateParameters_ctxNewFromName_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        // Exercises interface/util/dsa.c:75
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);

        int[] err = new int[1];
        long ref = dsa.ni_generateParameters(1024, 160, err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(5000), err[0]);
    }

    @Test
    public void dsa_generateParameters_paramgenInit_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        // Exercises interface/util/dsa.c:80
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);

        int[] err = new int[1];
        long ref = dsa.ni_generateParameters(1024, 160, err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(5001), err[0]);
    }

    @Test
    public void dsa_generateParameters_setParams_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        // Exercises interface/util/dsa.c:90
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);

        int[] err = new int[1];
        long ref = dsa.ni_generateParameters(1024, 160, err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(5002), err[0]);
    }

    @Test
    public void dsa_generateParameters_paramgen_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        // Exercises interface/util/dsa.c:95
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_4);

        int[] err = new int[1];
        long ref = dsa.ni_generateParameters(1024, 160, err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(5003), err[0]);
    }

    @Test
    public void dsa_generateParameters_specKeyNull_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        // Exercises interface/util/dsa.c:100
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_5);

        int[] err = new int[1];
        long ref = dsa.ni_generateParameters(1024, 160, err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(5004), err[0]);
    }


    // -----------------------------------------------------------------
    // dsa_fromdata — via makeParamsFromComponents (params-only path)
    // -----------------------------------------------------------------

    @Test
    public void dsa_makeParams_bnBin2bn_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        byte[] p = component(DSAServiceNI.COMP_P);
        byte[] q = component(DSAServiceNI.COMP_Q);
        byte[] g = component(DSAServiceNI.COMP_G);
        // Exercises interface/util/dsa.c:153
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_6);

        int[] err = new int[1];
        long ref = dsa.ni_makeParamsFromComponents(p, q, g, err);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(5010), err[0]);
    }

    @Test
    public void dsa_makeParams_paramBldNew_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        byte[] p = component(DSAServiceNI.COMP_P);
        byte[] q = component(DSAServiceNI.COMP_Q);
        byte[] g = component(DSAServiceNI.COMP_G);
        // Exercises interface/util/dsa.c:199
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_8);

        int[] err = new int[1];
        long ref = dsa.ni_makeParamsFromComponents(p, q, g, err);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(5012), err[0]);
    }

    @Test
    public void dsa_makeParams_pushPQG_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        byte[] p = component(DSAServiceNI.COMP_P);
        byte[] q = component(DSAServiceNI.COMP_Q);
        byte[] g = component(DSAServiceNI.COMP_G);
        // Exercises interface/util/dsa.c:204
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_9);

        int[] err = new int[1];
        long ref = dsa.ni_makeParamsFromComponents(p, q, g, err);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(5013), err[0]);
    }

    @Test
    public void dsa_makeParams_toParam_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        byte[] p = component(DSAServiceNI.COMP_P);
        byte[] q = component(DSAServiceNI.COMP_Q);
        byte[] g = component(DSAServiceNI.COMP_G);
        // Exercises interface/util/dsa.c:227
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_12);

        int[] err = new int[1];
        long ref = dsa.ni_makeParamsFromComponents(p, q, g, err);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(5016), err[0]);
    }

    @Test
    public void dsa_makeParams_ctxNewFromName_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        byte[] p = component(DSAServiceNI.COMP_P);
        byte[] q = component(DSAServiceNI.COMP_Q);
        byte[] g = component(DSAServiceNI.COMP_G);
        // Exercises interface/util/dsa.c:234
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);

        int[] err = new int[1];
        long ref = dsa.ni_makeParamsFromComponents(p, q, g, err);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(5017), err[0]);
    }

    @Test
    public void dsa_makeParams_fromdataInit_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        byte[] p = component(DSAServiceNI.COMP_P);
        byte[] q = component(DSAServiceNI.COMP_Q);
        byte[] g = component(DSAServiceNI.COMP_G);
        // Exercises interface/util/dsa.c:239
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);

        int[] err = new int[1];
        long ref = dsa.ni_makeParamsFromComponents(p, q, g, err);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(5018), err[0]);
    }

    @Test
    public void dsa_makeParams_fromdata_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        byte[] p = component(DSAServiceNI.COMP_P);
        byte[] q = component(DSAServiceNI.COMP_Q);
        byte[] g = component(DSAServiceNI.COMP_G);
        // Exercises interface/util/dsa.c:247
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_INIT_1);

        int[] err = new int[1];
        long ref = dsa.ni_makeParamsFromComponents(p, q, g, err);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(5022), err[0]);
    }


    // -----------------------------------------------------------------
    // dsa_fromdata — private-key path (x present, y computed)
    // -----------------------------------------------------------------

    @Test
    public void dsa_makePrivate_bnBin2bnX_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        byte[] p = component(DSAServiceNI.COMP_P);
        byte[] q = component(DSAServiceNI.COMP_Q);
        byte[] g = component(DSAServiceNI.COMP_G);
        byte[] x = component(DSAServiceNI.COMP_PRIVATE_VALUE);
        // Exercises interface/util/dsa.c:169
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_4);

        int[] err = new int[1];
        long ref = dsa.ni_makePrivateFromComponents(p, q, g, x, err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(5020), err[0]);
    }

    @Test
    public void dsa_makePrivate_bnCtxNew_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        byte[] p = component(DSAServiceNI.COMP_P);
        byte[] q = component(DSAServiceNI.COMP_Q);
        byte[] g = component(DSAServiceNI.COMP_G);
        byte[] x = component(DSAServiceNI.COMP_PRIVATE_VALUE);
        // Exercises interface/util/dsa.c:186
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_5);

        int[] err = new int[1];
        long ref = dsa.ni_makePrivateFromComponents(p, q, g, x, err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(5021), err[0]);
    }

    @Test
    public void dsa_makePrivate_bnModExp_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        byte[] p = component(DSAServiceNI.COMP_P);
        byte[] q = component(DSAServiceNI.COMP_Q);
        byte[] g = component(DSAServiceNI.COMP_G);
        byte[] x = component(DSAServiceNI.COMP_PRIVATE_VALUE);
        // Exercises interface/util/dsa.c:190
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_7);

        int[] err = new int[1];
        long ref = dsa.ni_makePrivateFromComponents(p, q, g, x, err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(5011), err[0]);
    }

    @Test
    public void dsa_makePrivate_pushPub_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        byte[] p = component(DSAServiceNI.COMP_P);
        byte[] q = component(DSAServiceNI.COMP_Q);
        byte[] g = component(DSAServiceNI.COMP_G);
        byte[] x = component(DSAServiceNI.COMP_PRIVATE_VALUE);
        // Exercises interface/util/dsa.c:212
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_10);

        int[] err = new int[1];
        long ref = dsa.ni_makePrivateFromComponents(p, q, g, x, err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(5014), err[0]);
    }

    @Test
    public void dsa_makePrivate_pushPriv_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        byte[] p = component(DSAServiceNI.COMP_P);
        byte[] q = component(DSAServiceNI.COMP_Q);
        byte[] g = component(DSAServiceNI.COMP_G);
        byte[] x = component(DSAServiceNI.COMP_PRIVATE_VALUE);
        // Exercises interface/util/dsa.c:219
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_11);

        int[] err = new int[1];
        long ref = dsa.ni_makePrivateFromComponents(p, q, g, x, err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(5015), err[0]);
    }


    // -----------------------------------------------------------------
    // dsa_fromdata — public-key path (y supplied)
    // -----------------------------------------------------------------

    @Test
    public void dsa_makePublic_bnBin2bnY_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        byte[] p = component(DSAServiceNI.COMP_P);
        byte[] q = component(DSAServiceNI.COMP_Q);
        byte[] g = component(DSAServiceNI.COMP_G);
        byte[] y = component(DSAServiceNI.COMP_PUBLIC_VALUE);
        // Exercises interface/util/dsa.c:160
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);

        int[] err = new int[1];
        long ref = dsa.ni_makePublicFromComponents(p, q, g, y, err);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(5019), err[0]);
    }


    // -----------------------------------------------------------------
    // dsa_generate_key
    // -----------------------------------------------------------------

    @Test
    public void dsa_generateKeyPair_ctxNewFromPkey_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        // Exercises interface/util/dsa.c:367
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);

        int[] err = new int[1];
        long ref = dsa.ni_generateKeyPair(paramsRef, err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(5030), err[0]);
    }

    @Test
    public void dsa_generateKeyPair_keygenInit_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        // Exercises interface/util/dsa.c:372
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_4);

        int[] err = new int[1];
        long ref = dsa.ni_generateKeyPair(paramsRef, err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(5031), err[0]);
    }

    @Test
    public void dsa_generateKeyPair_keygen_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        // Exercises interface/util/dsa.c:377
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_5);

        int[] err = new int[1];
        long ref = dsa.ni_generateKeyPair(paramsRef, err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(5032), err[0]);
    }

    @Test
    public void dsa_generateKeyPair_specKeyNull_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        // Exercises interface/util/dsa.c:382
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_6);

        int[] err = new int[1];
        long ref = dsa.ni_generateKeyPair(paramsRef, err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(5033), err[0]);
    }


    // -----------------------------------------------------------------
    // get_bn_component
    // -----------------------------------------------------------------

    @Test
    public void dsa_getComponent_getBnParam_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        // Exercises interface/util/dsa.c:409
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_7);

        int code = dsa.ni_getComponent(keyRef, DSAServiceNI.COMP_P, new byte[256]);
        Assertions.assertEquals(errorAt(5110), code);
    }

    @Test
    public void dsa_getComponent_bnNumBytes_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        // Exercises interface/util/dsa.c:415
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_8);

        int code = dsa.ni_getComponent(keyRef, DSAServiceNI.COMP_P, new byte[256]);
        Assertions.assertEquals(errorAt(5111), code);
    }

    @Test
    public void dsa_getComponent_bn2bin_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        // Exercises interface/util/dsa.c:431
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_9);

        int code = dsa.ni_getComponent(keyRef, DSAServiceNI.COMP_P, new byte[256]);
        Assertions.assertEquals(errorAt(5112), code);
    }


    // -----------------------------------------------------------------
    // dsa_ctx_init_sign / init_verify (digest path)
    // -----------------------------------------------------------------

    @Test
    public void dsa_initSign_mdCtxNew_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        long ref = dsa.allocateSigner();
        try
        {
            // Exercises interface/util/dsa.c:633
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);
            int code = dsa.ni_initSign(ref, keyRef, "SHA-256", TestUtil.RNDSrc);
            Assertions.assertEquals(errorAt(5040), code);
        }
        finally
        {
            ops.resetFlags();
            dsa.disposeSigner(ref);
        }
    }

    @Test
    public void dsa_initSign_digestSignInit_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        long ref = dsa.allocateSigner();
        try
        {
            // Exercises interface/util/dsa.c:638
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_4);
            int code = dsa.ni_initSign(ref, keyRef, "SHA-256", TestUtil.RNDSrc);
            Assertions.assertEquals(errorAt(5041), code);
        }
        finally
        {
            ops.resetFlags();
            dsa.disposeSigner(ref);
        }
    }

    @Test
    public void dsa_initVerify_mdCtxNew_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        long ref = dsa.allocateSigner();
        try
        {
            // Exercises interface/util/dsa.c:690
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_5);
            int code = dsa.ni_initVerify(ref, keyRef, "SHA-256");
            Assertions.assertEquals(errorAt(5050), code);
        }
        finally
        {
            ops.resetFlags();
            dsa.disposeSigner(ref);
        }
    }

    @Test
    public void dsa_initVerify_digestVerifyInit_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        long ref = dsa.allocateSigner();
        try
        {
            // Exercises interface/util/dsa.c:695
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_6);
            int code = dsa.ni_initVerify(ref, keyRef, "SHA-256");
            Assertions.assertEquals(errorAt(5051), code);
        }
        finally
        {
            ops.resetFlags();
            dsa.disposeSigner(ref);
        }
    }


    // -----------------------------------------------------------------
    // dsa_ctx_update
    // -----------------------------------------------------------------

    @Test
    public void dsa_update_signMode_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        long ref = dsa.allocateSigner();
        try
        {
            dsa.initSign(ref, keyRef, "SHA-256", TestUtil.RNDSrc);
            // Exercises interface/util/dsa.c:740
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_7);
            int code = dsa.ni_update(ref, new byte[]{0x01}, 0, 1);
            Assertions.assertEquals(errorAt(5060), code);
        }
        finally
        {
            ops.resetFlags();
            dsa.disposeSigner(ref);
        }
    }

    @Test
    public void dsa_update_verifyMode_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        long ref = dsa.allocateSigner();
        try
        {
            dsa.initVerify(ref, keyRef, "SHA-256");
            // Exercises interface/util/dsa.c:745
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_7);
            int code = dsa.ni_update(ref, new byte[]{0x01}, 0, 1);
            Assertions.assertEquals(errorAt(5061), code);
        }
        finally
        {
            ops.resetFlags();
            dsa.disposeSigner(ref);
        }
    }


    // -----------------------------------------------------------------
    // dsa_ctx_sign (digest path)
    // -----------------------------------------------------------------

    @Test
    public void dsa_sign_probe_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        long ref = dsa.allocateSigner();
        try
        {
            dsa.initSign(ref, keyRef, "SHA-256", TestUtil.RNDSrc);
            dsa.update(ref, new byte[]{0x01}, 0, 1);
            // Exercises interface/util/dsa.c:807
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_8);
            int code = dsa.ni_sign(ref, null, 0, TestUtil.RNDSrc);
            Assertions.assertEquals(errorAt(5070), code);
        }
        finally
        {
            ops.resetFlags();
            dsa.disposeSigner(ref);
        }
    }

    @Test
    public void dsa_sign_fetch_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        long ref = dsa.allocateSigner();
        try
        {
            dsa.initSign(ref, keyRef, "SHA-256", TestUtil.RNDSrc);
            dsa.update(ref, new byte[]{0x01}, 0, 1);
            // Exercises interface/util/dsa.c:831
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_9);
            int code = dsa.ni_sign(ref, new byte[128], 0, TestUtil.RNDSrc);
            Assertions.assertEquals(errorAt(5071), code);
        }
        finally
        {
            ops.resetFlags();
            dsa.disposeSigner(ref);
        }
    }

    @Test
    public void dsa_sign_sigLenOverflow_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        long ref = dsa.allocateSigner();
        try
        {
            dsa.initSign(ref, keyRef, "SHA-256", TestUtil.RNDSrc);
            dsa.update(ref, new byte[]{0x01}, 0, 1);
            // Exercises interface/util/dsa.c:812
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);
            int code = dsa.ni_sign(ref, null, 0, TestUtil.RNDSrc);
            Assertions.assertEquals(JO_OUTPUT_TOO_LONG_INT32, code);
        }
        finally
        {
            ops.resetFlags();
            dsa.disposeSigner(ref);
        }
    }


    // -----------------------------------------------------------------
    // dsa_ctx_verify (digest path)
    // -----------------------------------------------------------------

    @Test
    public void dsa_verify_structuralError_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        long ref = dsa.allocateSigner();
        try
        {
            dsa.initVerify(ref, keyRef, "SHA-256");
            dsa.update(ref, new byte[]{0x01}, 0, 1);
            // Exercises interface/util/dsa.c:900
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_10);
            int code = dsa.ni_verify(ref, new byte[]{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}, 8, TestUtil.RNDSrc);
            Assertions.assertEquals(errorAt(5080), code);
        }
        finally
        {
            ops.resetFlags();
            dsa.disposeSigner(ref);
        }
    }


    // -----------------------------------------------------------------
    // Raw ("NONE") session — init / sign probe / verify structural
    // -----------------------------------------------------------------

    @Test
    public void dsa_rawInit_ctxNewFromPkey_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        long ref = dsa.allocateSigner();
        try
        {
            // Exercises interface/util/dsa.c:546
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_11);
            int code = dsa.ni_initSign(ref, keyRef, "NONE", TestUtil.RNDSrc);
            Assertions.assertEquals(errorAt(5090), code);
        }
        finally
        {
            ops.resetFlags();
            dsa.disposeSigner(ref);
        }
    }

    @Test
    public void dsa_rawInit_signInit_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        long ref = dsa.allocateSigner();
        try
        {
            // Exercises interface/util/dsa.c:553
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_INIT_2);
            int code = dsa.ni_initSign(ref, keyRef, "NONE", TestUtil.RNDSrc);
            Assertions.assertEquals(errorAt(5093), code);
        }
        finally
        {
            ops.resetFlags();
            dsa.disposeSigner(ref);
        }
    }

    @Test
    public void dsa_rawSign_probe_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        long ref = dsa.allocateSigner();
        try
        {
            dsa.initSign(ref, keyRef, "NONE", TestUtil.RNDSrc);
            dsa.update(ref, new byte[20], 0, 20);
            // Exercises interface/util/dsa.c:773
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_12);
            int code = dsa.ni_sign(ref, null, 0, TestUtil.RNDSrc);
            Assertions.assertEquals(errorAt(5091), code);
        }
        finally
        {
            ops.resetFlags();
            dsa.disposeSigner(ref);
        }
    }

    @Test
    public void dsa_rawVerify_structuralError_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        long ref = dsa.allocateSigner();
        try
        {
            dsa.initVerify(ref, keyRef, "NONE");
            dsa.update(ref, new byte[20], 0, 20);
            // Exercises interface/util/dsa.c:863
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_11);
            int code = dsa.ni_verify(ref, new byte[]{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}, 8, TestUtil.RNDSrc);
            Assertions.assertEquals(errorAt(5092), code);
        }
        finally
        {
            ops.resetFlags();
            dsa.disposeSigner(ref);
        }
    }


    // -----------------------------------------------------------------
    // JNI access faults (OPS_FAILED_ACCESS_*) — JNI-only. The FFI
    // bridge has no JVM array-access path so the tests are guarded by
    // Loader.isFFI().
    // -----------------------------------------------------------------

    @Test
    public void dsa_makeParams_accessP_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        byte[] p = component(DSAServiceNI.COMP_P);
        byte[] q = component(DSAServiceNI.COMP_Q);
        byte[] g = component(DSAServiceNI.COMP_G);
        try
        {
            // Exercises interface/jni/dsa_ni_jni.c:90
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            int[] err = new int[1];
            long ref = dsa.ni_makeParamsFromComponents(p, q, g, err);
            Assertions.assertEquals(0L, ref);
            Assertions.assertEquals(JO_FAILED_ACCESS_INPUT, err[0]);
        }
        finally
        {
            ops.resetFlags();
        }
    }

    @Test
    public void dsa_makeParams_accessQ_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        byte[] p = component(DSAServiceNI.COMP_P);
        byte[] q = component(DSAServiceNI.COMP_Q);
        byte[] g = component(DSAServiceNI.COMP_G);
        try
        {
            // Exercises interface/jni/dsa_ni_jni.c:94
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_2);
            int[] err = new int[1];
            long ref = dsa.ni_makeParamsFromComponents(p, q, g, err);
            Assertions.assertEquals(0L, ref);
            Assertions.assertEquals(JO_FAILED_ACCESS_INPUT, err[0]);
        }
        finally
        {
            ops.resetFlags();
        }
    }

    @Test
    public void dsa_makeParams_accessG_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        byte[] p = component(DSAServiceNI.COMP_P);
        byte[] q = component(DSAServiceNI.COMP_Q);
        byte[] g = component(DSAServiceNI.COMP_G);
        try
        {
            // Exercises interface/jni/dsa_ni_jni.c:98
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_3);
            int[] err = new int[1];
            long ref = dsa.ni_makeParamsFromComponents(p, q, g, err);
            Assertions.assertEquals(0L, ref);
            Assertions.assertEquals(JO_FAILED_ACCESS_INPUT, err[0]);
        }
        finally
        {
            ops.resetFlags();
        }
    }

    @Test
    public void dsa_makePrivate_accessP_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        byte[] p = component(DSAServiceNI.COMP_P);
        byte[] q = component(DSAServiceNI.COMP_Q);
        byte[] g = component(DSAServiceNI.COMP_G);
        byte[] x = component(DSAServiceNI.COMP_PRIVATE_VALUE);
        try
        {
            // Exercises interface/jni/dsa_ni_jni.c:208
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            int[] err = new int[1];
            long ref = dsa.ni_makePrivateFromComponents(p, q, g, x, err, TestUtil.RNDSrc);
            Assertions.assertEquals(0L, ref);
            Assertions.assertEquals(JO_FAILED_ACCESS_INPUT, err[0]);
        }
        finally
        {
            ops.resetFlags();
        }
    }

    @Test
    public void dsa_makePrivate_accessQ_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        byte[] p = component(DSAServiceNI.COMP_P);
        byte[] q = component(DSAServiceNI.COMP_Q);
        byte[] g = component(DSAServiceNI.COMP_G);
        byte[] x = component(DSAServiceNI.COMP_PRIVATE_VALUE);
        try
        {
            // Exercises interface/jni/dsa_ni_jni.c:212
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_2);
            int[] err = new int[1];
            long ref = dsa.ni_makePrivateFromComponents(p, q, g, x, err, TestUtil.RNDSrc);
            Assertions.assertEquals(0L, ref);
            Assertions.assertEquals(JO_FAILED_ACCESS_INPUT, err[0]);
        }
        finally
        {
            ops.resetFlags();
        }
    }

    @Test
    public void dsa_makePrivate_accessG_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        byte[] p = component(DSAServiceNI.COMP_P);
        byte[] q = component(DSAServiceNI.COMP_Q);
        byte[] g = component(DSAServiceNI.COMP_G);
        byte[] x = component(DSAServiceNI.COMP_PRIVATE_VALUE);
        try
        {
            // Exercises interface/jni/dsa_ni_jni.c:216
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_3);
            int[] err = new int[1];
            long ref = dsa.ni_makePrivateFromComponents(p, q, g, x, err, TestUtil.RNDSrc);
            Assertions.assertEquals(0L, ref);
            Assertions.assertEquals(JO_FAILED_ACCESS_INPUT, err[0]);
        }
        finally
        {
            ops.resetFlags();
        }
    }

    @Test
    public void dsa_makePrivate_accessX_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        byte[] p = component(DSAServiceNI.COMP_P);
        byte[] q = component(DSAServiceNI.COMP_Q);
        byte[] g = component(DSAServiceNI.COMP_G);
        byte[] x = component(DSAServiceNI.COMP_PRIVATE_VALUE);
        try
        {
            // Exercises interface/jni/dsa_ni_jni.c:220
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_4);
            int[] err = new int[1];
            long ref = dsa.ni_makePrivateFromComponents(p, q, g, x, err, TestUtil.RNDSrc);
            Assertions.assertEquals(0L, ref);
            Assertions.assertEquals(JO_FAILED_ACCESS_INPUT, err[0]);
        }
        finally
        {
            ops.resetFlags();
        }
    }

    @Test
    public void dsa_makePublic_accessP_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        byte[] p = component(DSAServiceNI.COMP_P);
        byte[] q = component(DSAServiceNI.COMP_Q);
        byte[] g = component(DSAServiceNI.COMP_G);
        byte[] y = component(DSAServiceNI.COMP_PUBLIC_VALUE);
        try
        {
            // Exercises interface/jni/dsa_ni_jni.c:283
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            int[] err = new int[1];
            long ref = dsa.ni_makePublicFromComponents(p, q, g, y, err);
            Assertions.assertEquals(0L, ref);
            Assertions.assertEquals(JO_FAILED_ACCESS_INPUT, err[0]);
        }
        finally
        {
            ops.resetFlags();
        }
    }

    @Test
    public void dsa_makePublic_accessQ_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        byte[] p = component(DSAServiceNI.COMP_P);
        byte[] q = component(DSAServiceNI.COMP_Q);
        byte[] g = component(DSAServiceNI.COMP_G);
        byte[] y = component(DSAServiceNI.COMP_PUBLIC_VALUE);
        try
        {
            // Exercises interface/jni/dsa_ni_jni.c:287
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_2);
            int[] err = new int[1];
            long ref = dsa.ni_makePublicFromComponents(p, q, g, y, err);
            Assertions.assertEquals(0L, ref);
            Assertions.assertEquals(JO_FAILED_ACCESS_INPUT, err[0]);
        }
        finally
        {
            ops.resetFlags();
        }
    }

    @Test
    public void dsa_makePublic_accessG_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        byte[] p = component(DSAServiceNI.COMP_P);
        byte[] q = component(DSAServiceNI.COMP_Q);
        byte[] g = component(DSAServiceNI.COMP_G);
        byte[] y = component(DSAServiceNI.COMP_PUBLIC_VALUE);
        try
        {
            // Exercises interface/jni/dsa_ni_jni.c:291
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_3);
            int[] err = new int[1];
            long ref = dsa.ni_makePublicFromComponents(p, q, g, y, err);
            Assertions.assertEquals(0L, ref);
            Assertions.assertEquals(JO_FAILED_ACCESS_INPUT, err[0]);
        }
        finally
        {
            ops.resetFlags();
        }
    }

    @Test
    public void dsa_makePublic_accessY_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        byte[] p = component(DSAServiceNI.COMP_P);
        byte[] q = component(DSAServiceNI.COMP_Q);
        byte[] g = component(DSAServiceNI.COMP_G);
        byte[] y = component(DSAServiceNI.COMP_PUBLIC_VALUE);
        try
        {
            // Exercises interface/jni/dsa_ni_jni.c:295
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_4);
            int[] err = new int[1];
            long ref = dsa.ni_makePublicFromComponents(p, q, g, y, err);
            Assertions.assertEquals(0L, ref);
            Assertions.assertEquals(JO_FAILED_ACCESS_INPUT, err[0]);
        }
        finally
        {
            ops.resetFlags();
        }
    }

    @Test
    public void dsa_getComponent_accessOutput_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        try
        {
            // Exercises interface/jni/dsa_ni_jni.c:351
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            int code = dsa.ni_getComponent(keyRef, DSAServiceNI.COMP_P, new byte[256]);
            Assertions.assertEquals(JO_FAILED_ACCESS_OUTPUT, code);
        }
        finally
        {
            ops.resetFlags();
        }
    }

    @Test
    public void dsa_initSign_accessDigestName_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        long ref = dsa.allocateSigner();
        try
        {
            // Exercises interface/jni/dsa_ni_jni.c:423
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            int code = dsa.ni_initSign(ref, keyRef, "SHA-256", TestUtil.RNDSrc);
            Assertions.assertEquals(JO_UNABLE_TO_ACCESS_NAME, code);
        }
        finally
        {
            ops.resetFlags();
            dsa.disposeSigner(ref);
        }
    }

    @Test
    public void dsa_initVerify_accessDigestName_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        long ref = dsa.allocateSigner();
        try
        {
            // Exercises interface/jni/dsa_ni_jni.c:455
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            int code = dsa.ni_initVerify(ref, keyRef, "SHA-256");
            Assertions.assertEquals(JO_UNABLE_TO_ACCESS_NAME, code);
        }
        finally
        {
            ops.resetFlags();
            dsa.disposeSigner(ref);
        }
    }

    @Test
    public void dsa_update_accessInput_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        long ref = dsa.allocateSigner();
        try
        {
            dsa.initSign(ref, keyRef, "SHA-256", TestUtil.RNDSrc);
            // Exercises interface/jni/dsa_ni_jni.c:498
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            int code = dsa.ni_update(ref, new byte[]{0x01}, 0, 1);
            Assertions.assertEquals(JO_FAILED_ACCESS_INPUT, code);
        }
        finally
        {
            ops.resetFlags();
            dsa.disposeSigner(ref);
        }
    }

    @Test
    public void dsa_sign_accessOutput_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        long ref = dsa.allocateSigner();
        try
        {
            dsa.initSign(ref, keyRef, "SHA-256", TestUtil.RNDSrc);
            dsa.update(ref, new byte[]{0x01}, 0, 1);
            // Exercises interface/jni/dsa_ni_jni.c:544
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            int code = dsa.ni_sign(ref, new byte[128], 0, TestUtil.RNDSrc);
            Assertions.assertEquals(JO_FAILED_ACCESS_OUTPUT, code);
        }
        finally
        {
            ops.resetFlags();
            dsa.disposeSigner(ref);
        }
    }

    @Test
    public void dsa_verify_accessSig_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        long ref = dsa.allocateSigner();
        try
        {
            dsa.initVerify(ref, keyRef, "SHA-256");
            dsa.update(ref, new byte[]{0x01}, 0, 1);
            // Exercises interface/jni/dsa_ni_jni.c:597
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            int code = dsa.ni_verify(ref, new byte[64], 64, TestUtil.RNDSrc);
            Assertions.assertEquals(JO_FAILED_ACCESS_SIG, code);
        }
        finally
        {
            ops.resetFlags();
            dsa.disposeSigner(ref);
        }
    }
}
