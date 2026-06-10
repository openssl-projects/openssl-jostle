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

package org.openssl.jostle.test.dh;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.OpenSSL;
import org.openssl.jostle.jcajce.provider.dh.DHServiceNI;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.test.crypto.TestNISelector;
import org.openssl.jostle.util.ops.OperationsTestNI;

import java.security.Security;

/**
 * Fault-injection tests for the DH NI layer.
 *
 * <p>Each test sets exactly one {@code OPS_*} flag in the C-side
 * instrumentation, drives the matching native function through the
 * raw {@code ni_*} entry points (so the integer error code is observable
 * directly), and asserts the resulting code matches the expected
 * {@code JO_OPENSSL_ERROR + (-offset)} value.
 *
 * <p>All tests are guarded by {@link OperationsTestNI#opsTestAvailable()}
 * so they no-op on a release native build.
 *
 * <h2>Target map: offset → {@code interface/util/dh.c} fault-injection line</h2>
 *
 * <pre>
 *   Offset  dh.c line  Function                          Trigger
 *   ----------------------------------------------------------------------------
 *   5200    128        dh_generate_key_by_group          EVP_PKEY_CTX_new_from_name == NULL
 *   5201    133        dh_generate_key_by_group          EVP_PKEY_keygen_init failed
 *   5202    143        dh_generate_key_by_group          EVP_PKEY_CTX_set_params failed
 *   5203    151        dh_generate_key_by_group          EVP_PKEY_keygen failed
 *   5204    156        dh_generate_key_by_group          spec-&gt;key == NULL after keygen
 *
 *   5210    193        dh_generate_parameters            EVP_PKEY_CTX_new_from_name == NULL
 *   5211    198        dh_generate_parameters            EVP_PKEY_paramgen_init failed
 *   5212    210        dh_generate_parameters            EVP_PKEY_CTX_set_params failed
 *   5213    215        dh_generate_parameters            EVP_PKEY_paramgen failed
 *   5214    220        dh_generate_parameters            spec-&gt;key == NULL after paramgen
 *
 *   5220    272        dh_fromdata                       BN_bin2bn(p/g) == NULL
 *   5221    279        dh_fromdata (public path)         BN_bin2bn(y) == NULL
 *   5222    288        dh_fromdata (private path)        BN_bin2bn(x) == NULL
 *   5223    305        dh_fromdata (private path)        BN_CTX_new / BN_new == NULL
 *   5224    309        dh_fromdata (private path)        BN_mod_exp failed
 *   5225    318        dh_fromdata                       OSSL_PARAM_BLD_new == NULL
 *   5226    323        dh_fromdata                       OSSL_PARAM_BLD_push_BN(p/g) failed
 *   5227    330        dh_fromdata (public/private)      OSSL_PARAM_BLD_push_BN(pub) failed
 *   5228    337        dh_fromdata (private path)        OSSL_PARAM_BLD_push_BN(priv) failed
 *   5229    345        dh_fromdata                       OSSL_PARAM_BLD_to_param == NULL
 *   5230    352        dh_fromdata                       EVP_PKEY_CTX_new_from_name == NULL
 *   5231    357        dh_fromdata                       EVP_PKEY_fromdata_init failed
 *   5232    364        dh_fromdata                       EVP_PKEY_fromdata failed (flag FAILED_INIT_1)
 *
 *   5240    477        dh_generate_key                   EVP_PKEY_CTX_new_from_pkey == NULL
 *   5241    482        dh_generate_key                   EVP_PKEY_keygen_init failed
 *   5242    487        dh_generate_key                   EVP_PKEY_keygen failed
 *   5243    492        dh_generate_key                   spec-&gt;key == NULL after keygen
 *
 *   5250    519        get_bn_component                  EVP_PKEY_get_bn_param failed
 *   5251    525        get_bn_component                  defensive BN_num_bytes &lt; 0
 *   5252    541        get_bn_component                  defensive BN_bn2bin &lt; 0
 *
 *   5260    645        dh_kex_init                       EVP_PKEY_CTX_new_from_pkey == NULL
 *   5261    649        dh_kex_init                       EVP_PKEY_derive_init failed
 *   5262    670        dh_kex_init                       pad set_params failed (flag FAILED_INIT_2)
 *
 *   5270    709        dh_kex_set_peer                   EVP_PKEY_derive_set_peer failed
 *
 *   5280    740        dh_kex_derive (NULL-buffer probe) EVP_PKEY_derive failed (flag _2)
 *   5281    757        dh_kex_derive (real-buffer fetch) EVP_PKEY_derive failed (flag _3)
 *
 *   --      744        dh_kex_derive (probe path)        need &gt; INT32_MAX (flag INT32_OVERFLOW_1, returns JO_OUTPUT_TOO_LONG_INT32)
 * </pre>
 */
public class DHOpsTest
{
    private static final int JO_OPENSSL_ERROR = -2;
    private static final int JO_OUTPUT_TOO_LONG_INT32 = -20;
    private static final int JO_FAILED_ACCESS_INPUT = -22;
    private static final int JO_FAILED_ACCESS_OUTPUT = -23;
    private static final int JO_UNABLE_TO_ACCESS_NAME = -89;

    private static DHServiceNI dh;
    private static SpecNI specNI;
    private static OperationsTestNI ops;

    /** Class-wide ffdhe2048 keypair, peer, and an explicit-params spec. */
    private static long keyRef = 0;
    private static long peerRef = 0;
    private static long paramsRef = 0;


    @BeforeAll
    public static void beforeAll()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        dh = TestNISelector.getDHNi();
        specNI = TestNISelector.getSpecNI();
        ops = TestNISelector.getOperationsTestNI();
        if (ops.opsTestAvailable())
        {
            ops.resetFlags();
        }
        keyRef = dh.generateKeyPairByGroup("ffdhe2048", TestUtil.RNDSrc);
        peerRef = dh.generateKeyPairByGroup("ffdhe2048", TestUtil.RNDSrc);
        paramsRef = dh.makeParamsFromComponents(
                component(DHServiceNI.COMP_P), component(DHServiceNI.COMP_G));
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
        if (peerRef != 0)
        {
            specNI.dispose(peerRef);
            peerRef = 0;
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
        byte[] out = new byte[dh.getComponent(keyRef, selector, null)];
        dh.getComponent(keyRef, selector, out);
        return out;
    }


    // -----------------------------------------------------------------
    // dh_generate_key_by_group
    // -----------------------------------------------------------------

    @Test
    public void dh_generateKeyPairByGroup_ctxNewFromName_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        // Exercises interface/util/dh.c:128
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);

        int[] err = new int[1];
        long ref = dh.ni_generateKeyPairByGroup("ffdhe2048", err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(5200), err[0]);
    }

    @Test
    public void dh_generateKeyPairByGroup_keygenInit_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        // Exercises interface/util/dh.c:133
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);

        int[] err = new int[1];
        long ref = dh.ni_generateKeyPairByGroup("ffdhe2048", err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(5201), err[0]);
    }

    @Test
    public void dh_generateKeyPairByGroup_setParams_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        // Exercises interface/util/dh.c:143
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);

        int[] err = new int[1];
        long ref = dh.ni_generateKeyPairByGroup("ffdhe2048", err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(5202), err[0]);
    }

    @Test
    public void dh_generateKeyPairByGroup_keygen_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        // Exercises interface/util/dh.c:151
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_4);

        int[] err = new int[1];
        long ref = dh.ni_generateKeyPairByGroup("ffdhe2048", err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(5203), err[0]);
    }

    @Test
    public void dh_generateKeyPairByGroup_specKeyNull_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        // Exercises interface/util/dh.c:156
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_5);

        int[] err = new int[1];
        long ref = dh.ni_generateKeyPairByGroup("ffdhe2048", err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(5204), err[0]);
    }


    // -----------------------------------------------------------------
    // dh_generate_parameters
    // -----------------------------------------------------------------

    @Test
    public void dh_generateParameters_ctxNewFromName_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        // Exercises interface/util/dh.c:193
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_6);

        int[] err = new int[1];
        long ref = dh.ni_generateParameters(512, err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(5210), err[0]);
    }

    @Test
    public void dh_generateParameters_paramgenInit_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        // Exercises interface/util/dh.c:198
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_7);

        int[] err = new int[1];
        long ref = dh.ni_generateParameters(512, err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(5211), err[0]);
    }

    @Test
    public void dh_generateParameters_setParams_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        // Exercises interface/util/dh.c:210
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_8);

        int[] err = new int[1];
        long ref = dh.ni_generateParameters(512, err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(5212), err[0]);
    }

    @Test
    public void dh_generateParameters_paramgen_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        // Exercises interface/util/dh.c:215
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_9);

        int[] err = new int[1];
        long ref = dh.ni_generateParameters(512, err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(5213), err[0]);
    }

    @Test
    public void dh_generateParameters_specKeyNull_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        // Exercises interface/util/dh.c:220
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_10);

        int[] err = new int[1];
        long ref = dh.ni_generateParameters(512, err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(5214), err[0]);
    }


    // -----------------------------------------------------------------
    // dh_fromdata — via makeParamsFromComponents (params-only path)
    // -----------------------------------------------------------------

    @Test
    public void dh_makeParams_bnBin2bn_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        byte[] p = component(DHServiceNI.COMP_P);
        byte[] g = component(DHServiceNI.COMP_G);
        // Exercises interface/util/dh.c:272
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_6);

        int[] err = new int[1];
        long ref = dh.ni_makeParamsFromComponents(p, g, err);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(5220), err[0]);
    }

    @Test
    public void dh_makeParams_paramBldNew_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        byte[] p = component(DHServiceNI.COMP_P);
        byte[] g = component(DHServiceNI.COMP_G);
        // Exercises interface/util/dh.c:318
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_8);

        int[] err = new int[1];
        long ref = dh.ni_makeParamsFromComponents(p, g, err);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(5225), err[0]);
    }

    @Test
    public void dh_makeParams_pushPG_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        byte[] p = component(DHServiceNI.COMP_P);
        byte[] g = component(DHServiceNI.COMP_G);
        // Exercises interface/util/dh.c:323
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_9);

        int[] err = new int[1];
        long ref = dh.ni_makeParamsFromComponents(p, g, err);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(5226), err[0]);
    }

    @Test
    public void dh_makeParams_toParam_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        byte[] p = component(DHServiceNI.COMP_P);
        byte[] g = component(DHServiceNI.COMP_G);
        // Exercises interface/util/dh.c:345
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_12);

        int[] err = new int[1];
        long ref = dh.ni_makeParamsFromComponents(p, g, err);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(5229), err[0]);
    }

    @Test
    public void dh_makeParams_ctxNewFromName_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        byte[] p = component(DHServiceNI.COMP_P);
        byte[] g = component(DHServiceNI.COMP_G);
        // Exercises interface/util/dh.c:352
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);

        int[] err = new int[1];
        long ref = dh.ni_makeParamsFromComponents(p, g, err);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(5230), err[0]);
    }

    @Test
    public void dh_makeParams_fromdataInit_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        byte[] p = component(DHServiceNI.COMP_P);
        byte[] g = component(DHServiceNI.COMP_G);
        // Exercises interface/util/dh.c:357
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);

        int[] err = new int[1];
        long ref = dh.ni_makeParamsFromComponents(p, g, err);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(5231), err[0]);
    }

    @Test
    public void dh_makeParams_fromdata_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        byte[] p = component(DHServiceNI.COMP_P);
        byte[] g = component(DHServiceNI.COMP_G);
        // Exercises interface/util/dh.c:364
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_INIT_1);

        int[] err = new int[1];
        long ref = dh.ni_makeParamsFromComponents(p, g, err);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(5232), err[0]);
    }


    // -----------------------------------------------------------------
    // dh_fromdata — private-key path (x present, y computed)
    // -----------------------------------------------------------------

    @Test
    public void dh_makePrivate_bnBin2bnX_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        byte[] p = component(DHServiceNI.COMP_P);
        byte[] g = component(DHServiceNI.COMP_G);
        byte[] x = component(DHServiceNI.COMP_PRIVATE_VALUE);
        // Exercises interface/util/dh.c:288
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_4);

        int[] err = new int[1];
        long ref = dh.ni_makePrivateFromComponents(p, g, x, err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(5222), err[0]);
    }

    @Test
    public void dh_makePrivate_bnCtxNew_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        byte[] p = component(DHServiceNI.COMP_P);
        byte[] g = component(DHServiceNI.COMP_G);
        byte[] x = component(DHServiceNI.COMP_PRIVATE_VALUE);
        // Exercises interface/util/dh.c:305
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_5);

        int[] err = new int[1];
        long ref = dh.ni_makePrivateFromComponents(p, g, x, err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(5223), err[0]);
    }

    @Test
    public void dh_makePrivate_bnModExp_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        byte[] p = component(DHServiceNI.COMP_P);
        byte[] g = component(DHServiceNI.COMP_G);
        byte[] x = component(DHServiceNI.COMP_PRIVATE_VALUE);
        // Exercises interface/util/dh.c:309
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_7);

        int[] err = new int[1];
        long ref = dh.ni_makePrivateFromComponents(p, g, x, err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(5224), err[0]);
    }

    @Test
    public void dh_makePrivate_pushPub_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        byte[] p = component(DHServiceNI.COMP_P);
        byte[] g = component(DHServiceNI.COMP_G);
        byte[] x = component(DHServiceNI.COMP_PRIVATE_VALUE);
        // Exercises interface/util/dh.c:330
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_10);

        int[] err = new int[1];
        long ref = dh.ni_makePrivateFromComponents(p, g, x, err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(5227), err[0]);
    }

    @Test
    public void dh_makePrivate_pushPriv_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        byte[] p = component(DHServiceNI.COMP_P);
        byte[] g = component(DHServiceNI.COMP_G);
        byte[] x = component(DHServiceNI.COMP_PRIVATE_VALUE);
        // Exercises interface/util/dh.c:337
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_11);

        int[] err = new int[1];
        long ref = dh.ni_makePrivateFromComponents(p, g, x, err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(5228), err[0]);
    }


    // -----------------------------------------------------------------
    // dh_fromdata — public-key path (y supplied)
    // -----------------------------------------------------------------

    @Test
    public void dh_makePublic_bnBin2bnY_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        byte[] p = component(DHServiceNI.COMP_P);
        byte[] g = component(DHServiceNI.COMP_G);
        byte[] y = component(DHServiceNI.COMP_PUBLIC_VALUE);
        // Exercises interface/util/dh.c:279
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);

        int[] err = new int[1];
        long ref = dh.ni_makePublicFromComponents(p, g, y, err);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(5221), err[0]);
    }


    // -----------------------------------------------------------------
    // dh_generate_key (from established parameters)
    // -----------------------------------------------------------------

    @Test
    public void dh_generateKeyPair_ctxNewFromPkey_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        // Exercises interface/util/dh.c:477
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);

        int[] err = new int[1];
        long ref = dh.ni_generateKeyPair(paramsRef, err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(5240), err[0]);
    }

    @Test
    public void dh_generateKeyPair_keygenInit_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        // Exercises interface/util/dh.c:482
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_4);

        int[] err = new int[1];
        long ref = dh.ni_generateKeyPair(paramsRef, err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(5241), err[0]);
    }

    @Test
    public void dh_generateKeyPair_keygen_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        // Exercises interface/util/dh.c:487
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_5);

        int[] err = new int[1];
        long ref = dh.ni_generateKeyPair(paramsRef, err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(5242), err[0]);
    }

    @Test
    public void dh_generateKeyPair_specKeyNull_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        // Exercises interface/util/dh.c:492
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_6);

        int[] err = new int[1];
        long ref = dh.ni_generateKeyPair(paramsRef, err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(5243), err[0]);
    }


    // -----------------------------------------------------------------
    // get_bn_component
    // -----------------------------------------------------------------

    @Test
    public void dh_getComponent_getBnParam_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        // Exercises interface/util/dh.c:519
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_7);

        int code = dh.ni_getComponent(keyRef, DHServiceNI.COMP_P, new byte[512]);
        Assertions.assertEquals(errorAt(5250), code);
    }

    @Test
    public void dh_getComponent_bnNumBytes_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        // Exercises interface/util/dh.c:525
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_8);

        int code = dh.ni_getComponent(keyRef, DHServiceNI.COMP_P, new byte[512]);
        Assertions.assertEquals(errorAt(5251), code);
    }

    @Test
    public void dh_getComponent_bn2bin_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        // Exercises interface/util/dh.c:541
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_9);

        int code = dh.ni_getComponent(keyRef, DHServiceNI.COMP_P, new byte[512]);
        Assertions.assertEquals(errorAt(5252), code);
    }


    // -----------------------------------------------------------------
    // dh_kex_init / set_peer / derive
    // -----------------------------------------------------------------

    @Test
    public void dh_kexInit_ctxNewFromPkey_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        long ref = dh.allocateKex();
        try
        {
            // Exercises interface/util/dh.c:645
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_11);
            int code = dh.ni_kexInit(ref, keyRef, TestUtil.RNDSrc);
            Assertions.assertEquals(errorAt(5260), code);
        }
        finally
        {
            ops.resetFlags();
            dh.disposeKex(ref);
        }
    }

    @Test
    public void dh_kexInit_deriveInit_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        long ref = dh.allocateKex();
        try
        {
            // Exercises interface/util/dh.c:649
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_12);
            int code = dh.ni_kexInit(ref, keyRef, TestUtil.RNDSrc);
            Assertions.assertEquals(errorAt(5261), code);
        }
        finally
        {
            ops.resetFlags();
            dh.disposeKex(ref);
        }
    }

    @Test
    public void dh_kexInit_padSetParams_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        long ref = dh.allocateKex();
        try
        {
            // Exercises interface/util/dh.c:670
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_INIT_2);
            int code = dh.ni_kexInit(ref, keyRef, TestUtil.RNDSrc);
            Assertions.assertEquals(errorAt(5262), code);
        }
        finally
        {
            ops.resetFlags();
            dh.disposeKex(ref);
        }
    }

    @Test
    public void dh_kexSetPeer_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        long ref = dh.allocateKex();
        try
        {
            dh.kexInit(ref, keyRef, TestUtil.RNDSrc);
            // Exercises interface/util/dh.c:709
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            int code = dh.ni_kexSetPeer(ref, peerRef, TestUtil.RNDSrc);
            Assertions.assertEquals(errorAt(5270), code);
        }
        finally
        {
            ops.resetFlags();
            dh.disposeKex(ref);
        }
    }

    @Test
    public void dh_kexDerive_probe_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        long ref = dh.allocateKex();
        try
        {
            dh.kexInit(ref, keyRef, TestUtil.RNDSrc);
            dh.kexSetPeer(ref, peerRef, TestUtil.RNDSrc);
            // Exercises interface/util/dh.c:740
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            int code = dh.ni_kexDerive(ref, null, 0, TestUtil.RNDSrc);
            Assertions.assertEquals(errorAt(5280), code);
        }
        finally
        {
            ops.resetFlags();
            dh.disposeKex(ref);
        }
    }

    @Test
    public void dh_kexDerive_fetch_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        long ref = dh.allocateKex();
        try
        {
            dh.kexInit(ref, keyRef, TestUtil.RNDSrc);
            dh.kexSetPeer(ref, peerRef, TestUtil.RNDSrc);
            // Exercises interface/util/dh.c:757
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);
            int code = dh.ni_kexDerive(ref, new byte[256], 0, TestUtil.RNDSrc);
            Assertions.assertEquals(errorAt(5281), code);
        }
        finally
        {
            ops.resetFlags();
            dh.disposeKex(ref);
        }
    }

    @Test
    public void dh_kexDerive_needOverflow_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        long ref = dh.allocateKex();
        try
        {
            dh.kexInit(ref, keyRef, TestUtil.RNDSrc);
            dh.kexSetPeer(ref, peerRef, TestUtil.RNDSrc);
            // Exercises interface/util/dh.c:744
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);
            int code = dh.ni_kexDerive(ref, null, 0, TestUtil.RNDSrc);
            Assertions.assertEquals(JO_OUTPUT_TOO_LONG_INT32, code);
        }
        finally
        {
            ops.resetFlags();
            dh.disposeKex(ref);
        }
    }


    // -----------------------------------------------------------------
    // JNI access faults (OPS_FAILED_ACCESS_*) — JNI-only. The FFI
    // bridge has no JVM array-access path so the tests are guarded by
    // Loader.isFFI().
    // -----------------------------------------------------------------

    @Test
    public void dh_groupSupported_accessName_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        try
        {
            // Exercises interface/jni/dh_ni_jni.c:41
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            int code = dh.ni_groupSupported("ffdhe2048");
            Assertions.assertEquals(JO_UNABLE_TO_ACCESS_NAME, code);
        }
        finally
        {
            ops.resetFlags();
        }
    }

    @Test
    public void dh_generateKeyPairByGroup_accessName_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        try
        {
            // Exercises interface/jni/dh_ni_jni.c:76
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            int[] err = new int[1];
            long ref = dh.ni_generateKeyPairByGroup("ffdhe2048", err, TestUtil.RNDSrc);
            Assertions.assertEquals(0L, ref);
            Assertions.assertEquals(JO_UNABLE_TO_ACCESS_NAME, err[0]);
        }
        finally
        {
            ops.resetFlags();
        }
    }

    @Test
    public void dh_makeParams_accessP_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        byte[] p = component(DHServiceNI.COMP_P);
        byte[] g = component(DHServiceNI.COMP_G);
        try
        {
            // Exercises interface/jni/dh_ni_jni.c:161
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            int[] err = new int[1];
            long ref = dh.ni_makeParamsFromComponents(p, g, err);
            Assertions.assertEquals(0L, ref);
            Assertions.assertEquals(JO_FAILED_ACCESS_INPUT, err[0]);
        }
        finally
        {
            ops.resetFlags();
        }
    }

    @Test
    public void dh_makeParams_accessG_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        byte[] p = component(DHServiceNI.COMP_P);
        byte[] g = component(DHServiceNI.COMP_G);
        try
        {
            // Exercises interface/jni/dh_ni_jni.c:165
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_2);
            int[] err = new int[1];
            long ref = dh.ni_makeParamsFromComponents(p, g, err);
            Assertions.assertEquals(0L, ref);
            Assertions.assertEquals(JO_FAILED_ACCESS_INPUT, err[0]);
        }
        finally
        {
            ops.resetFlags();
        }
    }

    @Test
    public void dh_makePrivate_accessX_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        byte[] p = component(DHServiceNI.COMP_P);
        byte[] g = component(DHServiceNI.COMP_G);
        byte[] x = component(DHServiceNI.COMP_PRIVATE_VALUE);
        try
        {
            // Exercises interface/jni/dh_ni_jni.c:272
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_3);
            int[] err = new int[1];
            long ref = dh.ni_makePrivateFromComponents(p, g, x, err, TestUtil.RNDSrc);
            Assertions.assertEquals(0L, ref);
            Assertions.assertEquals(JO_FAILED_ACCESS_INPUT, err[0]);
        }
        finally
        {
            ops.resetFlags();
        }
    }

    @Test
    public void dh_makePublic_accessY_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        byte[] p = component(DHServiceNI.COMP_P);
        byte[] g = component(DHServiceNI.COMP_G);
        byte[] y = component(DHServiceNI.COMP_PUBLIC_VALUE);
        try
        {
            // Exercises interface/jni/dh_ni_jni.c:335
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_3);
            int[] err = new int[1];
            long ref = dh.ni_makePublicFromComponents(p, g, y, err);
            Assertions.assertEquals(0L, ref);
            Assertions.assertEquals(JO_FAILED_ACCESS_INPUT, err[0]);
        }
        finally
        {
            ops.resetFlags();
        }
    }

    @Test
    public void dh_getComponent_accessOutput_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        try
        {
            // Exercises interface/jni/dh_ni_jni.c:388
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            int code = dh.ni_getComponent(keyRef, DHServiceNI.COMP_P, new byte[512]);
            Assertions.assertEquals(JO_FAILED_ACCESS_OUTPUT, code);
        }
        finally
        {
            ops.resetFlags();
        }
    }

    @Test
    public void dh_kexDerive_accessOutput_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        long ref = dh.allocateKex();
        try
        {
            dh.kexInit(ref, keyRef, TestUtil.RNDSrc);
            dh.kexSetPeer(ref, peerRef, TestUtil.RNDSrc);
            // Exercises interface/jni/dh_ni_jni.c:518
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            int code = dh.ni_kexDerive(ref, new byte[256], 0, TestUtil.RNDSrc);
            Assertions.assertEquals(JO_FAILED_ACCESS_OUTPUT, code);
        }
        finally
        {
            ops.resetFlags();
            dh.disposeKex(ref);
        }
    }
}
