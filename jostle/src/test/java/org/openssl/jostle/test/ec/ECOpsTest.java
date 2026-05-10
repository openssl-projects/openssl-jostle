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
 * <h2>Offset map (mirror of the {@code OPS_OFFSET_*} sites in
 * {@code interface/util/ec.c}; range 3000-3099)</h2>
 *
 * <pre>
 *   ec_generate_key                3000-3004 (flags 1-5)
 *   ec_make_private_from_components 3010-3018 (flags 6-12, then 1, 2)
 *   ec_ctx_init_sign               3020-3021 (flags 3, 4)
 *   ec_ctx_init_verify             3030-3031 (flags 5, 6)
 *   ec_ctx_update                  3040 / 3041 (flag 7)
 *   ec_ctx_sign                    3050 / 3051 (flags 8, 9)
 *   ec_ctx_verify                  3060      (flag 10)
 *   ec_kex_init                    3070-3071 (flags 11, 12)
 *   ec_kex_set_peer                3080      (flag 1)
 *   ec_kex_derive                  3090 / 3091 (flag 2)
 * </pre>
 */
public class ECOpsTest
{
    private static final int JO_OPENSSL_ERROR = -2;

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
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            // The probe site (3090) fires first because the same flag
            // matches both probe and fetch — caller has to drive a
            // separate path to test fetch in isolation. Here we just
            // confirm the flag fires on the first matching site.
            int code = ec.ni_kexDerive(kexRef, new byte[64], 0, TestUtil.RNDSrc);
            Assertions.assertEquals(errorAt(3090), code);
        }
        finally
        {
            ec.disposeKex(kexRef);
            specNI.dispose(keyRef);
            specNI.dispose(peerRef);
        }
    }
}
