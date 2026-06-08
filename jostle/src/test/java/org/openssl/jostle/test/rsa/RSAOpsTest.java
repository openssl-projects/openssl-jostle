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

package org.openssl.jostle.test.rsa;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.AccessException;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.OpenSSL;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.OverflowException;
import org.openssl.jostle.jcajce.provider.rsa.RSAServiceNI;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.test.crypto.TestNISelector;
import org.openssl.jostle.util.ops.OperationsTestNI;

import java.security.Security;

/**
 * Fault-injection tests for the RSA NI layer. Each test sets exactly one
 * {@code OPS_*} flag in the C-side instrumentation, drives the matching
 * native function, and asserts that the resulting error code or thrown
 * exception matches the expected failure path.
 *
 * <p>All tests are guarded by {@link OperationsTestNI#opsTestAvailable()}
 * so they no-op on a release native build. JNI-specific
 * {@code OPS_FAILED_ACCESS_*} tests are additionally guarded by
 * {@code Assumptions.assumeFalse(Loader.isFFI())} because the FFI bridge
 * does not use {@code GetByteArrayElements} and so cannot fault those
 * access points.
 */
public class RSAOpsTest
{
    private static final byte[] PUB_EXP_F4 = {0x01, 0x00, 0x01};

    RSAServiceNI rsaServiceNI = TestNISelector.getRSANi();
    SpecNI specNI = TestNISelector.getSpecNI();
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


    // -----------------------------------------------------------------
    // generateKeyPair
    // -----------------------------------------------------------------

    @Test
    public void RSA_generateKeyPair_failedAccessPubExp() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());

        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access input array", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void RSA_generateKeyPair_opensslError() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        try
        {
            OpenSSL.getOpenSSLErrors(); // purge any earlier errors
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (OpenSSLException e)
        {
            // The instrumentation pretends keygen succeeded but cleared
            // spec->key, so no real OSSL error is queued — message will
            // be "OpenSSL Error: null".
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }


    // -----------------------------------------------------------------
    // decode component access faults (JNI-only)
    // -----------------------------------------------------------------

    @Test
    public void RSA_decodePublicComponents_failedAccess() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());

        long keyRef = 0;
        try
        {
            keyRef = specNI.allocate();
            Assertions.assertTrue(keyRef > 0);
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            rsaServiceNI.decodePublicComponents(keyRef, new byte[]{0x01}, PUB_EXP_F4);
            Assertions.fail();
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access input array", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSA_decodePrivateComponents_failedAccess_n() throws Exception
    {
        runDecodePrivateComponentsAccessFailure(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
    }

    @Test
    public void RSA_decodePrivateComponents_failedAccess_e() throws Exception
    {
        runDecodePrivateComponentsAccessFailure(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_2);
    }

    @Test
    public void RSA_decodePrivateComponents_failedAccess_d() throws Exception
    {
        runDecodePrivateComponentsAccessFailure(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_3);
    }

    private void runDecodePrivateComponentsAccessFailure(OperationsTestNI.OpsTestFlag flag) throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());

        long keyRef = 0;
        try
        {
            keyRef = specNI.allocate();
            Assertions.assertTrue(keyRef > 0);
            operationsTestNI.setFlag(flag);
            rsaServiceNI.decodePrivateComponents(keyRef,
                    new byte[]{0x01}, PUB_EXP_F4, new byte[]{0x01});
            Assertions.fail();
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access input array", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSA_decodePrivateComponentsCrt_failedAccess_n() throws Exception
    {
        runDecodePrivateComponentsCrtAccessFailure(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
    }

    @Test
    public void RSA_decodePrivateComponentsCrt_failedAccess_e() throws Exception
    {
        runDecodePrivateComponentsCrtAccessFailure(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_2);
    }

    @Test
    public void RSA_decodePrivateComponentsCrt_failedAccess_d() throws Exception
    {
        runDecodePrivateComponentsCrtAccessFailure(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_3);
    }

    @Test
    public void RSA_decodePrivateComponentsCrt_failedAccess_p() throws Exception
    {
        runDecodePrivateComponentsCrtAccessFailure(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_4);
    }

    private void runDecodePrivateComponentsCrtAccessFailure(OperationsTestNI.OpsTestFlag flag) throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());

        byte[] one = {0x01};
        long keyRef = 0;
        try
        {
            keyRef = specNI.allocate();
            Assertions.assertTrue(keyRef > 0);
            operationsTestNI.setFlag(flag);
            rsaServiceNI.decodePrivateComponentsCrt(keyRef,
                    one, PUB_EXP_F4, one,
                    one, one,
                    one, one, one);
            Assertions.fail();
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access input array", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSA_getComponent_failedAccessOutput() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());

        long keyRef = 0;
        try
        {
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            Assertions.assertTrue(keyRef > 0);

            int len = rsaServiceNI.getComponent(keyRef, RSAServiceNI.COMP_MODULUS, null);
            Assertions.assertTrue(len > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            rsaServiceNI.getComponent(keyRef, RSAServiceNI.COMP_MODULUS, new byte[len]);
            Assertions.fail();
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access output array", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }


    // -----------------------------------------------------------------
    // initSign / initVerify — JNI access faults (digest / mgf1 string fetch).
    // These exercise rsa_init_strings_load in interface/jni/rsa_ni_jni.c,
    // shared by both initSign and initVerify. JNI-only.
    // -----------------------------------------------------------------

    /**
     * Target: {@code interface/jni/rsa_ni_jni.c:366} — fault-injects the
     * {@code GetStringUTFChars(digest)} failure inside {@code rsa_init_strings_load},
     * the helper shared by {@code ni_initSign} and {@code ni_initVerify}.
     */
    @Test
    public void RSA_initSign_accessDigestName_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());

        long rsaRef = 0;
        long keyRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            Assertions.assertTrue(rsaRef > 0);
            Assertions.assertTrue(keyRef > 0);

            // Exercises interface/jni/rsa_ni_jni.c:366
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            rsaServiceNI.initSign(rsaRef, keyRef, "SHA-256",
                    RSAServiceNI.PADDING_PKCS1, null, 0, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IllegalStateException e)
        {
            Assertions.assertEquals("unable to access name", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }

    /**
     * Target: {@code interface/jni/rsa_ni_jni.c:372} — fault-injects the
     * {@code GetStringUTFChars(mgf1)} failure inside {@code rsa_init_strings_load}.
     * PSS padding is used so {@code mgf1_str} is non-null and the mgf1 fetch
     * actually runs.
     */
    @Test
    public void RSA_initSign_accessMgf1Name_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());

        long rsaRef = 0;
        long keyRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            Assertions.assertTrue(rsaRef > 0);
            Assertions.assertTrue(keyRef > 0);

            // Exercises interface/jni/rsa_ni_jni.c:372
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_2);
            rsaServiceNI.initSign(rsaRef, keyRef, "SHA-256",
                    RSAServiceNI.PADDING_PSS, "SHA-256", -1, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IllegalStateException e)
        {
            Assertions.assertEquals("unable to access name", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }


    // -----------------------------------------------------------------
    // initSign — distinguishable failure paths via offset codes
    // -----------------------------------------------------------------

    @Test
    public void RSA_initSign_evpMdCtxNew_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long rsaRef = 0;
        long keyRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            Assertions.assertTrue(rsaRef > 0);
            Assertions.assertTrue(keyRef > 0);

            // Exercises interface/util/rsa.c:589
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            int code = rsaServiceNI.ni_initSign(rsaRef, keyRef, "SHA-256",
                    RSAServiceNI.PADDING_PKCS1, null, 0, TestUtil.RNDSrc);
            // Offset = -1002 (JO_OPENSSL_ERROR is -2, offset adds -1000).
            Assertions.assertEquals(-1002, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSA_initSign_digestSignInit_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long rsaRef = 0;
        long keyRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            Assertions.assertTrue(rsaRef > 0);
            Assertions.assertTrue(keyRef > 0);

            // Exercises interface/util/rsa.c:594
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            int code = rsaServiceNI.ni_initSign(rsaRef, keyRef, "SHA-256",
                    RSAServiceNI.PADDING_PKCS1, null, 0, TestUtil.RNDSrc);
            Assertions.assertEquals(-1003, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }


    // -----------------------------------------------------------------
    // configure_padding (called via initSign / initVerify) — OPS coverage
    // for each OpenSSL call inside the static helper.
    // -----------------------------------------------------------------

    @Test
    public void RSA_configurePadding_pkcs1_setRsaPadding_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long rsaRef = 0;
        long keyRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            Assertions.assertTrue(rsaRef > 0);
            Assertions.assertTrue(keyRef > 0);

            // Exercises interface/util/rsa.c:515
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);
            int code = rsaServiceNI.ni_initSign(rsaRef, keyRef, "SHA-256",
                    RSAServiceNI.PADDING_PKCS1, null, 0, TestUtil.RNDSrc);
            // JO_OPENSSL_ERROR (-2) + offset(-1020) = -1022.
            Assertions.assertEquals(-1022, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSA_configurePadding_pss_setRsaPadding_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long rsaRef = 0;
        long keyRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            Assertions.assertTrue(rsaRef > 0);
            Assertions.assertTrue(keyRef > 0);

            // Exercises interface/util/rsa.c:522
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_4);
            int code = rsaServiceNI.ni_initSign(rsaRef, keyRef, "SHA-256",
                    RSAServiceNI.PADDING_PSS, "SHA-256", -1, TestUtil.RNDSrc);
            // -2 + (-1021) = -1023.
            Assertions.assertEquals(-1023, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSA_configurePadding_pss_setMgf1MdName_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long rsaRef = 0;
        long keyRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            Assertions.assertTrue(rsaRef > 0);
            Assertions.assertTrue(keyRef > 0);

            // Exercises interface/util/rsa.c:531
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_5);
            int code = rsaServiceNI.ni_initSign(rsaRef, keyRef, "SHA-256",
                    RSAServiceNI.PADDING_PSS, "SHA-256", -1, TestUtil.RNDSrc);
            // -2 + (-1022) = -1024.
            Assertions.assertEquals(-1024, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSA_configurePadding_pss_setSaltLen_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long rsaRef = 0;
        long keyRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            Assertions.assertTrue(rsaRef > 0);
            Assertions.assertTrue(keyRef > 0);

            // Exercises interface/util/rsa.c:537
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_6);
            int code = rsaServiceNI.ni_initSign(rsaRef, keyRef, "SHA-256",
                    RSAServiceNI.PADDING_PSS, "SHA-256", -1, TestUtil.RNDSrc);
            // -2 + (-1023) = -1025.
            Assertions.assertEquals(-1025, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }

    /**
     * configure_padding is shared by sign and verify. Sanity-check that the
     * verify path also surfaces the PSS set-padding failure with the same
     * offset code.
     */
    @Test
    public void RSA_configurePadding_pss_setRsaPadding_failure_onVerify() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long rsaRef = 0;
        long keyRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);

            // Exercises interface/util/rsa.c:522
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_4);
            int code = rsaServiceNI.ni_initVerify(rsaRef, keyRef, "SHA-256",
                    RSAServiceNI.PADDING_PSS, "SHA-256", -1);
            Assertions.assertEquals(-1023, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }


    // -----------------------------------------------------------------
    // fromdata_construct — OPS coverage for each OpenSSL call inside the
    // static helper. Reachable via decodePublicComponents (and its private
    // siblings); using the public path keeps the input minimal.
    // -----------------------------------------------------------------

    @Test
    public void RSA_fromdataConstruct_bldToParam_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = 0;
        try
        {
            keyRef = specNI.allocate();
            Assertions.assertTrue(keyRef > 0);

            // Exercises interface/util/rsa.c:79
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_7);
            int code = rsaServiceNI.ni_decodePublicComponents(keyRef,
                    new byte[]{0x01}, PUB_EXP_F4);
            // -2 + (-1030) = -1032.
            Assertions.assertEquals(-1032, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSA_fromdataConstruct_ctxNewFromName_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = 0;
        try
        {
            keyRef = specNI.allocate();
            Assertions.assertTrue(keyRef > 0);

            // Exercises interface/util/rsa.c:85
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_8);
            int code = rsaServiceNI.ni_decodePublicComponents(keyRef,
                    new byte[]{0x01}, PUB_EXP_F4);
            Assertions.assertEquals(-1033, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSA_fromdataConstruct_fromdataInit_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = 0;
        try
        {
            keyRef = specNI.allocate();
            Assertions.assertTrue(keyRef > 0);

            // Exercises interface/util/rsa.c:90
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_9);
            int code = rsaServiceNI.ni_decodePublicComponents(keyRef,
                    new byte[]{0x01}, PUB_EXP_F4);
            Assertions.assertEquals(-1034, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSA_fromdataConstruct_fromdata_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = 0;
        try
        {
            keyRef = specNI.allocate();
            Assertions.assertTrue(keyRef > 0);

            // Exercises interface/util/rsa.c:95
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_10);
            int code = rsaServiceNI.ni_decodePublicComponents(keyRef,
                    new byte[]{0x01}, PUB_EXP_F4);
            Assertions.assertEquals(-1035, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }


    // -----------------------------------------------------------------
    // initVerify
    // -----------------------------------------------------------------

    /**
     * Regression test for the init-failure-leaves-state bug: when
     * {@code EVP_DigestSignInit_ex} fails partway through
     * {@code rsa_ctx_init_sign}, the ctx must NOT be left with
     * {@code digest_ctx} non-null and a stale {@code opp} value.
     * Subsequent {@code update} / {@code sign} must return
     * {@code JO_NOT_INITIALIZED}, not dispatch into a half-configured
     * digest_ctx (which is undefined behaviour inside libcrypto).
     */
    @Test
    public void RSA_initSign_failure_leavesCtxNotInitialized() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long rsaRef = 0;
        long keyRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            Assertions.assertTrue(rsaRef > 0);
            Assertions.assertTrue(keyRef > 0);

            // First init: succeeds. Sets ctx->digest_ctx and ctx->opp.
            rsaServiceNI.initSign(rsaRef, keyRef, "SHA-256",
                    RSAServiceNI.PADDING_PKCS1, null, 0, TestUtil.RNDSrc);

            // Second init: forced to fail at EVP_DigestSignInit_ex.
            // Exercises interface/util/rsa.c:594
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            int code = rsaServiceNI.ni_initSign(rsaRef, keyRef, "SHA-256",
                    RSAServiceNI.PADDING_PKCS1, null, 0, TestUtil.RNDSrc);
            Assertions.assertEquals(-1003, code);
            operationsTestNI.resetFlags();

            // Now attempt to update on the post-failed-init context.
            // Pre-fix bug: digest_ctx still allocated + opp == RSA_OP_SIGN
            // from the FIRST init, so update would dispatch into a
            // half-configured digest_ctx → undefined behaviour. After the
            // fix init clears state up-front, so update sees digest_ctx
            // == NULL and rejects cleanly.
            try
            {
                rsaServiceNI.update(rsaRef, new byte[]{1, 2, 3}, 0, 3);
                Assertions.fail("update on context with failed init must reject");
            }
            catch (IllegalStateException e)
            {
                Assertions.assertEquals("not initialized", e.getMessage());
            }
        }
        finally
        {
            operationsTestNI.resetFlags();
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSA_initVerify_failure_leavesCtxNotInitialized() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long rsaRef = 0;
        long keyRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);

            rsaServiceNI.initVerify(rsaRef, keyRef, "SHA-256",
                    RSAServiceNI.PADDING_PKCS1, null, 0);

            // Exercises interface/util/rsa.c:661
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            int code = rsaServiceNI.ni_initVerify(rsaRef, keyRef, "SHA-256",
                    RSAServiceNI.PADDING_PKCS1, null, 0);
            Assertions.assertEquals(-1006, code);
            operationsTestNI.resetFlags();

            try
            {
                rsaServiceNI.verify(rsaRef, new byte[]{0}, 1);
                Assertions.fail("verify on context with failed init must reject");
            }
            catch (IllegalStateException e)
            {
                Assertions.assertEquals("not initialized", e.getMessage());
            }
        }
        finally
        {
            operationsTestNI.resetFlags();
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSA_initVerify_evpMdCtxNew_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long rsaRef = 0;
        long keyRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            Assertions.assertTrue(rsaRef > 0);
            Assertions.assertTrue(keyRef > 0);

            // Exercises interface/util/rsa.c:656
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            int code = rsaServiceNI.ni_initVerify(rsaRef, keyRef, "SHA-256",
                    RSAServiceNI.PADDING_PKCS1, null, 0);
            Assertions.assertEquals(-1005, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSA_initVerify_digestVerifyInit_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long rsaRef = 0;
        long keyRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            Assertions.assertTrue(rsaRef > 0);
            Assertions.assertTrue(keyRef > 0);

            // Exercises interface/util/rsa.c:661
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            int code = rsaServiceNI.ni_initVerify(rsaRef, keyRef, "SHA-256",
                    RSAServiceNI.PADDING_PKCS1, null, 0);
            Assertions.assertEquals(-1006, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }


    // -----------------------------------------------------------------
    // update
    // -----------------------------------------------------------------

    @Test
    public void RSA_update_failedAccessInput() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());

        long rsaRef = 0;
        long keyRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            rsaServiceNI.initSign(rsaRef, keyRef, "SHA-256",
                    RSAServiceNI.PADDING_PKCS1, null, 0, TestUtil.RNDSrc);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            rsaServiceNI.update(rsaRef, new byte[16], 0, 16);
            Assertions.fail();
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access input array", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }


    // -----------------------------------------------------------------
    // sign
    // -----------------------------------------------------------------

    @Test
    public void RSA_sign_failedAccessOutput() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());

        long rsaRef = 0;
        long keyRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            rsaServiceNI.initSign(rsaRef, keyRef, "SHA-256",
                    RSAServiceNI.PADDING_PKCS1, null, 0, TestUtil.RNDSrc);

            int needed = rsaServiceNI.sign(rsaRef, null, 0, TestUtil.RNDSrc);
            Assertions.assertTrue(needed > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            rsaServiceNI.sign(rsaRef, new byte[needed], 0, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access output array", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSA_sign_lenQuery_opensslError() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long rsaRef = 0;
        long keyRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            rsaServiceNI.initSign(rsaRef, keyRef, "SHA-256",
                    RSAServiceNI.PADDING_PKCS1, null, 0, TestUtil.RNDSrc);

            OpenSSL.getOpenSSLErrors(); // purge
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            rsaServiceNI.sign(rsaRef, null, 0, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (OpenSSLException e)
        {
            Assertions.assertTrue(e.getMessage().startsWith("OpenSSL Error:"),
                    "expected OpenSSL Error prefix, got: " + e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSA_sign_lenInt32Overflow() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long rsaRef = 0;
        long keyRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            rsaServiceNI.initSign(rsaRef, keyRef, "SHA-256",
                    RSAServiceNI.PADDING_PKCS1, null, 0, TestUtil.RNDSrc);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);
            rsaServiceNI.sign(rsaRef, null, 0, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (OverflowException e)
        {
            Assertions.assertEquals("output too long int32", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSA_sign_finalCalc_opensslError() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long rsaRef = 0;
        long keyRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            rsaServiceNI.initSign(rsaRef, keyRef, "SHA-256",
                    RSAServiceNI.PADDING_PKCS1, null, 0, TestUtil.RNDSrc);

            int needed = rsaServiceNI.sign(rsaRef, null, 0, TestUtil.RNDSrc);

            OpenSSL.getOpenSSLErrors(); // purge
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            rsaServiceNI.sign(rsaRef, new byte[needed], 0, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (OpenSSLException e)
        {
            Assertions.assertTrue(e.getMessage().startsWith("OpenSSL Error:"),
                    "expected OpenSSL Error prefix, got: " + e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSA_sign_unexpectedSigLenChange() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long rsaRef = 0;
        long keyRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            rsaServiceNI.initSign(rsaRef, keyRef, "SHA-256",
                    RSAServiceNI.PADDING_PKCS1, null, 0, TestUtil.RNDSrc);

            int needed = rsaServiceNI.sign(rsaRef, null, 0, TestUtil.RNDSrc);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_LEN_CHANGE_1);
            rsaServiceNI.sign(rsaRef, new byte[needed], 0, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IllegalStateException e)
        {
            Assertions.assertEquals("unexpected sig length change", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }


    // -----------------------------------------------------------------
    // verify
    // -----------------------------------------------------------------

    @Test
    public void RSA_verify_failedAccessSig() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());

        long rsaRef = 0;
        long keyRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            rsaServiceNI.initVerify(rsaRef, keyRef, "SHA-256",
                    RSAServiceNI.PADDING_PKCS1, null, 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            rsaServiceNI.verify(rsaRef, new byte[1], 1);
            Assertions.fail();
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access signature array", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSA_verify_opensslError() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long rsaRef = 0;
        long keyRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            rsaServiceNI.initVerify(rsaRef, keyRef, "SHA-256",
                    RSAServiceNI.PADDING_PKCS1, null, 0);

            OpenSSL.getOpenSSLErrors(); // purge
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            // Pass a deliberately-wrong-length signature; even if the
            // instrumentation didn't trip, the real EVP_DigestVerifyFinal
            // would also fail. The instrumentation forces ret = -1 which
            // is the structural-error branch.
            rsaServiceNI.verify(rsaRef, new byte[1], 1);
            Assertions.fail();
        }
        catch (OpenSSLException e)
        {
            // Real OSSL errors may or may not be queued depending on order
            // of evaluation; either "OpenSSL Error: null" or a populated
            // error message is acceptable.
            Assertions.assertTrue(e.getMessage().startsWith("OpenSSL Error:"),
                    "expected OpenSSL Error prefix, got: " + e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }


    // -----------------------------------------------------------------
    // generateKeyPair — exhaustive OPS coverage of the OpenSSL-error
    // branches inside rsa_generate_key (keygen_init, set_keygen_bits,
    // BN_bin2bn, set1_rsa_keygen_pubexp). Each one a distinct slot so
    // tests can isolate which call failed via the offset.
    // -----------------------------------------------------------------

    @Test
    public void RSA_generateKeyPair_keygenInit_failure() throws Exception
    {
        runGenerateKeyPairOpsCodeAssertion(
                OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2, -1042);
    }

    @Test
    public void RSA_generateKeyPair_setKeygenBits_failure() throws Exception
    {
        runGenerateKeyPairOpsCodeAssertion(
                OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3, -1043);
    }

    @Test
    public void RSA_generateKeyPair_bnBin2bn_failure() throws Exception
    {
        runGenerateKeyPairOpsCodeAssertion(
                OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_4, -1044);
    }

    @Test
    public void RSA_generateKeyPair_set1PubExp_failure() throws Exception
    {
        runGenerateKeyPairOpsCodeAssertion(
                OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_5, -1045);
    }

    private void runGenerateKeyPairOpsCodeAssertion(
            OperationsTestNI.OpsTestFlag flag, int expectedCode) throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        try
        {
            operationsTestNI.setFlag(flag);
            int[] err = new int[1];
            long ref = rsaServiceNI.ni_generateKeyPair(2048, PUB_EXP_F4, err, TestUtil.RNDSrc);
            // OPS-injected failure: the native side returns 0 ref + a
            // negative err[0] indicating which fault point fired.
            Assertions.assertEquals(0L, ref);
            Assertions.assertEquals(expectedCode, err[0]);
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }


    // -----------------------------------------------------------------
    // decodePublicComponents / decodePrivateComponents — BN-allocation
    // and OSSL_PARAM_BLD failure branches inside the decoders.
    // -----------------------------------------------------------------

    @Test
    public void RSA_decodePublic_bnBin2bn_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = 0;
        try
        {
            keyRef = specNI.allocate();
            Assertions.assertTrue(keyRef > 0);

            // Exercises interface/util/rsa.c:231
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            int code = rsaServiceNI.ni_decodePublicComponents(keyRef,
                    new byte[]{0x01}, PUB_EXP_F4);
            // -2 + (-1050) = -1052.
            Assertions.assertEquals(-1052, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSA_decodePublic_paramBldNew_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = 0;
        try
        {
            keyRef = specNI.allocate();
            Assertions.assertTrue(keyRef > 0);

            // Exercises interface/util/rsa.c:236
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_11);
            int code = rsaServiceNI.ni_decodePublicComponents(keyRef,
                    new byte[]{0x01}, PUB_EXP_F4);
            // -2 + (-1051) = -1053.
            Assertions.assertEquals(-1053, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSA_decodePublic_paramBldPushBN_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = 0;
        try
        {
            keyRef = specNI.allocate();
            Assertions.assertTrue(keyRef > 0);

            // Exercises interface/util/rsa.c:241
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_12);
            int code = rsaServiceNI.ni_decodePublicComponents(keyRef,
                    new byte[]{0x01}, PUB_EXP_F4);
            // -2 + (-1052) = -1054.
            Assertions.assertEquals(-1054, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSA_decodePrivate_bnAllocChain_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = 0;
        try
        {
            keyRef = specNI.allocate();
            Assertions.assertTrue(keyRef > 0);

            // Slot _3 is shared with rsa_generate_key (set_rsa_keygen_bits)
            // and configure_padding (PKCS1 set_rsa_padding); within the
            // decode-private code path it fires on the BN-allocation
            // chain (n_bn || e_bn || d_bn == NULL).
            // Exercises interface/util/rsa.c:283
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);
            int code = rsaServiceNI.ni_decodePrivateComponents(keyRef,
                    new byte[]{0x01}, PUB_EXP_F4, new byte[]{0x01});
            // -2 + (-1060) = -1062.
            Assertions.assertEquals(-1062, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSA_decodePrivate_bnBin2bnD_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = 0;
        try
        {
            keyRef = specNI.allocate();
            Assertions.assertTrue(keyRef > 0);

            // Exercises interface/util/rsa.c:287
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_4);
            int code = rsaServiceNI.ni_decodePrivateComponents(keyRef,
                    new byte[]{0x01}, PUB_EXP_F4, new byte[]{0x01});
            // -2 + (-1061) = -1063.
            Assertions.assertEquals(-1063, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }


    // -----------------------------------------------------------------
    // rsa_generate_key — additional EVP failure points.
    //
    // Existing tests already cover keygen_init, set_rsa_keygen_bits,
    // BN_bin2bn, set1_rsa_keygen_pubexp, and the post-keygen NULL
    // check. The two below add the remaining EVP calls:
    //
    //   1. EVP_PKEY_CTX_new_from_name (line 148) — context allocation.
    //   2. EVP_PKEY_keygen (line 176) — the actual keygen call (distinct
    //      from the post-keygen NULL-trick path the existing
    //      RSA_generateKeyPair_opensslError test covers via OPS_OPENSSL_ERROR_1).
    //
    // Slots _6 / _7 are reused — they currently fire in
    // configure_padding (PSS saltlen) and fromdata_construct (BLD_to_param)
    // respectively, neither of which is reached from rsa_generate_key.
    // -----------------------------------------------------------------

    @Test
    public void RSA_generateKeyPair_ctxNewFromName_failure() throws Exception
    {
        runGenerateKeyPairOpsCodeAssertion(
                OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_6, -1046);
    }

    @Test
    public void RSA_generateKeyPair_evpKeygen_failure() throws Exception
    {
        runGenerateKeyPairOpsCodeAssertion(
                OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_7, -1047);
    }


    // -----------------------------------------------------------------
    // rsa_get_component — EVP_PKEY_get_bn_param failure.
    //
    // The real failure path here is "component absent on this key"
    // (e.g. requesting d on a public-only key), which returns a bare
    // JO_OPENSSL_ERROR = -2 that the SPI's RSAComponents.getOptional
    // maps to a null component. The OPS injection returns a
    // distinguishable -1072 so the test can pin exactly which call
    // site fired.
    //
    // Slot _8 is reused — it currently fires in fromdata_construct
    // (EVP_PKEY_CTX_new_from_name), which is not reached from
    // rsa_get_component.
    // -----------------------------------------------------------------

    @Test
    public void RSA_getComponent_getBnParam_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = 0;
        try
        {
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            Assertions.assertTrue(keyRef > 0);

            // Exercises interface/util/rsa.c:441
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_8);
            // 256-byte buffer is comfortably larger than any RSA-2048
            // component; size doesn't matter because the OPS flag short-
            // circuits the EVP_PKEY_get_bn_param call.
            int code = rsaServiceNI.ni_getComponent(keyRef,
                    RSAServiceNI.COMP_MODULUS, new byte[256]);
            // -2 + (-1070) = -1072.
            Assertions.assertEquals(-1072, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }


    // -----------------------------------------------------------------
    // rsa_ctx_update — sign and verify update paths.
    //
    // These are the two EVP_Digest*Update calls that consume input
    // bytes between init and final. Slots _9 / _10 are reused — they
    // currently fire in fromdata_construct (fromdata_init / fromdata),
    // neither of which is called during the init→update→final pipeline.
    // -----------------------------------------------------------------

    @Test
    public void RSA_update_sign_digestSignUpdate_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long rsaRef = 0;
        long keyRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            Assertions.assertTrue(rsaRef > 0);
            Assertions.assertTrue(keyRef > 0);

            // Init without OPS flag — must succeed cleanly so update is
            // the only operation the OPS flag affects.
            int initCode = rsaServiceNI.ni_initSign(rsaRef, keyRef, "SHA-256",
                    RSAServiceNI.PADDING_PKCS1, null, 0, TestUtil.RNDSrc);
            Assertions.assertEquals(0, initCode);

            // Exercises interface/util/rsa.c:708
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_9);
            int code = rsaServiceNI.ni_update(rsaRef, new byte[]{0x01, 0x02, 0x03}, 0, 3);
            // -2 + (-1010) = -1012.
            Assertions.assertEquals(-1012, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSA_update_verify_digestVerifyUpdate_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long rsaRef = 0;
        long keyRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            Assertions.assertTrue(rsaRef > 0);
            Assertions.assertTrue(keyRef > 0);

            int initCode = rsaServiceNI.ni_initVerify(rsaRef, keyRef, "SHA-256",
                    RSAServiceNI.PADDING_PKCS1, null, 0);
            Assertions.assertEquals(0, initCode);

            // Exercises interface/util/rsa.c:714
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_10);
            int code = rsaServiceNI.ni_update(rsaRef, new byte[]{0x01, 0x02, 0x03}, 0, 3);
            // -2 + (-1011) = -1013.
            Assertions.assertEquals(-1013, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }


    // -----------------------------------------------------------------
    // Raw PKCS#1 v1.5 (NoneWithRSA) — rsa_raw_init / raw sign / raw verify
    // -----------------------------------------------------------------

    @Test
    public void RSA_noneRawInitSign_opensslError() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long rsaRef = rsaServiceNI.allocateSigner();
        long keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
        try
        {
            OpenSSL.getOpenSSLErrors();
            // Exercises interface/util/rsa.c:545
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_11);
            int code = rsaServiceNI.ni_initSign(rsaRef, keyRef, "NONE",
                    RSAServiceNI.PADDING_PKCS1_NONE, null, 0, TestUtil.RNDSrc);
            // -2 + (-1100) = -1102.
            Assertions.assertEquals(-1102, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSA_noneRawSign_opensslError() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long rsaRef = rsaServiceNI.allocateSigner();
        long keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
        try
        {
            int initCode = rsaServiceNI.ni_initSign(rsaRef, keyRef, "NONE",
                    RSAServiceNI.PADDING_PKCS1_NONE, null, 0, TestUtil.RNDSrc);
            Assertions.assertEquals(0, initCode);
            rsaServiceNI.ni_update(rsaRef, new byte[32], 0, 32);
            OpenSSL.getOpenSSLErrors();
            // Exercises interface/util/rsa.c:860
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_12);
            int code = rsaServiceNI.ni_sign(rsaRef, null, 0, TestUtil.RNDSrc);
            // -2 + (-1101) = -1103.
            Assertions.assertEquals(-1103, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSA_noneRawVerify_opensslError() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long rsaRef = rsaServiceNI.allocateSigner();
        long keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
        try
        {
            int initCode = rsaServiceNI.ni_initVerify(rsaRef, keyRef, "NONE",
                    RSAServiceNI.PADDING_PKCS1_NONE, null, 0);
            Assertions.assertEquals(0, initCode);
            rsaServiceNI.ni_update(rsaRef, new byte[32], 0, 32);
            OpenSSL.getOpenSSLErrors();
            // Exercises interface/util/rsa.c:949
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_11);
            int code = rsaServiceNI.ni_verify(rsaRef, new byte[256], 256);
            // -2 + (-1102) = -1104.
            Assertions.assertEquals(-1104, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }
}
