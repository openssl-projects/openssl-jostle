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
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.OpenSSL;
import org.openssl.jostle.jcajce.provider.OverflowException;
import org.openssl.jostle.jcajce.provider.rsa.RSAOAEPCipherNI;
import org.openssl.jostle.jcajce.provider.rsa.RSAServiceNI;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.test.crypto.TestNISelector;
import org.openssl.jostle.util.ops.OperationsTestNI;

import java.security.Security;

/**
 * Fault-injection tests for the RSA-OAEP cipher NI. Each test sets one
 * {@code OPS_*} flag, drives the matching native call, and asserts the
 * matching error code or exception. Mirrors {@link RSAOpsTest}'s shape.
 *
 * <p>FAILED_ACCESS tests are JNI-only and guard via
 * {@link Loader#isFFI()} because the FFI bridge does not use
 * {@code GetByteArrayElements}.
 */
public class RSAOAEPCipherOpsTest
{
    private static final byte[] PUB_EXP_F4 = {0x01, 0x00, 0x01};

    RSAServiceNI rsaServiceNI = TestNISelector.getRSANi();
    RSAOAEPCipherNI cipherNI = TestNISelector.getRSAOAEPCipherNi();
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
    // init — JNI access faults (digest / mgf1 string fetch). JNI-only.
    // -----------------------------------------------------------------

    /**
     * Target: {@code interface/jni/rsa_oaep_ni_jni.c:84} — fault-injects the
     * {@code GetStringUTFChars(oaep_md)} failure inside {@code ni_init}.
     * Uses slot {@code _2} because {@code _1} is consumed by the label
     * byte-array load further down the same function.
     */
    @Test
    public void RSAOAEPCipher_init_accessOaepMdName_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());

        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = cipherNI.allocateCipher();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);

            // Exercises interface/jni/rsa_oaep_ni_jni.c:84
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_2);
            int code = cipherNI.ni_init(ref, keyRef, RSAOAEPCipherNI.OP_ENCRYPT,
                    "SHA-256", null, null, TestUtil.RNDSrc);
            Assertions.assertEquals(ErrorCode.JO_UNABLE_TO_ACCESS_NAME.getCode(), code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            cipherNI.disposeCipher(ref);
            specNI.dispose(keyRef);
        }
    }

    /**
     * Target: {@code interface/jni/rsa_oaep_ni_jni.c:90} — fault-injects the
     * {@code GetStringUTFChars(mgf1_md)} failure inside {@code ni_init}.
     * The mgf1 string must be non-null for the fetch to actually run.
     */
    @Test
    public void RSAOAEPCipher_init_accessMgf1MdName_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());

        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = cipherNI.allocateCipher();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);

            // Exercises interface/jni/rsa_oaep_ni_jni.c:90
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_3);
            int code = cipherNI.ni_init(ref, keyRef, RSAOAEPCipherNI.OP_ENCRYPT,
                    "SHA-256", "SHA-256", null, TestUtil.RNDSrc);
            Assertions.assertEquals(ErrorCode.JO_UNABLE_TO_ACCESS_NAME.getCode(), code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            cipherNI.disposeCipher(ref);
            specNI.dispose(keyRef);
        }
    }


    // -----------------------------------------------------------------
    // init — distinguishable failure paths via offset codes
    // -----------------------------------------------------------------

    @Test
    public void RSAOAEPCipher_init_evpPkeyCtxNew_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = cipherNI.allocateCipher();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);

            // Exercises interface/util/rsa_oaep.c:114
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            int code = cipherNI.ni_init(ref, keyRef, RSAOAEPCipherNI.OP_ENCRYPT,
                    "SHA-256", null, null, TestUtil.RNDSrc);
            // Offset 2000 + JO_OPENSSL_ERROR (-2) → -2002.
            Assertions.assertEquals(-2002, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            cipherNI.disposeCipher(ref);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSAOAEPCipher_init_evpEncryptInit_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = cipherNI.allocateCipher();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);

            // Exercises interface/util/rsa_oaep.c:125
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            int code = cipherNI.ni_init(ref, keyRef, RSAOAEPCipherNI.OP_ENCRYPT,
                    "SHA-256", null, null, TestUtil.RNDSrc);
            // Offset 2001 + JO_OPENSSL_ERROR (-2) → -2003.
            Assertions.assertEquals(-2003, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            cipherNI.disposeCipher(ref);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSAOAEPCipher_init_evpDecryptInit_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = cipherNI.allocateCipher();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);

            // Exercises interface/util/rsa_oaep.c:125
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            int code = cipherNI.ni_init(ref, keyRef, RSAOAEPCipherNI.OP_DECRYPT,
                    "SHA-256", null, null, TestUtil.RNDSrc);
            Assertions.assertEquals(-2003, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            cipherNI.disposeCipher(ref);
            specNI.dispose(keyRef);
        }
    }


    // -----------------------------------------------------------------
    // init — configure_padding-style fault points inside rsa_oaep_init.
    // -----------------------------------------------------------------

    @Test
    public void RSAOAEPCipher_init_setRsaPadding_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = cipherNI.allocateCipher();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);

            // Exercises interface/util/rsa_oaep.c:130
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);
            int code = cipherNI.ni_init(ref, keyRef, RSAOAEPCipherNI.OP_ENCRYPT,
                    "SHA-256", null, null, TestUtil.RNDSrc);
            // -2 + (-2010) = -2012.
            Assertions.assertEquals(-2012, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            cipherNI.disposeCipher(ref);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSAOAEPCipher_init_setOaepMdName_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = cipherNI.allocateCipher();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);

            // Exercises interface/util/rsa_oaep.c:135
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_4);
            int code = cipherNI.ni_init(ref, keyRef, RSAOAEPCipherNI.OP_ENCRYPT,
                    "SHA-256", null, null, TestUtil.RNDSrc);
            // -2 + (-2011) = -2013.
            Assertions.assertEquals(-2013, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            cipherNI.disposeCipher(ref);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSAOAEPCipher_init_setMgf1MdName_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = cipherNI.allocateCipher();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);

            // Exercises interface/util/rsa_oaep.c:143
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_5);
            int code = cipherNI.ni_init(ref, keyRef, RSAOAEPCipherNI.OP_ENCRYPT,
                    "SHA-256", null, null, TestUtil.RNDSrc);
            // -2 + (-2012) = -2014.
            Assertions.assertEquals(-2014, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            cipherNI.disposeCipher(ref);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSAOAEPCipher_init_setOaepLabel_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = cipherNI.allocateCipher();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);

            // Exercises interface/util/rsa_oaep.c:159
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_6);
            // Provide a non-empty label so the set0_rsa_oaep_label call is
            // reached (it lives behind `if (label != NULL && label_len > 0)`).
            int code = cipherNI.ni_init(ref, keyRef, RSAOAEPCipherNI.OP_ENCRYPT,
                    "SHA-256", null, new byte[]{0x01, 0x02, 0x03}, TestUtil.RNDSrc);
            // -2 + (-2013) = -2015.
            Assertions.assertEquals(-2015, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            cipherNI.disposeCipher(ref);
            specNI.dispose(keyRef);
        }
    }


    // -----------------------------------------------------------------
    // doFinal — size-query and final-call failure paths
    // -----------------------------------------------------------------

    @Test
    public void RSAOAEPCipher_doFinal_sizeQuery_opensslError() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = cipherNI.allocateCipher();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            cipherNI.init(ref, keyRef, RSAOAEPCipherNI.OP_ENCRYPT,
                    "SHA-256", null, null, TestUtil.RNDSrc);

            OpenSSL.getOpenSSLErrors(); // purge
            // Exercises interface/util/rsa_oaep.c:212
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            // Offset 2002 + JO_OPENSSL_ERROR (-2) → -2004.
            int code = cipherNI.ni_doFinal(ref, new byte[]{1, 2, 3}, 0, 3,
                    null, 0, TestUtil.RNDSrc);
            Assertions.assertEquals(-2004, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            cipherNI.disposeCipher(ref);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSAOAEPCipher_doFinal_int32Overflow() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = cipherNI.allocateCipher();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            cipherNI.init(ref, keyRef, RSAOAEPCipherNI.OP_ENCRYPT,
                    "SHA-256", null, null, TestUtil.RNDSrc);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);
            cipherNI.doFinal(ref, new byte[]{1, 2, 3}, 0, 3,
                    null, 0, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (OverflowException e)
        {
            Assertions.assertEquals("output too long int32", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
            cipherNI.disposeCipher(ref);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSAOAEPCipher_doFinal_finalCall_opensslError() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = cipherNI.allocateCipher();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            cipherNI.init(ref, keyRef, RSAOAEPCipherNI.OP_ENCRYPT,
                    "SHA-256", null, null, TestUtil.RNDSrc);

            // Run the size-query branch first to populate out_required
            // before tripping the second EVP_PKEY_encrypt call.
            int needed = cipherNI.doFinal(ref, new byte[]{1, 2, 3}, 0, 3,
                    null, 0, TestUtil.RNDSrc);
            byte[] out = new byte[needed];

            OpenSSL.getOpenSSLErrors(); // purge
            // Exercises interface/util/rsa_oaep.c:246
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            // Offset 2003 + JO_OPENSSL_ERROR (-2) → -2005.
            int code = cipherNI.ni_doFinal(ref, new byte[]{1, 2, 3}, 0, 3,
                    out, 0, TestUtil.RNDSrc);
            Assertions.assertEquals(-2005, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            cipherNI.disposeCipher(ref);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSAOAEPCipher_doFinal_decryptFailure_returnsInvalidCipherText() throws Exception
    {
        // OPS-driven assertion of the decrypt-mode error code split:
        // when EVP_PKEY_decrypt fails, the C layer returns
        // JO_INVALID_CIPHER_TEXT (-21) instead of JO_OPENSSL_ERROR (-2).
        // The bridge translates to InvalidCipherTextException; the SPI
        // then to BadPaddingException for JCE callers.
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long encRef = 0;
        long decRef = 0;
        long keyRef = 0;
        try
        {
            encRef = cipherNI.allocateCipher();
            decRef = cipherNI.allocateCipher();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            cipherNI.init(encRef, keyRef, RSAOAEPCipherNI.OP_ENCRYPT,
                    "SHA-256", null, null, TestUtil.RNDSrc);

            // Produce a real ciphertext to feed to the decrypt path —
            // structure must be valid so the size-query path succeeds
            // before the OPS flag trips the second EVP_PKEY_decrypt.
            int needed = cipherNI.doFinal(encRef, new byte[]{1, 2, 3}, 0, 3,
                    null, 0, TestUtil.RNDSrc);
            byte[] ct = new byte[needed];
            cipherNI.doFinal(encRef, new byte[]{1, 2, 3}, 0, 3, ct, 0, TestUtil.RNDSrc);

            cipherNI.init(decRef, keyRef, RSAOAEPCipherNI.OP_DECRYPT,
                    "SHA-256", null, null, TestUtil.RNDSrc);
            int sizeQuery = cipherNI.doFinal(decRef, ct, 0, ct.length,
                    null, 0, TestUtil.RNDSrc);
            byte[] pt = new byte[sizeQuery];

            OpenSSL.getOpenSSLErrors(); // purge
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            // JO_INVALID_CIPHER_TEXT (-21) + offset(-2003) = -2024.
            int code = cipherNI.ni_doFinal(decRef, ct, 0, ct.length,
                    pt, 0, TestUtil.RNDSrc);
            Assertions.assertEquals(-2024, code,
                    "decrypt-mode OPS failure must surface JO_INVALID_CIPHER_TEXT-based code");
        }
        finally
        {
            operationsTestNI.resetFlags();
            cipherNI.disposeCipher(encRef);
            cipherNI.disposeCipher(decRef);
            specNI.dispose(keyRef);
        }
    }


    // -----------------------------------------------------------------
    // doFinal — input/output access faults (JNI only)
    // -----------------------------------------------------------------

    @Test
    public void RSAOAEPCipher_doFinal_failedAccessInput() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());

        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = cipherNI.allocateCipher();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            cipherNI.init(ref, keyRef, RSAOAEPCipherNI.OP_ENCRYPT,
                    "SHA-256", null, null, TestUtil.RNDSrc);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            cipherNI.doFinal(ref, new byte[]{1, 2, 3}, 0, 3,
                    null, 0, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access input array", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
            cipherNI.disposeCipher(ref);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSAOAEPCipher_doFinal_failedAccessOutput() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());

        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = cipherNI.allocateCipher();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            cipherNI.init(ref, keyRef, RSAOAEPCipherNI.OP_ENCRYPT,
                    "SHA-256", null, null, TestUtil.RNDSrc);

            // Compute needed first to allocate a real-sized output.
            int needed = cipherNI.doFinal(ref, new byte[]{1, 2, 3}, 0, 3,
                    null, 0, TestUtil.RNDSrc);
            byte[] out = new byte[needed];

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_2);
            cipherNI.doFinal(ref, new byte[]{1, 2, 3}, 0, 3,
                    out, 0, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access output array", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
            cipherNI.disposeCipher(ref);
            specNI.dispose(keyRef);
        }
    }
}
