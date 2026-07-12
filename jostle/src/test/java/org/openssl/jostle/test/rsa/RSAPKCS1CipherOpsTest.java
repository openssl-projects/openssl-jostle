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
import org.openssl.jostle.jcajce.provider.InvalidCipherTextException;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.OpenSSL;
import org.openssl.jostle.jcajce.provider.OverflowException;
import org.openssl.jostle.jcajce.provider.ProviderCapabilityException;
import org.openssl.jostle.jcajce.provider.rsa.RSAPKCS1CipherNI;
import org.openssl.jostle.jcajce.provider.rsa.RSAServiceNI;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.test.crypto.TestNISelector;
import org.openssl.jostle.util.ops.OperationsTestNI;

import java.security.Security;

/**
 * Fault-injection tests for the RSA-PKCS#1 v1.5 cipher NI. Mirrors
 * {@link RSAOAEPCipherOpsTest} but targets {@code rsa_pkcs1.c}'s
 * OPS sites:
 * <ol>
 *   <li>init — offset 2100 (EVP_PKEY_CTX_new_from_pkey), 2101
 *       (EVP_PKEY_encrypt/decrypt_init), 2110 (EVP_PKEY_CTX_set_rsa_padding),
 *       2111 (implicit-rejection EVP_PKEY_CTX_set_params, DECRYPT only);
 *       plus the DECRYPT-only capability probe (OPS_FAILED_INIT_1) whose
 *       raw code is JO_IMPLICIT_REJECTION_UNAVAILABLE (-135, no offset).</li>
 *   <li>doFinal — offset 2102 (size query), 2103 (final call). The base
 *       error code is classified by op mode: ENCRYPT stays
 *       JO_OPENSSL_ERROR (-2 → -2104 / -2105); DECRYPT maps to
 *       JO_INVALID_CIPHER_TEXT (-21 → -2123 / -2124).</li>
 * </ol>
 */
public class RSAPKCS1CipherOpsTest
{
    private static final byte[] PUB_EXP_F4 = {0x01, 0x00, 0x01};

    RSAServiceNI rsaServiceNI = TestNISelector.getRSANi();
    RSAPKCS1CipherNI cipherNI = TestNISelector.getRSAPKCS1CipherNi();
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
    // init — distinguishable failure paths via offset codes
    // -----------------------------------------------------------------

    @Test
    public void RSAPKCS1Cipher_init_evpPkeyCtxNew_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = cipherNI.allocateCipher();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);

            // Exercises interface/nonfips/util/rsa_pkcs1.c:98
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            int code = cipherNI.ni_init(ref, keyRef, RSAPKCS1CipherNI.OP_ENCRYPT, TestUtil.RNDSrc);
            // Offset 2100 + JO_OPENSSL_ERROR (-2) → -2102.
            Assertions.assertEquals(-2102, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            cipherNI.disposeCipher(ref);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSAPKCS1Cipher_init_evpEncryptInit_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = cipherNI.allocateCipher();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);

            // Exercises interface/nonfips/util/rsa_pkcs1.c:109
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            int code = cipherNI.ni_init(ref, keyRef, RSAPKCS1CipherNI.OP_ENCRYPT, TestUtil.RNDSrc);
            // Offset 2101 + JO_OPENSSL_ERROR (-2) → -2103.
            Assertions.assertEquals(-2103, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            cipherNI.disposeCipher(ref);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSAPKCS1Cipher_init_evpDecryptInit_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = cipherNI.allocateCipher();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);

            // Exercises interface/nonfips/util/rsa_pkcs1.c:109
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            int code = cipherNI.ni_init(ref, keyRef, RSAPKCS1CipherNI.OP_DECRYPT, TestUtil.RNDSrc);
            Assertions.assertEquals(-2103, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            cipherNI.disposeCipher(ref);
            specNI.dispose(keyRef);
        }
    }


    @Test
    public void RSAPKCS1Cipher_init_setRsaPadding_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = cipherNI.allocateCipher();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);

            // Exercises interface/nonfips/util/rsa_pkcs1.c:114
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);
            int code = cipherNI.ni_init(ref, keyRef, RSAPKCS1CipherNI.OP_ENCRYPT, TestUtil.RNDSrc);
            // -2 + (-2110) = -2112.
            Assertions.assertEquals(-2112, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            cipherNI.disposeCipher(ref);
            specNI.dispose(keyRef);
        }
    }

    /**
     * DECRYPT-only implicit-rejection capability probe (fail-loud contract):
     * when the loaded provider does not expose
     * {@code OSSL_ASYM_CIPHER_PARAM_IMPLICIT_REJECTION}, decrypt init is
     * refused with the raw code {@code JO_IMPLICIT_REJECTION_UNAVAILABLE}
     * (-135, deliberately NO OPS offset — the code must be exact even under
     * fault injection). The wrapped {@code init} surfaces it as
     * {@link ProviderCapabilityException}. The base provider supports the
     * parameter, so the branch is only reachable here via OPS_FAILED_INIT_1.
     * Encrypt init never runs the probe and must succeed with the flag set.
     */
    @Test
    public void RSAPKCS1Cipher_init_decrypt_capabilityProbe_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = cipherNI.allocateCipher();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);

            // Exercises interface/nonfips/util/rsa_pkcs1.c:153
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_INIT_1);
            int code = cipherNI.ni_init(ref, keyRef, RSAPKCS1CipherNI.OP_DECRYPT, TestUtil.RNDSrc);
            // JO_IMPLICIT_REJECTION_UNAVAILABLE — raw code, no OPS offset.
            Assertions.assertEquals(-135, code);

            // Wrapped path: typed capability rejection with the exact message.
            try
            {
                cipherNI.init(ref, keyRef, RSAPKCS1CipherNI.OP_DECRYPT, TestUtil.RNDSrc);
                Assertions.fail();
            }
            catch (ProviderCapabilityException e)
            {
                Assertions.assertEquals(
                        "PKCS#1 v1.5 decryption requires implicit rejection, which the loaded provider does not support",
                        e.getMessage());
            }

            // The probe is DECRYPT-only: encrypt init succeeds with the flag set.
            Assertions.assertEquals(0,
                    cipherNI.ni_init(ref, keyRef, RSAPKCS1CipherNI.OP_ENCRYPT, TestUtil.RNDSrc));
        }
        finally
        {
            operationsTestNI.resetFlags();
            cipherNI.disposeCipher(ref);
            specNI.dispose(keyRef);
        }
    }

    /**
     * Fault-injects the explicit implicit-rejection EVP_PKEY_CTX_set_params
     * call (DECRYPT-only, runs after the capability probe passes on the base
     * provider). Also pins that ENCRYPT init never reaches the site: the set
     * is inside the DECRYPT-only block, so encrypt succeeds with the flag on.
     */
    @Test
    public void RSAPKCS1Cipher_init_decrypt_setImplicitRejection_opensslError() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = cipherNI.allocateCipher();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);

            // Exercises interface/nonfips/util/rsa_pkcs1.c:165
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_4);
            int code = cipherNI.ni_init(ref, keyRef, RSAPKCS1CipherNI.OP_DECRYPT, TestUtil.RNDSrc);
            // Offset 2111 + JO_OPENSSL_ERROR (-2) → -2113.
            Assertions.assertEquals(-2113, code);

            // The set is DECRYPT-only: encrypt init succeeds with the flag set.
            Assertions.assertEquals(0,
                    cipherNI.ni_init(ref, keyRef, RSAPKCS1CipherNI.OP_ENCRYPT, TestUtil.RNDSrc));
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
    public void RSAPKCS1Cipher_doFinal_sizeQuery_opensslError() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = cipherNI.allocateCipher();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            cipherNI.init(ref, keyRef, RSAPKCS1CipherNI.OP_ENCRYPT, TestUtil.RNDSrc);

            OpenSSL.getOpenSSLErrors(); // purge
            // Exercises interface/nonfips/util/rsa_pkcs1.c:214
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            // Offset 2102 + JO_OPENSSL_ERROR (-2) → -2104 (ENCRYPT mode).
            int code = cipherNI.ni_doFinal(ref, new byte[]{1, 2, 3}, 0, 3,
                    null, 0, TestUtil.RNDSrc);
            Assertions.assertEquals(-2104, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            cipherNI.disposeCipher(ref);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSAPKCS1Cipher_doFinal_int32Overflow() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = cipherNI.allocateCipher();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            cipherNI.init(ref, keyRef, RSAPKCS1CipherNI.OP_ENCRYPT, TestUtil.RNDSrc);

            // Exercises interface/nonfips/util/rsa_pkcs1.c:224
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);
            cipherNI.doFinal(ref, new byte[]{1, 2, 3}, 0, 3, null, 0, TestUtil.RNDSrc);
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
    public void RSAPKCS1Cipher_doFinal_finalCall_opensslError() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = cipherNI.allocateCipher();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            cipherNI.init(ref, keyRef, RSAPKCS1CipherNI.OP_ENCRYPT, TestUtil.RNDSrc);

            int needed = cipherNI.doFinal(ref, new byte[]{1, 2, 3}, 0, 3,
                    null, 0, TestUtil.RNDSrc);
            byte[] out = new byte[needed];

            OpenSSL.getOpenSSLErrors(); // purge
            // Exercises interface/nonfips/util/rsa_pkcs1.c:242
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            // Offset 2103 + JO_OPENSSL_ERROR (-2) → -2105 (ENCRYPT mode).
            int code = cipherNI.ni_doFinal(ref, new byte[]{1, 2, 3}, 0, 3,
                    out, 0, TestUtil.RNDSrc);
            Assertions.assertEquals(-2105, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            cipherNI.disposeCipher(ref);
            specNI.dispose(keyRef);
        }
    }


    // -----------------------------------------------------------------
    // doFinal — DECRYPT-mode classification: the same fault sites map to
    // base JO_INVALID_CIPHER_TEXT (-21) instead of JO_OPENSSL_ERROR (-2).
    // Decrypt init succeeds on the base provider (implicit rejection is
    // supported), so the fault is injected AFTER a real init + ciphertext.
    // -----------------------------------------------------------------

    @Test
    public void RSAPKCS1Cipher_doFinal_decrypt_sizeQuery_invalidCipherText() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long encRef = 0;
        long decRef = 0;
        long keyRef = 0;
        try
        {
            encRef = cipherNI.allocateCipher();
            decRef = cipherNI.allocateCipher();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            byte[] ct = encrypt(encRef, keyRef, new byte[]{1, 2, 3});

            cipherNI.init(decRef, keyRef, RSAPKCS1CipherNI.OP_DECRYPT, TestUtil.RNDSrc);

            OpenSSL.getOpenSSLErrors(); // purge
            // Exercises interface/nonfips/util/rsa_pkcs1.c:214
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            // Offset 2102 + JO_INVALID_CIPHER_TEXT (-21) → -2123 (DECRYPT mode).
            int code = cipherNI.ni_doFinal(decRef, ct, 0, ct.length,
                    null, 0, TestUtil.RNDSrc);
            Assertions.assertEquals(-2123, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            cipherNI.disposeCipher(encRef);
            cipherNI.disposeCipher(decRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSAPKCS1Cipher_doFinal_decrypt_finalCall_invalidCipherText() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long encRef = 0;
        long decRef = 0;
        long keyRef = 0;
        try
        {
            encRef = cipherNI.allocateCipher();
            decRef = cipherNI.allocateCipher();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            byte[] ct = encrypt(encRef, keyRef, new byte[]{1, 2, 3});

            cipherNI.init(decRef, keyRef, RSAPKCS1CipherNI.OP_DECRYPT, TestUtil.RNDSrc);
            int needed = cipherNI.doFinal(decRef, ct, 0, ct.length,
                    null, 0, TestUtil.RNDSrc);
            byte[] out = new byte[needed];

            OpenSSL.getOpenSSLErrors(); // purge
            // Exercises interface/nonfips/util/rsa_pkcs1.c:242
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            // Offset 2103 + JO_INVALID_CIPHER_TEXT (-21) → -2124 (DECRYPT mode).
            int code = cipherNI.ni_doFinal(decRef, ct, 0, ct.length,
                    out, 0, TestUtil.RNDSrc);
            Assertions.assertEquals(-2124, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            cipherNI.disposeCipher(encRef);
            cipherNI.disposeCipher(decRef);
            specNI.dispose(keyRef);
        }
    }

    /**
     * Wrapped-call variant: {@code JO_INVALID_CIPHER_TEXT} surfaces as
     * {@link InvalidCipherTextException}. The OPS flag and the OPS offset
     * share one index, so an injected fault always carries the offset
     * (-2123) — a code only an instrumented build can produce, which the
     * wrapped handler maps to the JO_UNKNOWN fallback. The release-build
     * code is the bare {@code JO_INVALID_CIPHER_TEXT} (-21); drive that
     * through the wrapped handler with an empty OpenSSL error queue and pin
     * the exact formatted message. (The real-failure path is pinned by
     * {@code RSAPKCS1CipherLimitTest} with a structural decrypt failure.)
     */
    @Test
    public void RSAPKCS1Cipher_doFinal_decrypt_wrapped_invalidCipherTextException() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long encRef = 0;
        long decRef = 0;
        long keyRef = 0;
        try
        {
            encRef = cipherNI.allocateCipher();
            decRef = cipherNI.allocateCipher();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            byte[] ct = encrypt(encRef, keyRef, new byte[]{1, 2, 3});

            cipherNI.init(decRef, keyRef, RSAPKCS1CipherNI.OP_DECRYPT, TestUtil.RNDSrc);

            OpenSSL.getOpenSSLErrors(); // purge
            // Exercises interface/nonfips/util/rsa_pkcs1.c:214
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            int code = cipherNI.ni_doFinal(decRef, ct, 0, ct.length,
                    null, 0, TestUtil.RNDSrc);
            Assertions.assertEquals(-2123, code);
            operationsTestNI.resetFlags();

            OpenSSL.getOpenSSLErrors(); // purge — empty queue formats "null"
            try
            {
                cipherNI.handleErrors(-21);
                Assertions.fail();
            }
            catch (InvalidCipherTextException e)
            {
                Assertions.assertEquals("invalid cipher text: null", e.getMessage());
            }
        }
        finally
        {
            operationsTestNI.resetFlags();
            cipherNI.disposeCipher(encRef);
            cipherNI.disposeCipher(decRef);
            specNI.dispose(keyRef);
        }
    }

    /** Encrypt a message on {@code encRef}, returning the real ciphertext. */
    private byte[] encrypt(long encRef, long keyRef, byte[] msg)
    {
        cipherNI.init(encRef, keyRef, RSAPKCS1CipherNI.OP_ENCRYPT, TestUtil.RNDSrc);
        int ctLen = cipherNI.doFinal(encRef, msg, 0, msg.length, null, 0, TestUtil.RNDSrc);
        byte[] ct = new byte[ctLen];
        cipherNI.doFinal(encRef, msg, 0, msg.length, ct, 0, TestUtil.RNDSrc);
        return ct;
    }


    // -----------------------------------------------------------------
    // doFinal — input/output access faults (JNI only)
    // -----------------------------------------------------------------

    @Test
    public void RSAPKCS1Cipher_doFinal_failedAccessInput() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());

        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = cipherNI.allocateCipher();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            cipherNI.init(ref, keyRef, RSAPKCS1CipherNI.OP_ENCRYPT, TestUtil.RNDSrc);

            // Exercises interface/nonfips/jni/rsa_pkcs1_ni_jni.c:109
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
    public void RSAPKCS1Cipher_doFinal_failedAccessOutput() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());

        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = cipherNI.allocateCipher();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            cipherNI.init(ref, keyRef, RSAPKCS1CipherNI.OP_ENCRYPT, TestUtil.RNDSrc);

            int needed = cipherNI.doFinal(ref, new byte[]{1, 2, 3}, 0, 3,
                    null, 0, TestUtil.RNDSrc);
            byte[] out = new byte[needed];

            // Exercises interface/nonfips/jni/rsa_pkcs1_ni_jni.c:130
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
