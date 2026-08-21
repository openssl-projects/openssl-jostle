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
import org.openssl.jostle.jcajce.provider.AccessException;
import org.openssl.jostle.jcajce.provider.OpenSSL;
import org.openssl.jostle.jcajce.provider.OverflowException;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.provider.rsa.RSAPKCS1CipherNI;
import org.openssl.jostle.jcajce.provider.rsa.RSAServiceNI;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.util.ops.OperationsTestNI;

/**
 * FIPS mirror of {@code RSAPKCS1CipherOpsTest} (encrypt-mode subset), driving
 * the RSA-PKCS#1 v1.5 cipher NI through
 * {@link FIPSNISelector#RSAPKCS1CipherNI}. The fault sites live in
 * interface/fips/util/rsa_pkcs1.c (a content-identical copy of the base
 * tree's file), so the per-site {@code OPS_OFFSET_*}-disambiguated codes
 * (offsets 2100/2101/2110 at init, 2102/2103 at doFinal;
 * {@code JO_OPENSSL_ERROR (-2)} minus the offset) match the base mirror.
 * Pinning the exact code catches a silent offset renumber.
 *
 * <p><b>Not a straight mirror any more:</b> the 3.1.2 module fails
 * {@code rsa_pkcs1_init}'s implicit-rejection capability probe, so EVERY
 * OP_DECRYPT init is refused with the raw {@code
 * JO_IMPLICIT_REJECTION_UNAVAILABLE} (-135) — see
 * {@code FIPSRSAPKCS1CipherLimitTest} which pins that natural (non-injected)
 * behaviour. Consequently the base test's decrypt-mode doFinal fault variants
 * (-2123 / -2124, requiring a successful decrypt init) cannot exist here.
 * The OP_DECRYPT init fault test below still works: its injected fault fires
 * at the EVP_PKEY_decrypt_init check, BEFORE the capability probe runs.
 * Encrypt-mode tests are unaffected by the fail-loud decrypt contract.
 *
 * <p>Requires a JOSTLE_OPS_TEST build of the FIPS library: gated on
 * {@code TEST_FIPS_LIB} (whole class skips when unset) and, per test, on
 * {@code opsTestAvailable()} (skips against a shipped, non-instrumented FIPS
 * library). The FAILED_ACCESS tests are JNI-only (the FFI bridge takes raw
 * pointers).
 */
public class FIPSRSAPKCS1CipherOpsTest
{
    private static final byte[] PUB_EXP_F4 = {0x01, 0x00, 0x01};

    RSAServiceNI rsaServiceNI = FIPSNISelector.RSAServiceNI;
    RSAPKCS1CipherNI cipherNI = FIPSNISelector.RSAPKCS1CipherNI;
    SpecNI specNI = FIPSNISelector.SpecNI;
    OperationsTestNI operationsTestNI = FIPSNISelector.OperationsTestNI;

    @BeforeAll
    public static void beforeAll()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        TestUtil.addFipsProvider();
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

    /**
     * Skip the calling test when the loaded module refuses PKCS#1 v1.5
     * encryption.
     * <p>
     * These fault sites sit behind a real encrypt — including the
     * {@code out == NULL} size probe, which OpenSSL evaluates AFTER its FIPS
     * padding-mode gate — so they cannot be reached on a module that declines
     * it. OpenSSL's 3.5.x FIPS module does; 3.1.2 does not (see
     * {@link FIPSTestUtil#fipsPkcs1CanEncrypt}, which pins the refusal
     * message). The base tree's {@code RSAPKCS1CipherOpsTest} exercises the
     * same C sites unconditionally.
     */
    private void assumeEncryptAvailable()
    {
        long keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
        try
        {
            Assumptions.assumeTrue(
                    FIPSTestUtil.fipsPkcs1CanEncrypt(cipherNI, keyRef, TestUtil.RNDSrc),
                    "the loaded FIPS module refuses PKCS#1 v1.5 encryption");
        }
        finally
        {
            specNI.dispose(keyRef);
        }
    }

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

            // Exercises interface/fips/util/rsa_pkcs1.c:98
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

            // Exercises interface/fips/util/rsa_pkcs1.c:109
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

            // Injected fault fires at the EVP_PKEY_decrypt_init check, BEFORE
            // the implicit-rejection capability probe — so the offset code
            // (-2103) wins over the module's natural -135 refusal.
            // Exercises interface/fips/util/rsa_pkcs1.c:109
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

            // Exercises interface/fips/util/rsa_pkcs1.c:114
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
            // Exercises interface/fips/util/rsa_pkcs1.c:215
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
        assumeEncryptAvailable();

        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = cipherNI.allocateCipher();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            cipherNI.init(ref, keyRef, RSAPKCS1CipherNI.OP_ENCRYPT, TestUtil.RNDSrc);

            // Exercises interface/fips/util/rsa_pkcs1.c:226
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
        assumeEncryptAvailable();

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
            // Exercises interface/fips/util/rsa_pkcs1.c:247
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

            // Exercises interface/fips/jni/rsa_pkcs1_ni_jni.c:109
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
        assumeEncryptAvailable();
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

            // Exercises interface/fips/jni/rsa_pkcs1_ni_jni.c:130
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
