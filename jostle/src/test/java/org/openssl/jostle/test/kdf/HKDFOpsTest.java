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

package org.openssl.jostle.test.kdf;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.AccessException;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.kdf.KdfNI;
import org.openssl.jostle.test.crypto.TestNISelector;
import org.openssl.jostle.util.ops.OperationsTestNI;

import java.security.Security;

/**
 * Fault-injection tests for the HKDF entry points in
 * {@code interface/util/kdf.c::hkdf} and the matching
 * {@code interface/jni/kdf_jni.c::Java_..._hkdf} bridge.
 *
 * <p>Each test sets exactly one OPS flag, drives
 * {@code KdfNI.hkdf(...)}, and asserts the typed exception (for
 * bridge-side faults) or the multiplexed integer return code (for
 * util-side OpenSSL failures).
 *
 * <p>All tests are guarded by {@link OperationsTestNI#opsTestAvailable()}.
 *
 * <h2>Bridge-side sites (JNI only — FFI doesn't use these flags)</h2>
 * <pre>
 *   OPS_FAILED_ACCESS_1   IKM load_bytearray_ctx fails
 *   OPS_FAILED_ACCESS_2   salt load_bytearray_ctx fails
 *   OPS_FAILED_ACCESS_3   info load_bytearray_ctx fails
 *   OPS_FAILED_ACCESS_4   output load_bytearray_ctx fails
 * </pre>
 *
 * <h2>Util-side sites (cross-bridge)</h2>
 * <pre>
 *   Offset  kdf.c line  Trigger
 *   ----------------------------------------------------------------
 *   3000    line 113    EVP_KDF_fetch("HKDF") == NULL
 *   3001    line 119    EVP_KDF_CTX_new == NULL
 *   3002    line 141    EVP_KDF_derive failed
 * </pre>
 */
public class HKDFOpsTest
{
    private final KdfNI kdfNI = TestNISelector.getKDFNI();
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


    // -----------------------------------------------------------------
    // Bridge-side access failures (JNI only — FFI uses direct pointers)
    // -----------------------------------------------------------------

    @Test
    public void hkdf_access_ikm() throws Exception
    {
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        Assumptions.assumeTrue(ops.opsTestAvailable(), "Ops Test only");
        try
        {
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            kdfNI.handleErrorCodes(kdfNI.hkdf(
                    new byte[16], new byte[8], new byte[4], "SHA-256",
                    new byte[32], 0, 32));
            Assertions.fail("expected AccessException");
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access HKDF IKM array", e.getMessage());
        }
    }

    @Test
    public void hkdf_access_salt() throws Exception
    {
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        Assumptions.assumeTrue(ops.opsTestAvailable(), "Ops Test only");
        try
        {
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_2);
            kdfNI.handleErrorCodes(kdfNI.hkdf(
                    new byte[16], new byte[8], new byte[4], "SHA-256",
                    new byte[32], 0, 32));
            Assertions.fail("expected AccessException");
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access salt array", e.getMessage());
        }
    }

    @Test
    public void hkdf_access_info() throws Exception
    {
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        Assumptions.assumeTrue(ops.opsTestAvailable(), "Ops Test only");
        try
        {
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_3);
            kdfNI.handleErrorCodes(kdfNI.hkdf(
                    new byte[16], new byte[8], new byte[4], "SHA-256",
                    new byte[32], 0, 32));
            Assertions.fail("expected AccessException");
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access HKDF info array", e.getMessage());
        }
    }

    @Test
    public void hkdf_access_output() throws Exception
    {
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        Assumptions.assumeTrue(ops.opsTestAvailable(), "Ops Test only");
        try
        {
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_4);
            kdfNI.handleErrorCodes(kdfNI.hkdf(
                    new byte[16], new byte[8], new byte[4], "SHA-256",
                    new byte[32], 0, 32));
            Assertions.fail("expected AccessException");
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access output array", e.getMessage());
        }
    }


    // -----------------------------------------------------------------
    // Util-side OpenSSL failures (cross-bridge)
    // -----------------------------------------------------------------

    /**
     * Target: {@code kdf.c:113} (offset 3000) — {@code EVP_KDF_fetch("HKDF")
     * == NULL} inside {@code hkdf}.
     */
    @Test
    public void hkdf_kdf_fetch_failed()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable(), "Ops Test only");
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_4);
        int code = kdfNI.hkdf(
                new byte[16], new byte[8], new byte[4], "SHA-256",
                new byte[32], 0, 32);
        Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 3000, code);
    }

    /**
     * Target: {@code kdf.c:119} (offset 3001) — {@code EVP_KDF_CTX_new
     * == NULL} inside {@code hkdf}.
     */
    @Test
    public void hkdf_kdf_ctx_new_failed()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable(), "Ops Test only");
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_5);
        int code = kdfNI.hkdf(
                new byte[16], new byte[8], new byte[4], "SHA-256",
                new byte[32], 0, 32);
        Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 3001, code);
    }

    /**
     * Target: {@code kdf.c:141} (offset 3002) — {@code EVP_KDF_derive}
     * failure branch inside {@code hkdf}.
     */
    @Test
    public void hkdf_kdf_derive_failed()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable(), "Ops Test only");
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_6);
        int code = kdfNI.hkdf(
                new byte[16], new byte[8], new byte[4], "SHA-256",
                new byte[32], 0, 32);
        Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 3002, code);
    }
}
