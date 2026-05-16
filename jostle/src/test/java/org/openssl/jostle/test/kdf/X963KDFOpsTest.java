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
import org.openssl.jostle.jcajce.provider.kdf.KdfNI;
import org.openssl.jostle.test.crypto.TestNISelector;
import org.openssl.jostle.util.ops.OperationsTestNI;

import java.security.Security;

/**
 * Fault-injection tests for the X9.63 KDF entry points in
 * {@code interface/util/kdf.c::x963kdf} and the matching
 * {@code interface/jni/kdf_jni.c::Java_..._x963kdf} bridge.
 *
 * <p>Each test sets exactly one OPS flag, drives
 * {@code KdfNI.x963kdf(...)}, and asserts the typed exception (for
 * bridge-side faults) or the multiplexed integer return code (for
 * util-side OpenSSL failures).
 *
 * <p>All tests are guarded by {@link OperationsTestNI#opsTestAvailable()}.
 *
 * <h2>Bridge-side sites (JNI only — FFI doesn't use these flags)</h2>
 * <pre>
 *   OPS_FAILED_ACCESS_1   Z load_bytearray_ctx fails
 *   OPS_FAILED_ACCESS_2   sharedInfo load_bytearray_ctx fails
 *   OPS_FAILED_ACCESS_3   output load_bytearray_ctx fails
 * </pre>
 *
 * <h2>Util-side sites (cross-bridge)</h2>
 * <pre>
 *   Offset  kdf.c line  Trigger
 *   ----------------------------------------------------------------
 *   4000    line 184    EVP_KDF_fetch("X963KDF") == NULL
 *   4001    line 190    EVP_KDF_CTX_new == NULL
 *   4002    line 206    EVP_KDF_derive failed
 * </pre>
 *
 * <p>Note: 4000 numeric block is shared with {@code xec.c} but the
 * flag sets are disjoint ({@code OPS_OPENSSL_ERROR_7..._9} here vs
 * {@code _1..._4} in xec.c) — CLAUDE.md explicitly permits cross-file
 * offset reuse.
 */
public class X963KDFOpsTest
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
    public void x963kdf_access_z() throws Exception
    {
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        Assumptions.assumeTrue(ops.opsTestAvailable(), "Ops Test only");
        try
        {
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            kdfNI.handleErrorCodes(kdfNI.x963kdf(
                    new byte[16], new byte[8], "SHA-256",
                    new byte[32], 0, 32));
            Assertions.fail("expected AccessException");
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access X9.63 KDF Z array", e.getMessage());
        }
    }

    @Test
    public void x963kdf_access_sharedInfo() throws Exception
    {
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        Assumptions.assumeTrue(ops.opsTestAvailable(), "Ops Test only");
        try
        {
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_2);
            kdfNI.handleErrorCodes(kdfNI.x963kdf(
                    new byte[16], new byte[8], "SHA-256",
                    new byte[32], 0, 32));
            Assertions.fail("expected AccessException");
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access X9.63 KDF shared-info array", e.getMessage());
        }
    }

    @Test
    public void x963kdf_access_output() throws Exception
    {
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        Assumptions.assumeTrue(ops.opsTestAvailable(), "Ops Test only");
        try
        {
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_3);
            kdfNI.handleErrorCodes(kdfNI.x963kdf(
                    new byte[16], new byte[8], "SHA-256",
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
     * Target: {@code kdf.c:184} (offset 4000) — {@code EVP_KDF_fetch("X963KDF")
     * == NULL} inside {@code x963kdf}.
     */
    @Test
    public void x963kdf_kdf_fetch_failed()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable(), "Ops Test only");
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_7);
        int code = kdfNI.x963kdf(
                new byte[16], new byte[8], "SHA-256",
                new byte[32], 0, 32);
        Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 4000, code);
    }

    /**
     * Target: {@code kdf.c:190} (offset 4001) — {@code EVP_KDF_CTX_new
     * == NULL} inside {@code x963kdf}.
     */
    @Test
    public void x963kdf_kdf_ctx_new_failed()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable(), "Ops Test only");
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_8);
        int code = kdfNI.x963kdf(
                new byte[16], new byte[8], "SHA-256",
                new byte[32], 0, 32);
        Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 4001, code);
    }

    /**
     * Target: {@code kdf.c:206} (offset 4002) — {@code EVP_KDF_derive}
     * failure branch inside {@code x963kdf}.
     */
    @Test
    public void x963kdf_kdf_derive_failed()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable(), "Ops Test only");
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_9);
        int code = kdfNI.x963kdf(
                new byte[16], new byte[8], "SHA-256",
                new byte[32], 0, 32);
        Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 4002, code);
    }
}
