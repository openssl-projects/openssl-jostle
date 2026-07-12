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
import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.AccessException;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.provider.kdf.KdfNI;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.util.ops.OperationsTestNI;

/**
 * Operations-test fault injection at the FIPS PBKDF2 NI surface
 * ({@code FIPSNISelector.KdfNI.pbkdf2}). The FIPS JNI glue
 * (interface/fips/jni/kdf_fips_jni.c) is the base kdf_jni.c re-included under renamed
 * symbols, and the fault sites live in the shared interface/fips/util/kdf.c, so the
 * injected error paths (JNI access faults, plus the {@code OPS_OFFSET_*}
 * 2000-block OpenSSL-error codes) fire identically when driven through the FIPS
 * interface library. PBKDF2 is FIPS-approved (SP 800-132), so this is a straight
 * mirror of the base {@code PBKdf2OpsTest}; the OPS flags short-circuit before
 * any FIPS lower-bound check on salt/iterations, so the base inputs are
 * unchanged.
 *
 * <p>Requires a JOSTLE_OPS_TEST build of the FIPS library: gated on
 * {@code TEST_FIPS_LIB} (whole class skips when unset) and, per test, on
 * {@code opsTestAvailable()} (skips against a shipped, non-instrumented FIPS
 * library). The FAILED_ACCESS tests are JNI-only (the FFI bridge takes raw
 * pointers). Flags are set on the FIPS library's own OperationsTestNI, whose
 * flag state is independent of the base library's.
 */
public class FIPSPBKdf2OpsTest
{
    @BeforeAll
    public static void beforeAll()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        TestUtil.addFipsProvider();
    }

    private final KdfNI kdfNI = FIPSNISelector.KdfNI;
    private final OperationsTestNI operationsTestNI = FIPSNISelector.OperationsTestNI;

    @BeforeEach
    public void beforeEach()
    {
        if (operationsTestNI.opsTestAvailable())
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void pbekdf2_access_password() throws Exception
    {
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only"); // JNI only
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        try
        {
            // Exercises interface/fips/jni/kdf_jni.c:154
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            kdfNI.handleErrorCodes(kdfNI.pbkdf2(new byte[0], new byte[0], 1, "SHA-1", new byte[0], 0, 0));
            Assertions.fail();
        } catch (AccessException e)
        {
            Assertions.assertEquals("unable to access password array", e.getMessage());
        } finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void pbekdf2_access_salt() throws Exception
    {
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only"); // JNI only
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        try
        {
            // Exercises interface/fips/jni/kdf_jni.c:165
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_2);
            kdfNI.handleErrorCodes(kdfNI.pbkdf2(new byte[0], new byte[0], 1, "SHA-1", new byte[0], 0, 0));
            Assertions.fail();
        } catch (AccessException e)
        {
            Assertions.assertEquals("unable to access salt array", e.getMessage());
        } finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void pbekdf2_access_output() throws Exception
    {
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only"); // JNI only
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        try
        {
            // Exercises interface/fips/jni/kdf_jni.c:186
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_3);
            kdfNI.handleErrorCodes(kdfNI.pbkdf2(new byte[10], new byte[1], 1, "SHA-1", new byte[0], 0, 0));
            Assertions.fail();
        } catch (AccessException e)
        {
            Assertions.assertEquals("unable to access output array", e.getMessage());
        } finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void pbekdf2_access_digest_name() throws Exception
    {
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only"); // JNI only
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        try
        {
            // Exercises interface/fips/jni/kdf_jni.c:223
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_4);
            kdfNI.handleErrorCodes(kdfNI.pbkdf2(new byte[10], new byte[1], 1, "SHA-1", new byte[16], 0, 16));
            Assertions.fail();
        } catch (IllegalStateException e)
        {
            Assertions.assertEquals("unable to access name", e.getMessage());
        } finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void pbekdf2_kdf_fetch_failed() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            kdfNI.handleErrorCodes(kdfNI.pbkdf2(new byte[10], new byte[1], 1, "SHA-1", new byte[0], 0, 0));
            Assertions.fail();
        } catch (OpenSSLException e)
        {
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        } finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void pbekdf2_kdf_create_kdfctx() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        int code;
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            code = kdfNI.pbkdf2(new byte[10], new byte[1], 1, "SHA-1", new byte[0], 0, 0);
            Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 2000, code);
        } finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void pbekdf2_kdf_derive() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        int code;
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);
            code = kdfNI.pbkdf2(new byte[10], new byte[1], 1, "SHA-1", new byte[0], 0, 0);
            Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 2001, code);
        } finally
        {
            operationsTestNI.resetFlags();
        }
    }
}
