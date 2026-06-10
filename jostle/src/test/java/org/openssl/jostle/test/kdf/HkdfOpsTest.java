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
 * Fault-injection (OPS) tests for the HKDF bridge and util code, mirroring
 * {@link PBKdf2OpsTest}. The JNI access faults (OPS_FAILED_ACCESS_*) are
 * JNI-only; the util-layer OPENSSL_ERROR sites run on both bridges.
 */
public class HkdfOpsTest
{
    KdfNI kdfNI = TestNISelector.getKDFNI();
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

    @Test
    public void hkdf_access_ikm() throws Exception
    {
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        try
        {
            // Exercises interface/jni/kdf_jni.c:277
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            kdfNI.handleErrorCodes(kdfNI.hkdf(new byte[1], new byte[1], new byte[1], "SHA-256", new byte[1], 0, 1));
            Assertions.fail();
        } catch (AccessException e)
        {
            Assertions.assertEquals("unable to access ikm array", e.getMessage());
        } finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void hkdf_access_salt() throws Exception
    {
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        try
        {
            // Exercises interface/jni/kdf_jni.c:289
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_2);
            kdfNI.handleErrorCodes(kdfNI.hkdf(new byte[1], new byte[1], new byte[1], "SHA-256", new byte[1], 0, 1));
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
    public void hkdf_access_info() throws Exception
    {
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        try
        {
            // Exercises interface/jni/kdf_jni.c:296
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_3);
            kdfNI.handleErrorCodes(kdfNI.hkdf(new byte[1], new byte[1], new byte[1], "SHA-256", new byte[1], 0, 1));
            Assertions.fail();
        } catch (AccessException e)
        {
            Assertions.assertEquals("unable to access info array", e.getMessage());
        } finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void hkdf_access_output() throws Exception
    {
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        try
        {
            // Exercises interface/jni/kdf_jni.c:302
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_4);
            kdfNI.handleErrorCodes(kdfNI.hkdf(new byte[1], new byte[1], new byte[1], "SHA-256", new byte[1], 0, 1));
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
    public void hkdf_access_digest_name() throws Exception
    {
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        try
        {
            // Exercises interface/jni/kdf_jni.c:339
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_5);
            kdfNI.handleErrorCodes(kdfNI.hkdf(new byte[1], new byte[1], new byte[1], "SHA-256", new byte[1], 0, 1));
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
    public void hkdf_kdf_fetch_failed() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        int code;
        try
        {
            // Exercises interface/util/kdf.c:156
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            code = kdfNI.hkdf(new byte[1], new byte[1], new byte[1], "SHA-256", new byte[1], 0, 1);
            // -2 + (-3002) = -3004.
            Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 3002, code);
        } finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void hkdf_kdf_create_kdfctx() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        int code;
        try
        {
            // Exercises interface/util/kdf.c:163
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            code = kdfNI.hkdf(new byte[1], new byte[1], new byte[1], "SHA-256", new byte[1], 0, 1);
            // -2 + (-3000) = -3002.
            Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 3000, code);
        } finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void hkdf_kdf_derive() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        int code;
        try
        {
            // Exercises interface/util/kdf.c:191
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);
            code = kdfNI.hkdf(new byte[1], new byte[1], new byte[1], "SHA-256", new byte[1], 0, 1);
            // -2 + (-3001) = -3003.
            Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 3001, code);
        } finally
        {
            operationsTestNI.resetFlags();
        }
    }
}
