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
import org.openssl.jostle.jcajce.provider.kdf.MemoryHardKdfNI;
import org.openssl.jostle.test.crypto.TestNISelector;
import org.openssl.jostle.util.ops.OperationsTestNI;

import java.security.Security;

/**
 * Fault-injection coverage for the Argon2 error paths that cannot be reached
 * with real input: the three OpenSSL call sites in {@code jo_argon2} (KDF
 * fetch, ctx allocation, derive) and the JNI array-access failures.
 *
 * <p>Argon2 occupies the 4000 offset block in {@code kdf.c} (scrypt 1000,
 * PBKDF2 2000, HKDF 3000), so the codes asserted here are
 * {@code JO_OPENSSL_ERROR - 400x}. The exact numbers are contract: renumbering
 * an offset in C without updating this file leaves the test asserting a
 * different but still-plausible negative number.</p>
 *
 * <p>The three OpenSSL sites assert the RAW returned code rather than a mapped
 * exception message: an offset-adjusted code is deliberately not an
 * {@code ErrorCode} constant, so {@code handleErrorCodes} cannot classify it.
 * That is the same contract {@code ScryptOpsTest} follows for the 1000 block.
 * The access-failure tests below, whose codes carry no offset, do assert the
 * mapped exception message.</p>
 */
public class Argon2OpsTest
{
    MemoryHardKdfNI kdfNI = TestNISelector.getMemoryHardKDFNI();
    OperationsTestNI operationsTestNI = TestNISelector.getOperationsTestNI();

    /** Valid baseline: Argon2id, v1.3, 1 iteration, 8 KiB, 1 lane. */
    private static final int TYPE = 2;
    private static final int VERSION = 0x13;
    private static final int ITER = 1;
    private static final int MEMORY = 8;
    private static final int LANES = 1;

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
    // OpenSSL call sites in jo_argon2
    // -----------------------------------------------------------------

    @Test
    public void argon2_kdf_fetch_failed() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        int code;
        try
        {
            // Exercises interface/nonfips/util/kdf_memhard.c:147
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            code = kdfNI.argon2(new byte[8], new byte[16], TYPE, VERSION, ITER, MEMORY, LANES,
                    new byte[32], 0, 32);
            // -2 + (-4002) = -4004.
            Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 4002, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void argon2_kdf_create_kdfctx_failed() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        int code;
        try
        {
            // Exercises interface/nonfips/util/kdf_memhard.c:154
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            code = kdfNI.argon2(new byte[8], new byte[16], TYPE, VERSION, ITER, MEMORY, LANES,
                    new byte[32], 0, 32);
            Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 4000, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void argon2_derive_failed() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        int code;
        try
        {
            // Exercises interface/nonfips/util/kdf_memhard.c:170
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);
            code = kdfNI.argon2(new byte[8], new byte[16], TYPE, VERSION, ITER, MEMORY, LANES,
                    new byte[32], 0, 32);
            Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 4001, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    // -----------------------------------------------------------------
    // JNI array-access failures
    // -----------------------------------------------------------------

    @Test
    public void argon2_access_password() throws Exception
    {
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        try
        {
            // Exercises interface/nonfips/jni/kdf_memhard_jni.c:159
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            kdfNI.handleErrorCodes(kdfNI.argon2(new byte[8], new byte[16], TYPE, VERSION, ITER, MEMORY, LANES,
                    new byte[32], 0, 32));
            Assertions.fail("expected the injected access failure to surface");
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access password array", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void argon2_access_salt() throws Exception
    {
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        try
        {
            // Exercises interface/nonfips/jni/kdf_memhard_jni.c:169
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_2);
            kdfNI.handleErrorCodes(kdfNI.argon2(new byte[8], new byte[16], TYPE, VERSION, ITER, MEMORY, LANES,
                    new byte[32], 0, 32));
            Assertions.fail("expected the injected access failure to surface");
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access salt array", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void argon2_access_output() throws Exception
    {
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        try
        {
            // Exercises interface/nonfips/jni/kdf_memhard_jni.c:213
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_3);
            kdfNI.handleErrorCodes(kdfNI.argon2(new byte[8], new byte[16], TYPE, VERSION, ITER, MEMORY, LANES,
                    new byte[32], 0, 32));
            Assertions.fail("expected the injected access failure to surface");
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access output array", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }
}
