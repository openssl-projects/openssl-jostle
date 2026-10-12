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
import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.AccessException;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.kdf.MemoryHardKdfNI;
import org.openssl.jostle.test.crypto.TestNISelector;
import org.openssl.jostle.util.ops.OperationsTestNI;

import java.security.Security;

public class ScryptOpsTest
{


    MemoryHardKdfNI kdfNI = TestNISelector.getMemoryHardKDFNI();
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
    public void scrypt_access_password() throws Exception
    {
        Assumptions.assumeFalse(Loader.isFFM(), "JNI Only"); // JNI only
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        try
        {
            // Exercises interface/nonfips/jni/kdf_memhard_jni.c:83
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            kdfNI.handleErrorCodes(kdfNI.scrypt(new byte[0], new byte[0], 2, 10, 10, new byte[0], 0, 0));
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
    public void scrypt_access_salt() throws Exception
    {
        Assumptions.assumeFalse(Loader.isFFM(), "JNI Only"); // JNI only
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        try
        {
            // Exercises interface/nonfips/jni/kdf_memhard_jni.c:93
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_2);
            kdfNI.handleErrorCodes(kdfNI.scrypt(new byte[1], new byte[1], 2, 10, 10, new byte[0], 0, 0));
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
    public void scrypt_access_output() throws Exception
    {
        Assumptions.assumeFalse(Loader.isFFM(), "JNI Only"); // JNI only
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        try
        {
            // Exercises interface/nonfips/jni/kdf_memhard_jni.c:128
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_3);
            kdfNI.handleErrorCodes(kdfNI.scrypt(new byte[0], new byte[1], 2, 10, 10, new byte[0], 0, 0));
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
    public void scrypt_kdf_fetch_failed() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        int code;
        try
        {
            // Exercises interface/nonfips/util/kdf_memhard.c:51
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            code = kdfNI.scrypt(new byte[0], new byte[1], 2, 10, 10, new byte[16], 0, 16);
            // -2 + (-1002) = -1004.
            Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 1002, code);
        } finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void scrypt_kdf_create_kdfctx() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        int code;
        try
        {
            // Exercises interface/nonfips/util/kdf_memhard.c:59
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            code = kdfNI.scrypt(new byte[0], new byte[1], 2, 10, 10, new byte[16], 0, 16);

            Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 1000, code);
        } finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void scrypt_kdf_derive() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        int code;
        try
        {
            // Exercises interface/nonfips/util/kdf_memhard.c:74
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);
            code = kdfNI.scrypt(new byte[0], new byte[1], 2, 10, 10, new byte[16], 0, 16);

            Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 1001, code);
        } finally
        {
            operationsTestNI.resetFlags();
        }
    }

    /** JNI copies the password and the output through the cleansing helper on every outcome; FFM takes none. */
    @Test
    public void secretCopiesAreCleansed()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        int expected = Loader.isFFM() ? 0 : 2;
        int[][] nrp = {{16, 1, 1}, {16, 1, 1}, {1 << 16, 1, 1}};
        int[] outLen = {32, 33, 32};
        int[] codes = {0, ErrorCode.JO_OUTPUT_OUT_OF_RANGE.getCode(), ErrorCode.JO_OPENSSL_ERROR.getCode()};
        for (int i = 0; i != codes.length; i++)
        {
            operationsTestNI.ledgerReset();
            Assertions.assertEquals(codes[i],
                    kdfNI.scrypt(new byte[8], new byte[16], nrp[i][0], nrp[i][1], nrp[i][2], new byte[32], 0,
                            outLen[i]));
            for (OperationsTestNI.LedgerType t : new OperationsTestNI.LedgerType[]{
                    OperationsTestNI.LedgerType.SECRET_BYTEARRAY, OperationsTestNI.LedgerType.SECRET_CLEANSE})
            {
                Assertions.assertEquals(expected, operationsTestNI.ledgerCreated(t), "call " + i + " " + t);
                Assertions.assertEquals(expected, operationsTestNI.ledgerDestroyed(t), "call " + i + " " + t);
            }
        }
    }

    /** The caller's array changes only inside the window, and only when the derive succeeded. */
    @Test
    public void outputIsWrittenOnlyOnSuccess()
    {
        byte[] reference = new byte[32];
        Assertions.assertEquals(0, kdfNI.scrypt(new byte[8], new byte[16], 16, 1, 1, reference, 0, 32));
        int[][] cases = {{16, 32}, {16, 57}, {1 << 16, 32}};
        int[] codes = {0, ErrorCode.JO_OUTPUT_OUT_OF_RANGE.getCode(), ErrorCode.JO_OPENSSL_ERROR.getCode()};
        for (int i = 0; i != codes.length; i++)
        {
            byte[] out = new byte[64];
            java.util.Arrays.fill(out, (byte) 0xAA);
            byte[] before = out.clone();
            Assertions.assertEquals(codes[i],
                    kdfNI.scrypt(new byte[8], new byte[16], cases[i][0], 1, 1, out, 8, cases[i][1]));
            byte[] expected = before.clone();
            if (codes[i] == 0)
            {
                System.arraycopy(reference, 0, expected, 8, 32);
            }
            Assertions.assertArrayEquals(expected, out, "case " + i);
        }
    }
}
