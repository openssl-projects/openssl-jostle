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
 * Fault-injection (OPS) tests for the KBKDF / SSKDF / SSHKDF bridges and util
 * code, mirroring {@link HkdfOpsTest}. The JNI access faults
 * ({@code OPS_FAILED_ACCESS_*}) are JNI-only; the util-layer
 * {@code OPS_OPENSSL_ERROR_*} sites run on both bridges.
 */
public class SP800KdfOpsTest
{
    private final KdfNI kdfNI = TestNISelector.getKDFNI();
    private final OperationsTestNI operationsTestNI = TestNISelector.getOperationsTestNI();

    private static final String COUNTER = "COUNTER";
    private static final String HMAC = "HMAC";
    private static final byte[] KI = new byte[32];
    private static final byte[] H20 = new byte[20];

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

    private int kbkdf()
    {
        return kdfNI.kbkdf(COUNTER, HMAC, "SHA-256", null, KI, new byte[1], new byte[1],
                new byte[1], 32, 0, 0, new byte[16], 0, 16);
    }

    private int sskdf()
    {
        return kdfNI.sskdf("SHA-256", KI, new byte[1], new byte[16], 0, 16);
    }

    private int sshkdf()
    {
        return kdfNI.sshkdf("SHA-256", KI, H20, H20, "A", new byte[16], 0, 16);
    }

    private void assumeJniOps()
    {
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
    }

    // ---------------------------------------------------- KBKDF JNI access

    @Test
    public void kbkdf_access_mode()
    {
        assumeJniOps();
        try
        {
            // Exercises interface/nonfips/jni/kdf_jni.c:335
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_5);
            kdfNI.handleErrorCodes(kbkdf());
            Assertions.fail();
        }
        catch (IllegalStateException e)
        {
            Assertions.assertEquals("unable to access name", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void kbkdf_access_mac()
    {
        assumeJniOps();
        try
        {
            // Exercises interface/nonfips/jni/kdf_jni.c:352
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_6);
            kdfNI.handleErrorCodes(kbkdf());
            Assertions.fail();
        }
        catch (IllegalStateException e)
        {
            Assertions.assertEquals("unable to access name", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void kbkdf_access_digest()
    {
        assumeJniOps();
        try
        {
            // Exercises interface/nonfips/jni/kdf_jni.c:363
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_7);
            kdfNI.handleErrorCodes(kbkdf());
            Assertions.fail();
        }
        catch (IllegalStateException e)
        {
            Assertions.assertEquals("unable to access name", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void kbkdf_access_cipher()
    {
        assumeJniOps();
        try
        {
            // Exercises interface/nonfips/jni/kdf_jni.c:374
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_8);
            kdfNI.handleErrorCodes(kdfNI.kbkdf(COUNTER, "CMAC", null, "AES-128-CBC",
                    new byte[16], null, new byte[1], null, 32, 0, 0, new byte[16], 0, 16));
            Assertions.fail();
        }
        catch (IllegalStateException e)
        {
            Assertions.assertEquals("unable to access name", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void kbkdf_access_key()
    {
        assumeJniOps();
        try
        {
            // Exercises interface/nonfips/jni/kdf_jni.c:386
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            kdfNI.handleErrorCodes(kbkdf());
            Assertions.fail();
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access secret array", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void kbkdf_access_label()
    {
        assumeJniOps();
        try
        {
            // Exercises interface/nonfips/jni/kdf_jni.c:397
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_2);
            kdfNI.handleErrorCodes(kbkdf());
            Assertions.fail();
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
    public void kbkdf_access_context()
    {
        assumeJniOps();
        try
        {
            // Exercises interface/nonfips/jni/kdf_jni.c:403
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_3);
            kdfNI.handleErrorCodes(kbkdf());
            Assertions.fail();
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access context array", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void kbkdf_access_seed()
    {
        assumeJniOps();
        try
        {
            // Exercises interface/nonfips/jni/kdf_jni.c:409
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_9);
            kdfNI.handleErrorCodes(kbkdf());
            Assertions.fail();
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access seed array", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void kbkdf_access_output()
    {
        assumeJniOps();
        try
        {
            // Exercises interface/nonfips/jni/kdf_jni.c:414
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_4);
            kdfNI.handleErrorCodes(kbkdf());
            Assertions.fail();
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

    // ---------------------------------------------------- SSKDF JNI access

    @Test
    public void sskdf_access_digest()
    {
        assumeJniOps();
        try
        {
            // Exercises interface/nonfips/jni/kdf_jni.c:494
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            kdfNI.handleErrorCodes(sskdf());
            Assertions.fail();
        }
        catch (IllegalStateException e)
        {
            Assertions.assertEquals("unable to access name", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void sskdf_access_secret()
    {
        assumeJniOps();
        try
        {
            // Exercises interface/nonfips/jni/kdf_jni.c:499
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_2);
            kdfNI.handleErrorCodes(sskdf());
            Assertions.fail();
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access secret array", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void sskdf_access_info()
    {
        assumeJniOps();
        try
        {
            // Exercises interface/nonfips/jni/kdf_jni.c:510
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_3);
            kdfNI.handleErrorCodes(sskdf());
            Assertions.fail();
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access context array", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void sskdf_access_output()
    {
        assumeJniOps();
        try
        {
            // Exercises interface/nonfips/jni/kdf_jni.c:515
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_4);
            kdfNI.handleErrorCodes(sskdf());
            Assertions.fail();
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

    // --------------------------------------------------- SSHKDF JNI access

    @Test
    public void sshkdf_access_digest()
    {
        assumeJniOps();
        try
        {
            // Exercises interface/nonfips/jni/kdf_jni.c:582
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_5);
            kdfNI.handleErrorCodes(sshkdf());
            Assertions.fail();
        }
        catch (IllegalStateException e)
        {
            Assertions.assertEquals("unable to access name", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void sshkdf_access_type()
    {
        assumeJniOps();
        try
        {
            // Exercises interface/nonfips/jni/kdf_jni.c:599
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_6);
            kdfNI.handleErrorCodes(sshkdf());
            Assertions.fail();
        }
        catch (IllegalStateException e)
        {
            Assertions.assertEquals("unable to access name", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void sshkdf_access_key()
    {
        assumeJniOps();
        try
        {
            // Exercises interface/nonfips/jni/kdf_jni.c:604
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            kdfNI.handleErrorCodes(sshkdf());
            Assertions.fail();
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access secret array", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void sshkdf_access_xcghash()
    {
        assumeJniOps();
        try
        {
            // Exercises interface/nonfips/jni/kdf_jni.c:614
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_2);
            kdfNI.handleErrorCodes(sshkdf());
            Assertions.fail();
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access exchange hash array", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void sshkdf_access_sessionId()
    {
        assumeJniOps();
        try
        {
            // Exercises interface/nonfips/jni/kdf_jni.c:624
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_3);
            kdfNI.handleErrorCodes(sshkdf());
            Assertions.fail();
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access session id array", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void sshkdf_access_output()
    {
        assumeJniOps();
        try
        {
            // Exercises interface/nonfips/jni/kdf_jni.c:634
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_4);
            kdfNI.handleErrorCodes(sshkdf());
            Assertions.fail();
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

    // ------------------------------------------------------- util OpenSSL

    @Test
    public void kbkdf_fetch_failed()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        try
        {
            // Exercises interface/nonfips/util/kdf.c:198
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            // -2 + (-4002) = -4004.
            Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 4002, kbkdf());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void kbkdf_create_kdfctx()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        try
        {
            // Exercises interface/nonfips/util/kdf.c:204
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            // -2 + (-4000) = -4002.
            Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 4000, kbkdf());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void kbkdf_derive()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        try
        {
            // Exercises interface/nonfips/util/kdf.c:240
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);
            // -2 + (-4001) = -4003.
            Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 4001, kbkdf());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void sskdf_fetch_failed()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        try
        {
            // Exercises interface/nonfips/util/kdf.c:284
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            // -2 + (-5002) = -5004.
            Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 5002, sskdf());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void sskdf_create_kdfctx()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        try
        {
            // Exercises interface/nonfips/util/kdf.c:290
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            // -2 + (-5000) = -5002.
            Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 5000, sskdf());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void sskdf_derive()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        try
        {
            // Exercises interface/nonfips/util/kdf.c:304
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);
            // -2 + (-5001) = -5003.
            Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 5001, sskdf());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void sshkdf_fetch_failed()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        try
        {
            // Exercises interface/nonfips/util/kdf.c:352
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            // -2 + (-6002) = -6004.
            Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 6002, sshkdf());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void sshkdf_create_kdfctx()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        try
        {
            // Exercises interface/nonfips/util/kdf.c:358
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            // -2 + (-6000) = -6002.
            Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 6000, sshkdf());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void sshkdf_derive()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        try
        {
            // Exercises interface/nonfips/util/kdf.c:373
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);
            // -2 + (-6001) = -6003.
            Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 6001, sshkdf());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }
}
