package org.openssl.jostle.test.kdf;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.AccessException;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.kdf.KdfNI;
import org.openssl.jostle.test.crypto.TestNISelector;
import org.openssl.jostle.util.ops.OperationsTestNI;

public class PBKdf2OpsTest
{
    static
    {
        CryptoServicesRegistrar.isNativeAvailable(); // Trigger Loading
    }

    KdfNI kdfNI = TestNISelector.getKDFNI();
    OperationsTestNI operationsTestNI = TestNISelector.getOperationsTestNI();

    @Test
    public void pbekdf2_access_password() throws Exception
    {
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only"); // JNI only
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        try
        {
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
            Assertions.assertNull(e.getMessage());
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
            Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 1000, code);
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
            Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 1001, code);
        } finally
        {
            operationsTestNI.resetFlags();
        }
    }
}
