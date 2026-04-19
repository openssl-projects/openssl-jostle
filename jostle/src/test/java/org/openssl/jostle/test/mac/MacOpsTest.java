package org.openssl.jostle.test.mac;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.AccessException;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.mac.MacServiceNI;
import org.openssl.jostle.test.crypto.TestNISelector;
import org.openssl.jostle.util.ops.OperationsTestNI;

public class MacOpsTest
{
    static
    {
        CryptoServicesRegistrar.isNativeAvailable();
    }

    private final MacServiceNI MacServiceNI = TestNISelector.getMacServiceNI();
    private final OperationsTestNI operationsTestNI = TestNISelector.getOperationsTestNI();

    @BeforeEach
    public void beforeEach()
    {
        if (operationsTestNI.opsTestAvailable())
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void init_keyAccessFailure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");

        long ref = MacServiceNI.allocateMac("HMAC", "SHA-256");
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            MacServiceNI.engineInit(ref, new byte[16]);
            Assertions.fail();
        }
        catch (Exception e)
        {
            Assertions.assertEquals("unable to access key bytes", e.getMessage());
        }
        finally
        {
            MacServiceNI.dispose(ref);
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void update_inputAccessFailure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");

        long ref = MacServiceNI.allocateMac("HMAC", "SHA-256");
        try
        {
            MacServiceNI.engineInit(ref, new byte[16]);
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_2);
            MacServiceNI.engineUpdate(ref, new byte[10], 1, 9);
            Assertions.fail();
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access input array", e.getMessage());
        }
        finally
        {
            MacServiceNI.dispose(ref);
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void final_outputAccessFailure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");

        long ref = MacServiceNI.allocateMac("HMAC", "SHA-256");
        try
        {
            MacServiceNI.engineInit(ref, new byte[16]);
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_3);
            MacServiceNI.doFinal(ref, new byte[32], 0);
            Assertions.fail();
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access output array", e.getMessage());
        }
        finally
        {
            MacServiceNI.dispose(ref);
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void final_openSslFailure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");

        long ref = MacServiceNI.allocateMac("HMAC", "SHA-256");
        try
        {
            MacServiceNI.engineInit(ref, new byte[16]);
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            MacServiceNI.doFinal(ref, new byte[32], 0);
            Assertions.fail();
        }
        catch (OpenSSLException e)
        {
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        }
        finally
        {
            MacServiceNI.dispose(ref);
            operationsTestNI.resetFlags();
        }
    }
}
