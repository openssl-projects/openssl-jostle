package org.openssl.jostle.test.mac;

import org.junit.jupiter.api.*;
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.AccessException;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.mac.MacServiceNI;
import org.openssl.jostle.test.crypto.TestNISelector;
import org.openssl.jostle.util.ops.OperationsTestNI;

import java.security.Security;

public class MacOpsTest
{
    private final MacServiceNI MacServiceNI = TestNISelector.getMacServiceNI();
    private final OperationsTestNI operationsTestNI = TestNISelector.getOperationsTestNI();

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
    public void alloc_name_access() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");

        long ref = 0;
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            ref = MacServiceNI.allocateMac("HMAC", "SHA-256");
            Assertions.fail();
        }
        catch (Exception e)
        {
            Assertions.assertEquals("unable to access name", e.getMessage());
        }
        finally
        {
            if (ref != 0)
            {
                MacServiceNI.dispose(ref);
            }
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void alloc_name_function() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");

        long ref = 0;
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_2);
            ref = MacServiceNI.allocateMac("HMAC", "SHA-256");
            Assertions.fail();
        }
        catch (Exception e)
        {
            Assertions.assertEquals("unable to access function", e.getMessage());
        }
        finally
        {
            if (ref != 0)
            {
                MacServiceNI.dispose(ref);
            }
            operationsTestNI.resetFlags();
        }
    }


    @Test
    public void alloc_fetch_mac() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");


        long ref = 0;
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            ref = MacServiceNI.allocateMac("HMAC", "SHA-256");
            Assertions.fail();
        }
        catch (OpenSSLException e)
        {
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        }
        finally
        {
            if (ref != 0)
            {
                MacServiceNI.dispose(ref);
            }
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void alloc_fetch_new_mac_ctx() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");

        long ref = 0;
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            int[] err = new int[1];
            ref = MacServiceNI.ni_allocateMac("HMAC", "SHA-256", err);
            Assertions.assertEquals(-1002, err[0]); // Offset used to different failure points
        }
        finally
        {
            if (ref != 0)
            {
                MacServiceNI.dispose(ref);
            }
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
    public void init_Unexpected_State() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");

        long ref = MacServiceNI.allocateMac("HMAC", "SHA-256");
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_ALTERNATE_1);
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_ALTERNATE_2);
            MacServiceNI.engineInit(ref, new byte[16]);
            Assertions.fail();
        }
        catch (Exception e)
        {
            Assertions.assertEquals("unexpected state", e.getMessage());
        }
        finally
        {
            MacServiceNI.dispose(ref);
            operationsTestNI.resetFlags();
        }
    }


    @Test
    public void init_mac_init() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");


        long ref = MacServiceNI.allocateMac("HMAC", "SHA-256");
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            int code = MacServiceNI.ni_init(ref, new byte[16]);
            Assertions.assertEquals(-1002, code);
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
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
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
    public void update_update_mac_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");

        long ref = MacServiceNI.allocateMac("HMAC", "SHA-256");
        try
        {
            MacServiceNI.engineInit(ref, new byte[16]);
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            int code = MacServiceNI.ni_updateBytes(ref, new byte[10], 1, 9);
            Assertions.assertEquals(-1002, code);
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
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
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
    public void final_macLenFailed() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");

        long ref = MacServiceNI.allocateMac("HMAC", "SHA-256");
        try
        {
            MacServiceNI.engineInit(ref, new byte[16]);
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            int code = MacServiceNI.ni_doFinal(ref, new byte[32], 0);
            Assertions.assertEquals(-1002, code);
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

    @Test
    public void final_evpMacFinal() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");

        long ref = MacServiceNI.allocateMac("HMAC", "SHA-256");
        try
        {
            MacServiceNI.engineInit(ref, new byte[16]);
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
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
