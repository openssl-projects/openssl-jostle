package org.openssl.jostle.test.mac;

import org.junit.jupiter.api.*;
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.AccessException;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.OverflowException;
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
        Assumptions.assumeFalse(Loader.isFFM(), "JNI Only");

        long ref = 0;
        try
        {
            // Exercises interface/nonfips/jni/mac_jni.c:48
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
        Assumptions.assumeFalse(Loader.isFFM(), "JNI Only");

        long ref = 0;
        try
        {
            // Exercises interface/nonfips/jni/mac_jni.c:54
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
            // Exercises interface/nonfips/util/mac.c:201
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_CREATE_1);
            ref = MacServiceNI.allocateMac("HMAC", "SHA-256");
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            // An unfetchable MAC name is not found, as for the digests.
            Assertions.assertEquals("name not found", e.getMessage());
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
            // Exercises interface/nonfips/util/mac.c:207
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_CREATE_2);
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
        Assumptions.assumeFalse(Loader.isFFM(), "JNI Only");

        long ref = MacServiceNI.allocateMac("HMAC", "SHA-256");
        try
        {
            // Exercises interface/nonfips/jni/mac_jni.c:147
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_3);
            MacServiceNI.engineInit(ref, new byte[16], null, null, 0);
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
            // Exercises interface/nonfips/util/mac.c:69
            // Exercises interface/nonfips/util/mac.c:90
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_ALTERNATE_1);
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_ALTERNATE_2);
            MacServiceNI.engineInit(ref, new byte[16], null, null, 0);
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
            // Exercises interface/nonfips/util/mac.c:152
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_INIT_1);
            int code = MacServiceNI.ni_init(ref, new byte[16], null, null, 0);
            Assertions.assertEquals(-1003, code);
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
        Assumptions.assumeFalse(Loader.isFFM(), "JNI Only");

        long ref = MacServiceNI.allocateMac("HMAC", "SHA-256");
        try
        {
            MacServiceNI.engineInit(ref, new byte[16], null, null, 0);
            // Exercises interface/nonfips/jni/mac_jni.c:230
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_4);
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
            MacServiceNI.engineInit(ref, new byte[16], null, null, 0);
            // Exercises interface/nonfips/util/mac.c:398
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            int code = MacServiceNI.ni_updateBytes(ref, new byte[10], 1, 9);
            Assertions.assertEquals(-1004, code);
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
        Assumptions.assumeFalse(Loader.isFFM(), "JNI Only");

        long ref = MacServiceNI.allocateMac("HMAC", "SHA-256");
        try
        {
            MacServiceNI.engineInit(ref, new byte[16], null, null, 0);
            // Exercises interface/nonfips/jni/mac_jni.c:284
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_7);
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
            MacServiceNI.engineInit(ref, new byte[16], null, null, 0);
            // Exercises interface/nonfips/util/mac.c:450
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_12);
            int code = MacServiceNI.ni_doFinal(ref, new byte[32], 0);
            Assertions.assertEquals(-1005, code);
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
            MacServiceNI.engineInit(ref, new byte[16], null, null, 0);
            // Exercises interface/nonfips/util/mac.c:421
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


    @Test
    public void final_macLenOverflow() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");

        long ref = MacServiceNI.allocateMac("HMAC", "SHA-256");
        try
        {
            MacServiceNI.engineInit(ref, new byte[16], null, null, 0);
            // Exercises interface/nonfips/util/mac.c:454
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);
            MacServiceNI.getMacLength(ref);
            Assertions.fail();
        }
        catch (OverflowException e)
        {
            Assertions.assertEquals("output too long int32", e.getMessage());
        }
        finally
        {
            MacServiceNI.dispose(ref);
            operationsTestNI.resetFlags();
        }
    }


    @Test
    public void final_outputSizeOverflow() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");

        long ref = MacServiceNI.allocateMac("HMAC", "SHA-256");
        try
        {
            MacServiceNI.engineInit(ref, new byte[16], null, null, 0);
            // Exercises interface/nonfips/ffm/mac_ffm.c:150
            // Exercises interface/nonfips/jni/mac_jni.c:274
            operationsTestNI.setFlag(Loader.isFFM() ? OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_3
                    : OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_2);
            MacServiceNI.doFinal(ref, new byte[32], 0);
            Assertions.fail();
        }
        catch (OverflowException e)
        {
            Assertions.assertEquals("output too long int32", e.getMessage());
        }
        finally
        {
            MacServiceNI.dispose(ref);
            operationsTestNI.resetFlags();
        }
    }


    @Test
    public void macLengthMeta_fetchMd_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");

        long ref = MacServiceNI.allocateMac("HMAC", "SHA-256");
        try
        {
            // Exercises interface/nonfips/util/mac.c:481
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);
            int code = MacServiceNI.ni_macLengthMeta(ref);
            Assertions.assertEquals(-1012, code);
        }
        finally
        {
            MacServiceNI.dispose(ref);
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void macLengthMeta_fetchCipher_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");

        long ref = MacServiceNI.allocateMac("CMAC", "aes-cbc");
        try
        {
            // Exercises interface/nonfips/util/mac.c:501
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_4);
            int code = MacServiceNI.ni_macLengthMeta(ref);
            Assertions.assertEquals(-1013, code);
        }
        finally
        {
            MacServiceNI.dispose(ref);
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void macLengthMeta_mdSize_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");

        long ref = MacServiceNI.allocateMac("HMAC", "SHA-256");
        try
        {
            // Exercises interface/nonfips/util/mac.c:486
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_5);
            int code = MacServiceNI.ni_macLengthMeta(ref);
            Assertions.assertEquals(-1014, code);
        }
        finally
        {
            MacServiceNI.dispose(ref);
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void macLengthMeta_cipherBlock_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");

        long ref = MacServiceNI.allocateMac("CMAC", "aes-cbc");
        try
        {
            // Exercises interface/nonfips/util/mac.c:506
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_6);
            int code = MacServiceNI.ni_macLengthMeta(ref);
            Assertions.assertEquals(-1015, code);
        }
        finally
        {
            MacServiceNI.dispose(ref);
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void poly1305_init_branchSkipped_unexpectedState() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");

        long ref = MacServiceNI.allocateMac("POLY1305", "POLY1305");
        try
        {
            // OPS_ALTERNATE_3 skips the POLY1305 init branch; with the CMAC/HMAC
            // branches not matching the name, init falls through to the final
            // else -> JO_UNEXPECTED_STATE.
            // Exercises interface/nonfips/util/mac.c:96
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_ALTERNATE_3);
            MacServiceNI.engineInit(ref, new byte[32], null, null, 0);
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
    public void poly1305_macLengthMeta_getMacSize_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");

        long ref = MacServiceNI.allocateMac("POLY1305", "POLY1305");
        try
        {
            // Exercises interface/nonfips/util/mac.c:518
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_7);
            int code = MacServiceNI.ni_macLengthMeta(ref);
            Assertions.assertEquals(-1016, code);
        }
        finally
        {
            MacServiceNI.dispose(ref);
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void gmac_init_branchSkipped_unexpectedState() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");

        long ref = MacServiceNI.allocateMac("GMAC", "aes-gcm");
        try
        {
            // OPS_ALTERNATE_4 skips the GMAC init branch; with the CMAC/HMAC/
            // POLY1305 branches not matching the name, init falls through to
            // the final else -> JO_UNEXPECTED_STATE.
            // Exercises interface/nonfips/util/mac.c:101
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_ALTERNATE_4);
            MacServiceNI.engineInit(ref, new byte[16], new byte[12], null, 0);
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
    public void kmac_init_branchSkipped_unexpectedState() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");

        long ref = MacServiceNI.allocateMac("KMAC-128", "KMAC-128");
        try
        {
            // OPS_ALTERNATE_5 skips the KMAC init branch; with CMAC/HMAC/
            // POLY1305/GMAC not matching the name, init falls through to the
            // final else -> JO_UNEXPECTED_STATE.
            // Exercises interface/nonfips/util/mac.c:127
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_ALTERNATE_5);
            MacServiceNI.engineInit(ref, new byte[32], null, null, 0);
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
    public void kmac_init_customAccessFailure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        Assumptions.assumeFalse(Loader.isFFM(), "JNI Only");

        long ref = MacServiceNI.allocateMac("KMAC-128", "KMAC-128");
        try
        {
            // Exercises interface/nonfips/jni/mac_jni.c:157
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_6);
            MacServiceNI.engineInit(ref, new byte[32], null, new byte[]{1, 2, 3}, 0);
            Assertions.fail();
        }
        catch (IllegalStateException e)
        {
            Assertions.assertEquals("native layer was unable to access customisation string",
                    e.getMessage());
        }
        finally
        {
            MacServiceNI.dispose(ref);
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void kmac_macLengthMeta_ctxNewFailure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");

        long ref = MacServiceNI.allocateMac("KMAC-128", "KMAC-128");
        try
        {
            // Exercises interface/nonfips/util/mac.c:536
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_10);
            int code = MacServiceNI.ni_macLengthMeta(ref);
            Assertions.assertEquals(-1019, code);
        }
        finally
        {
            MacServiceNI.dispose(ref);
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void kmac_macLengthMeta_zeroSize() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");

        long ref = MacServiceNI.allocateMac("KMAC-128", "KMAC-128");
        try
        {
            // Exercises interface/nonfips/util/mac.c:541
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_11);
            int code = MacServiceNI.ni_macLengthMeta(ref);
            Assertions.assertEquals(-1020, code);
        }
        finally
        {
            MacServiceNI.dispose(ref);
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void wrongKindDisposeFreesNothing()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        MacCells.wrongKindDisposeFreesNothing(MacServiceNI, NISelector.MDServiceNI, operationsTestNI);
    }

    @Test
    public void unusableErrArrayCreatesNoContext()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        Assumptions.assumeTrue(Loader.isFFM(), "FFM only: JNI aborts at the bridge assert");
        MacCells.unusableErrArrayCreatesNoContext(MacServiceNI, operationsTestNI);
    }

    @Test
    public void keyCopiesAreCleansed()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        MacCells.keyCopiesAreCleansed(MacServiceNI, operationsTestNI);
    }

    @Test
    public void failedReinitInsideResetDropsEverything()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        // Exercises interface/nonfips/util/mac.c:152
        MacCells.failedReinitInsideResetDropsEverything(MacServiceNI, operationsTestNI,
                () -> operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_INIT_1), -1003);
    }

    @Test
    public void copy_upRefFailure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        // Exercises interface/nonfips/util/mac.c:254
        MacCells.copyFailureSite(MacServiceNI, operationsTestNI,
                () -> operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_8), -1017,
                JostleProvider.PROVIDER_NAME);
    }

    @Test
    public void copy_dupFailure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        // Exercises interface/nonfips/util/mac.c:261
        MacCells.copyFailureSite(MacServiceNI, operationsTestNI,
                () -> operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_9), -1018,
                JostleProvider.PROVIDER_NAME);
    }

    @Test
    public void gmac_init_ivAccessFailure()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        Assumptions.assumeFalse(Loader.isFFM(), "JNI Only");
        try
        {
            // Exercises interface/nonfips/jni/mac_jni.c:152
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_5);
            MacCells.gmacIvAccessFailure(MacServiceNI);
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }
}
