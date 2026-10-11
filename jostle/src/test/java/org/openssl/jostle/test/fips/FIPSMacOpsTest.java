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
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.AccessException;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.OverflowException;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.jcajce.provider.mac.MacServiceNI;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.test.mac.MacCells;
import org.openssl.jostle.util.ops.OperationsTestNI;

/**
 * Operations-test fault injection at the FIPS MAC NI surface. The fault sites
 * live in the shared interface/fips/util/mac.c, re-included into the FIPS library,
 * so the offset-disambiguated codes (1000-block) fire identically when driven
 * through {@link FIPSNISelector#MacServiceNI}. Mirrors {@code MacOpsTest}.
 *
 * <p>FIPS divergence: the two POLY1305 tests are omitted - Poly1305 is not
 * FIPS-approved, so {@code allocateMac("POLY1305", ...)} fails at the fetch
 * before any OPS site is reached. HMAC-SHA256 and CMAC/AES-CBC (both approved)
 * cover the remaining sites.
 *
 * <p>Requires a JOSTLE_OPS_TEST build of the FIPS library: gated on
 * {@code TEST_FIPS_LIB} and per-test on {@code opsTestAvailable()}. The
 * FAILED_ACCESS tests are JNI-only.
 */
public class FIPSMacOpsTest
{
    @BeforeAll
    public static void beforeAll()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        TestUtil.addFipsProvider();
    }

    private final MacServiceNI macServiceNI = FIPSNISelector.MacServiceNI;
    private final OperationsTestNI operationsTestNI = FIPSNISelector.OperationsTestNI;

    @BeforeEach
    public void beforeEach() throws Exception
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
            // Exercises interface/fips/jni/mac_jni.c:48
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            ref = macServiceNI.allocateMac("HMAC", "SHA-256");
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
                macServiceNI.dispose(ref);
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
            // Exercises interface/fips/jni/mac_jni.c:54
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_2);
            ref = macServiceNI.allocateMac("HMAC", "SHA-256");
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
                macServiceNI.dispose(ref);
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
            // Exercises interface/fips/util/mac.c:201
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_CREATE_1);
            ref = macServiceNI.allocateMac("HMAC", "SHA-256");
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
                macServiceNI.dispose(ref);
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
            // Exercises interface/fips/util/mac.c:207
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_CREATE_2);
            int[] err = new int[1];
            ref = macServiceNI.ni_allocateMac("HMAC", "SHA-256", err);
            Assertions.assertEquals(-1002, err[0]);
        }
        finally
        {
            if (ref != 0)
            {
                macServiceNI.dispose(ref);
            }
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void init_keyAccessFailure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        Assumptions.assumeFalse(Loader.isFFM(), "JNI Only");
        long ref = macServiceNI.allocateMac("HMAC", "SHA-256");
        try
        {
            // Exercises interface/fips/jni/mac_jni.c:147
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_3);
            macServiceNI.engineInit(ref, new byte[16], null, null, 0);
            Assertions.fail();
        }
        catch (Exception e)
        {
            Assertions.assertEquals("unable to access key bytes", e.getMessage());
        }
        finally
        {
            macServiceNI.dispose(ref);
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void init_Unexpected_State() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        long ref = macServiceNI.allocateMac("HMAC", "SHA-256");
        try
        {
            // Exercises interface/fips/util/mac.c:69
            // Exercises interface/fips/util/mac.c:90
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_ALTERNATE_1);
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_ALTERNATE_2);
            macServiceNI.engineInit(ref, new byte[16], null, null, 0);
            Assertions.fail();
        }
        catch (Exception e)
        {
            Assertions.assertEquals("unexpected state", e.getMessage());
        }
        finally
        {
            macServiceNI.dispose(ref);
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void init_mac_init() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        long ref = macServiceNI.allocateMac("HMAC", "SHA-256");
        try
        {
            // Exercises interface/fips/util/mac.c:152
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_INIT_1);
            int code = macServiceNI.ni_init(ref, new byte[16], null, null, 0);
            Assertions.assertEquals(-1003, code);
        }
        finally
        {
            macServiceNI.dispose(ref);
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void update_inputAccessFailure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        Assumptions.assumeFalse(Loader.isFFM(), "JNI Only");
        long ref = macServiceNI.allocateMac("HMAC", "SHA-256");
        try
        {
            macServiceNI.engineInit(ref, new byte[16], null, null, 0);
            // Exercises interface/fips/jni/mac_jni.c:230
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_4);
            macServiceNI.engineUpdate(ref, new byte[10], 1, 9);
            Assertions.fail();
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access input array", e.getMessage());
        }
        finally
        {
            macServiceNI.dispose(ref);
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void update_update_mac_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        long ref = macServiceNI.allocateMac("HMAC", "SHA-256");
        try
        {
            macServiceNI.engineInit(ref, new byte[16], null, null, 0);
            // Exercises interface/fips/util/mac.c:398
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            int code = macServiceNI.ni_updateBytes(ref, new byte[10], 1, 9);
            Assertions.assertEquals(-1004, code);
        }
        finally
        {
            macServiceNI.dispose(ref);
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void final_outputAccessFailure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        Assumptions.assumeFalse(Loader.isFFM(), "JNI Only");
        long ref = macServiceNI.allocateMac("HMAC", "SHA-256");
        try
        {
            macServiceNI.engineInit(ref, new byte[16], null, null, 0);
            // Exercises interface/fips/jni/mac_jni.c:284
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_7);
            macServiceNI.doFinal(ref, new byte[32], 0);
            Assertions.fail();
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access output array", e.getMessage());
        }
        finally
        {
            macServiceNI.dispose(ref);
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void final_macLenFailed() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        long ref = macServiceNI.allocateMac("HMAC", "SHA-256");
        try
        {
            macServiceNI.engineInit(ref, new byte[16], null, null, 0);
            // Exercises interface/fips/util/mac.c:450
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_12);
            int code = macServiceNI.ni_doFinal(ref, new byte[32], 0);
            Assertions.assertEquals(-1005, code);
        }
        catch (OpenSSLException e)
        {
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        }
        finally
        {
            macServiceNI.dispose(ref);
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void final_evpMacFinal() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        long ref = macServiceNI.allocateMac("HMAC", "SHA-256");
        try
        {
            macServiceNI.engineInit(ref, new byte[16], null, null, 0);
            // Exercises interface/fips/util/mac.c:421
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            macServiceNI.doFinal(ref, new byte[32], 0);
            Assertions.fail();
        }
        catch (OpenSSLException e)
        {
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        }
        finally
        {
            macServiceNI.dispose(ref);
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void final_macLenOverflow() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        long ref = macServiceNI.allocateMac("HMAC", "SHA-256");
        try
        {
            macServiceNI.engineInit(ref, new byte[16], null, null, 0);
            // Exercises interface/fips/util/mac.c:454
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);
            macServiceNI.getMacLength(ref);
            Assertions.fail();
        }
        catch (OverflowException e)
        {
            Assertions.assertEquals("output too long int32", e.getMessage());
        }
        finally
        {
            macServiceNI.dispose(ref);
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void final_outputSizeOverflow() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        long ref = macServiceNI.allocateMac("HMAC", "SHA-256");
        try
        {
            macServiceNI.engineInit(ref, new byte[16], null, null, 0);
            // Exercises interface/fips/ffm/mac_ffm.c:150
            // Exercises interface/fips/jni/mac_jni.c:274
            operationsTestNI.setFlag(Loader.isFFM() ? OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_3
                    : OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_2);
            macServiceNI.doFinal(ref, new byte[32], 0);
            Assertions.fail();
        }
        catch (OverflowException e)
        {
            Assertions.assertEquals("output too long int32", e.getMessage());
        }
        finally
        {
            macServiceNI.dispose(ref);
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void macLengthMeta_fetchMd_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        long ref = macServiceNI.allocateMac("HMAC", "SHA-256");
        try
        {
            // Exercises interface/fips/util/mac.c:481
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);
            int code = macServiceNI.ni_macLengthMeta(ref);
            Assertions.assertEquals(-1012, code);
        }
        finally
        {
            macServiceNI.dispose(ref);
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void macLengthMeta_fetchCipher_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        long ref = macServiceNI.allocateMac("CMAC", "aes-cbc");
        try
        {
            // Exercises interface/fips/util/mac.c:501
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_4);
            int code = macServiceNI.ni_macLengthMeta(ref);
            Assertions.assertEquals(-1013, code);
        }
        finally
        {
            macServiceNI.dispose(ref);
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void macLengthMeta_mdSize_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        long ref = macServiceNI.allocateMac("HMAC", "SHA-256");
        try
        {
            // Exercises interface/fips/util/mac.c:486
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_5);
            int code = macServiceNI.ni_macLengthMeta(ref);
            Assertions.assertEquals(-1014, code);
        }
        finally
        {
            macServiceNI.dispose(ref);
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void macLengthMeta_cipherBlock_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        long ref = macServiceNI.allocateMac("CMAC", "aes-cbc");
        try
        {
            // Exercises interface/fips/util/mac.c:506
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_6);
            int code = macServiceNI.ni_macLengthMeta(ref);
            Assertions.assertEquals(-1015, code);
        }
        finally
        {
            macServiceNI.dispose(ref);
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void gmac_init_branchSkipped_unexpectedState() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");

        long ref = macServiceNI.allocateMac("GMAC", "aes-gcm");
        try
        {
            // OPS_ALTERNATE_4 skips the GMAC init branch; with the CMAC/HMAC/
            // POLY1305 branches not matching the name, init falls through to
            // the final else -> JO_UNEXPECTED_STATE.
            // Exercises interface/fips/util/mac.c:101
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_ALTERNATE_4);
            macServiceNI.engineInit(ref, new byte[16], new byte[12], null, 0);
            Assertions.fail();
        }
        catch (Exception e)
        {
            Assertions.assertEquals("unexpected state", e.getMessage());
        }
        finally
        {
            macServiceNI.dispose(ref);
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void kmac_init_branchSkipped_unexpectedState() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");

        long ref = macServiceNI.allocateMac("KMAC-128", "KMAC-128");
        try
        {
            // OPS_ALTERNATE_5 skips the KMAC init branch; with CMAC/HMAC/
            // POLY1305/GMAC not matching the name, init falls through to the
            // final else -> JO_UNEXPECTED_STATE.
            // Exercises interface/fips/util/mac.c:127
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_ALTERNATE_5);
            macServiceNI.engineInit(ref, new byte[32], null, null, 0);
            Assertions.fail();
        }
        catch (Exception e)
        {
            Assertions.assertEquals("unexpected state", e.getMessage());
        }
        finally
        {
            macServiceNI.dispose(ref);
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void kmac_init_customAccessFailure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        Assumptions.assumeFalse(Loader.isFFM(), "JNI Only");

        long ref = macServiceNI.allocateMac("KMAC-128", "KMAC-128");
        try
        {
            // Exercises interface/fips/jni/mac_jni.c:157
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_6);
            macServiceNI.engineInit(ref, new byte[32], null, new byte[]{1, 2, 3}, 0);
            Assertions.fail();
        }
        catch (IllegalStateException e)
        {
            Assertions.assertEquals("native layer was unable to access customisation string",
                    e.getMessage());
        }
        finally
        {
            macServiceNI.dispose(ref);
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void kmac_macLengthMeta_ctxNewFailure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");

        long ref = macServiceNI.allocateMac("KMAC-128", "KMAC-128");
        try
        {
            // Exercises interface/fips/util/mac.c:536
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_10);
            Assertions.assertEquals(-1019, macServiceNI.ni_macLengthMeta(ref));
        }
        finally
        {
            macServiceNI.dispose(ref);
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void kmac_macLengthMeta_zeroSize() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");

        long ref = macServiceNI.allocateMac("KMAC-128", "KMAC-128");
        try
        {
            // Exercises interface/fips/util/mac.c:541
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_11);
            Assertions.assertEquals(-1020, macServiceNI.ni_macLengthMeta(ref));
        }
        finally
        {
            macServiceNI.dispose(ref);
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void wrongKindDisposeFreesNothing()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        MacCells.wrongKindDisposeFreesNothing(macServiceNI, FIPSNISelector.MDServiceNI, operationsTestNI);
    }

    @Test
    public void unusableErrArrayCreatesNoContext()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        Assumptions.assumeTrue(Loader.isFFM(), "FFM only: JNI aborts at the bridge assert");
        MacCells.unusableErrArrayCreatesNoContext(macServiceNI, operationsTestNI);
    }

    @Test
    public void keyCopiesAreCleansed()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        MacCells.keyCopiesAreCleansed(macServiceNI, operationsTestNI);
    }

    @Test
    public void failedReinitInsideResetDropsEverything()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        // Exercises interface/fips/util/mac.c:152
        MacCells.failedReinitInsideResetDropsEverything(macServiceNI, operationsTestNI,
                () -> operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_INIT_1), -1003);
    }

    @Test
    public void copy_upRefFailure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        // Exercises interface/fips/util/mac.c:254
        MacCells.copyFailureSite(macServiceNI, operationsTestNI,
                () -> operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_8), -1017,
                JostleFIPSProvider.PROVIDER_NAME);
    }

    @Test
    public void copy_dupFailure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        // Exercises interface/fips/util/mac.c:261
        MacCells.copyFailureSite(macServiceNI, operationsTestNI,
                () -> operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_9), -1018,
                JostleFIPSProvider.PROVIDER_NAME);
    }

    @Test
    public void gmac_init_ivAccessFailure()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        Assumptions.assumeFalse(Loader.isFFM(), "JNI Only");
        try
        {
            // Exercises interface/fips/jni/mac_jni.c:152
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_5);
            MacCells.gmacIvAccessFailure(macServiceNI);
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }
}
