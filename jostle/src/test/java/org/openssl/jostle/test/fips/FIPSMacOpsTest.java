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
import org.openssl.jostle.jcajce.provider.mac.MacServiceNI;
import org.openssl.jostle.test.TestUtil;
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
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
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
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
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
            // Exercises interface/fips/util/mac.c:110
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            ref = macServiceNI.allocateMac("HMAC", "SHA-256");
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
            // Exercises interface/fips/util/mac.c:227
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
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
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        long ref = macServiceNI.allocateMac("HMAC", "SHA-256");
        try
        {
            // Exercises interface/fips/jni/mac_jni.c:98
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
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
            // Exercises interface/fips/util/mac.c:187
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
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
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        long ref = macServiceNI.allocateMac("HMAC", "SHA-256");
        try
        {
            macServiceNI.engineInit(ref, new byte[16], null, null, 0);
            // Exercises interface/fips/jni/mac_jni.c:166
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
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
            // Exercises interface/fips/util/mac.c:448
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
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        long ref = macServiceNI.allocateMac("HMAC", "SHA-256");
        try
        {
            macServiceNI.engineInit(ref, new byte[16], null, null, 0);
            // Exercises interface/fips/jni/mac_jni.c:219
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
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
            // Exercises interface/fips/util/mac.c:487
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
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
            // Exercises interface/fips/util/mac.c:210
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
            // Exercises interface/fips/util/mac.c:234
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
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_2);
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
            // Exercises interface/fips/util/mac.c:518
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
            // Exercises interface/fips/util/mac.c:539
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
            // Exercises interface/fips/util/mac.c:523
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
            // Exercises interface/fips/util/mac.c:544
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
            // Exercises interface/fips/util/mac.c:81
            // OPS_ALTERNATE_4 skips the GMAC init branch; with the CMAC/HMAC/
            // POLY1305 branches not matching the name, init falls through to
            // the final else -> JO_UNEXPECTED_STATE.
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
            // Exercises interface/fips/util/mac.c:148
            // OPS_ALTERNATE_5 skips the KMAC init branch; with CMAC/HMAC/
            // POLY1305/GMAC not matching the name, init falls through to the
            // final else -> JO_UNEXPECTED_STATE.
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
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");

        long ref = macServiceNI.allocateMac("KMAC-128", "KMAC-128");
        try
        {
            // Exercises interface/fips/jni/mac_jni.c:166
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
            // Exercises interface/fips/util/mac.c:587
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
            // Exercises interface/fips/util/mac.c:592
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_11);
            Assertions.assertEquals(-1020, macServiceNI.ni_macLengthMeta(ref));
        }
        finally
        {
            macServiceNI.dispose(ref);
            operationsTestNI.resetFlags();
        }
    }
}
