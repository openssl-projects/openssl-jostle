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
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.jcajce.provider.md.MDServiceNI;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.util.ops.OperationsTestNI;

import java.security.MessageDigest;

/**
 * Operations-test fault injection at the FIPS MessageDigest NI surface. The
 * FIPS glue (interface/fips/jni/md_fips_jni.c) is the base md_jni.c re-included, and
 * the fault sites live in the shared interface/fips/util/md.c, so the {@code //
 * Exercises interface/fips/util/md.c:NNN} annotations point at the same lines as the
 * base {@code MDOpsTest}. This pins that those sites fire identically when
 * driven through the FIPS interface library. Mirrors {@code MDOpsTest}.
 *
 * <p>Requires a JOSTLE_OPS_TEST build of the FIPS library: gated on
 * {@code TEST_FIPS_LIB} (whole class skips when unset) and, per test, on
 * {@code opsTestAvailable()} (skips against a shipped, non-instrumented FIPS
 * library). Flags are set on the FIPS library's own OperationsTestNI, whose
 * flag state is independent of the base library's.
 */
public class FIPSMDOpsTest
{
    @BeforeAll
    public static void beforeAll()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        TestUtil.addFipsProvider();
    }

    private final MDServiceNI mdNI = FIPSNISelector.MDServiceNI;
    private final OperationsTestNI operationsTestNI = FIPSNISelector.OperationsTestNI;

    @BeforeEach
    public void beforeEach()
    {
        if (operationsTestNI.opsTestAvailable())
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void allocateDigest_mdFailCreate()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        try
        {
            // Exercises interface/fips/util/md.c:44
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_CREATE_1);
            mdNI.allocateDigest("SHA256", 0);
            Assertions.fail("Expected operation to fail but did not");
        }
        catch (IllegalStateException e)
        {
            Assertions.assertEquals("md create failed", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void allocateDigest_mdFailAccessName()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        try
        {
            // Exercises interface/fips/jni/md_jni.c:47
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            mdNI.allocateDigest("SHA256", 0);
            Assertions.fail("Expected operation to fail but did not");
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
    public void allocateDigest_mdFailInit()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        try
        {
            // Exercises interface/fips/util/md.c:56
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_INIT_1);
            mdNI.allocateDigest("SHA256", 0);
            Assertions.fail("Expected operation to fail but did not");
        }
        catch (IllegalStateException e)
        {
            Assertions.assertEquals("md init failed", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void updateByte_openSSLErrorOnUpdateCall()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        long ref = 0;
        try
        {
            ref = mdNI.allocateDigest("SHA256", 0);
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            mdNI.engineUpdate(ref, (byte) 1);
            Assertions.fail("Expected operation to fail but did not");
        }
        catch (OpenSSLException e)
        {
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        }
        finally
        {
            if (ref != 0)
            {
                mdNI.dispose(ref);
            }
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void reset_openSSLErrorOnDigestInit()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        long ref = 0;
        try
        {
            ref = mdNI.allocateDigest("SHA256", 0);
            // Exercises interface/fips/util/md.c:203
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);
            mdNI.reset(ref);
            Assertions.fail("Expected operation to fail but did not");
        }
        catch (OpenSSLException e)
        {
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        }
        finally
        {
            if (ref != 0)
            {
                mdNI.dispose(ref);
            }
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void updateBytes_array_access()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        long ref = mdNI.allocateDigest("SHA256", 0);
        try
        {
            // Exercises interface/fips/jni/md_jni.c:146
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            mdNI.engineUpdate(ref, new byte[10], 1, 9);
            Assertions.fail("ops");
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access input array", e.getMessage());
        }
        finally
        {
            if (ref > 0)
            {
                mdNI.dispose(ref);
            }
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void digest_array_access()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        long ref = mdNI.allocateDigest("SHA256", 0);
        try
        {
            // Exercises interface/fips/jni/md_jni.c:253
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            mdNI.digest(ref, new byte[32], 0, 32);
            Assertions.fail("ops");
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access output array", e.getMessage());
        }
        finally
        {
            if (ref > 0)
            {
                mdNI.dispose(ref);
            }
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void digest_final_failed()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        long ref = mdNI.allocateDigest("SHA256", 0);
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            mdNI.digest(ref, new byte[32], 0, 32);
            Assertions.fail("ops");
        }
        catch (OpenSSLException e)
        {
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        }
        finally
        {
            if (ref > 0)
            {
                mdNI.dispose(ref);
            }
        }
    }

    @Test
    public void digest_final_failed_xof()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        long ref = mdNI.allocateDigest("SHAKE-128", 32);
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            mdNI.digest(ref, new byte[32], 0, 32);
            Assertions.fail("ops");
        }
        catch (OpenSSLException e)
        {
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        }
        finally
        {
            if (ref > 0)
            {
                mdNI.dispose(ref);
            }
        }
    }

    @Test
    public void digest_final_intOverflow()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        long ref = mdNI.allocateDigest("SHA256", 0);
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);
            mdNI.digest(ref, new byte[32], 0, 32);
            Assertions.fail("ops");
        }
        catch (IllegalStateException e)
        {
            Assertions.assertEquals("digest len overflow", e.getMessage());
        }
        finally
        {
            if (ref > 0)
            {
                mdNI.dispose(ref);
            }
        }
    }

    @Test
    public void copyDigest_failCreate()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        long ref = mdNI.allocateDigest("SHA256", 0);
        try
        {
            // Exercises interface/fips/util/md.c:101
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_CREATE_2);
            mdNI.copyDigest(ref);
            Assertions.fail("Expected operation to fail but did not");
        }
        catch (IllegalStateException e)
        {
            Assertions.assertEquals("md create failed", e.getMessage());
        }
        finally
        {
            if (ref > 0)
            {
                mdNI.dispose(ref);
            }
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void copyDigest_copyFailed()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        long ref = mdNI.allocateDigest("SHA256", 0);
        try
        {
            // Exercises interface/fips/util/md.c:108
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_11);
            mdNI.copyDigest(ref);
            Assertions.fail("Expected operation to fail but did not");
        }
        catch (IllegalStateException e)
        {
            Assertions.assertEquals("md copy failed", e.getMessage());
        }
        finally
        {
            if (ref > 0)
            {
                mdNI.dispose(ref);
            }
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void copyDigest_upRefFailed()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        long ref = mdNI.allocateDigest("SHA256", 0);
        try
        {
            // Exercises interface/fips/util/md.c:116
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_12);
            mdNI.copyDigest(ref);
            Assertions.fail("Expected operation to fail but did not");
        }
        catch (IllegalStateException e)
        {
            Assertions.assertEquals("md copy failed", e.getMessage());
        }
        finally
        {
            if (ref > 0)
            {
                mdNI.dispose(ref);
            }
            operationsTestNI.resetFlags();
        }
    }

    /**
     * At the JCE {@code MessageDigest.clone()} boundary a native copy failure
     * must surface as {@link CloneNotSupportedException}, not the raw
     * {@link IllegalStateException} the NI throws - with the native failure as
     * the cause. Driven through the JSLFIPS provider so the FIPS MD SPI (bound
     * to the FIPS NI) is what fails.
     */
    @Test
    public void clone_copyFailed_surfacesAsCloneNotSupported() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        MessageDigest md = MessageDigest.getInstance("SHA-256", JostleFIPSProvider.PROVIDER_NAME);
        md.update((byte) 0x01);
        try
        {
            // Exercises interface/fips/util/md.c:108
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_11);
            md.clone();
            Assertions.fail("Expected clone() to fail but did not");
        }
        catch (CloneNotSupportedException e)
        {
            Assertions.assertEquals("unable to clone digest", e.getMessage());
            Assertions.assertTrue(e.getCause() instanceof IllegalStateException,
                    "native copy failure should be the cause");
            Assertions.assertEquals("md copy failed", e.getCause().getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }
}
