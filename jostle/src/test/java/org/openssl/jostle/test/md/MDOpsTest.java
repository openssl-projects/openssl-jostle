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

package org.openssl.jostle.test.md;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.AccessException;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.md.MDServiceNI;
import org.openssl.jostle.test.crypto.TestNISelector;
import org.openssl.jostle.util.ops.OperationsTestNI;

public class MDOpsTest
{
    static
    {
        CryptoServicesRegistrar.isNativeAvailable(); // Trigger Loading
    }

    MDServiceNI mdNI = TestNISelector.getMDNI();
    OperationsTestNI operationsTestNI = TestNISelector.getOperationsTestNI();

    @BeforeEach
    public void beforeEach()
    {
        if (operationsTestNI.opsTestAvailable())
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void allocateDigest_mdFailCreate() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(),"OPS Test support not compiled in");

        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_CREATE_1);
            mdNI.allocateDigest("SHA256", 0);
            Assertions.fail("Expected operation to fail but did not");
        } catch (IllegalStateException e)
        {
            Assertions.assertEquals("md create failed", e.getMessage());
        } finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void allocateDigest_mdFailAccessName() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(),"OPS Test support not compiled in");
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");

        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            mdNI.allocateDigest("SHA256", 0);
            Assertions.fail("Expected operation to fail but did not");
        } catch (IllegalStateException e)
        {
            Assertions.assertEquals("unable to access name", e.getMessage());
        } finally
        {
            operationsTestNI.resetFlags();
        }
    }


    @Test
    public void allocateDigest_mdFailInit() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(),"OPS Test support not compiled in");
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_INIT_1);
            mdNI.allocateDigest("SHA256", 0);
            Assertions.fail("Expected operation to fail but did not");
        } catch (IllegalStateException e)
        {
            Assertions.assertEquals("md init failed", e.getMessage());
        } finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void allocateDigest_mdSetParamFailed() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(),"OPS Test support not compiled in");
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_SET_1);
            mdNI.allocateDigest("SHA256", 256);
            Assertions.fail("Expected operation to fail but did not");
        } catch (IllegalStateException e)
        {
            Assertions.assertEquals("md unable to set param", e.getMessage());
        } finally
        {
            operationsTestNI.resetFlags();
        }
    }


    @Test
    public void updateByte_openSSLErrorOnUpdateCall() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(),"OPS Test support not compiled in");
        long ref = 0;
        try
        {
            ref = mdNI.allocateDigest("SHA256", 0);
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            mdNI.engineUpdate(ref, (byte) 1);
            Assertions.fail("Expected operation to fail but did not");
        } catch (OpenSSLException e)
        {
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        } finally
        {
            if (ref != 0)
            {
                mdNI.dispose(ref);
            }
            operationsTestNI.resetFlags();
        }
    }


    @Test
    public void updateBytes_array_access() throws Exception {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(),"OPS Test support not compiled in");

        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        long ref = mdNI.allocateDigest("SHA256", 0);

        try {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            mdNI.engineUpdate(ref,new byte[10],1,9);
            Assertions.fail("ops");
        } catch (AccessException e) {
            Assertions.assertEquals("unable to access input array", e.getMessage());
        } finally {
            if (ref >0) {
                mdNI.dispose(ref);
            }
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void digest_array_access() throws Exception {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(),"OPS Test support not compiled in");
       Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");

        long ref = mdNI.allocateDigest("SHA256", 0);

        try {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            mdNI.digest(ref,new byte[32],0,32);
            Assertions.fail("ops");
        } catch (AccessException e) {
            Assertions.assertEquals("unable to access output array", e.getMessage());
        } finally {
            if (ref >0) {
                mdNI.dispose(ref);
            }
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void digest_final_failed() throws Exception {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(),"OPS Test support not compiled in");

        long ref = mdNI.allocateDigest("SHA256", 0);

        try {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            mdNI.digest(ref,new byte[32],0,32);
            Assertions.fail("ops");
        } catch (OpenSSLException e) {
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        } finally {
            if (ref >0) {
                mdNI.dispose(ref);
            }
        }
    }

    @Test
    public void digest_final_failed_xof() throws Exception {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(),"OPS Test support not compiled in");
        long ref = mdNI.allocateDigest("SHAKE-128", 0);

        try {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            mdNI.digest(ref,new byte[32],0,32);
            Assertions.fail("ops");
        } catch (OpenSSLException e) {
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        } finally {
            if (ref >0) {
                mdNI.dispose(ref);
            }
        }
    }

    @Test
    public void digest_final_intOverflow() throws Exception {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(),"OPS Test support not compiled in");
        long ref = mdNI.allocateDigest("SHA256", 0);

        try {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);
            mdNI.digest(ref,new byte[32],0,32);
            Assertions.fail("ops");
        } catch (IllegalStateException e) {
            Assertions.assertEquals("digest len overflow", e.getMessage());
        } finally {
            if (ref >0) {
                mdNI.dispose(ref);
            }
        }
    }

}
