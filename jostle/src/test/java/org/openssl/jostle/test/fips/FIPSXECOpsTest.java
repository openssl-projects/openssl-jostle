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

package org.openssl.jostle.test.fips;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.provider.xec.XECServiceNI;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.util.ops.OperationsTestNI;

/**
 * Every XDH key-generation fault site in the FIPS tree, through the FIPS interface library. The site cells run where
 * the module serves the XDH key types; the served-iff cell runs on every module and build.
 */
public class FIPSXECOpsTest
{
    private static final int JO_OPENSSL_ERROR = ErrorCode.JO_OPENSSL_ERROR.getCode();
    private static final int JO_UNABLE_TO_ACCESS_NAME = ErrorCode.JO_UNABLE_TO_ACCESS_NAME.getCode();

    private final XECServiceNI xec = FIPSNISelector.XECServiceNI;
    private final OperationsTestNI ops = FIPSNISelector.OperationsTestNI;

    @BeforeAll
    public static void beforeAll()
    {
        FIPSTestUtil.assumeFipsProvider();
    }

    @BeforeEach
    public void beforeEach()
    {
        if (ops.opsTestAvailable())
        {
            ops.resetFlags();
        }
    }

    /** The code a fault site with this offset returns. */
    private static int errorAt(int offset)
    {
        return JO_OPENSSL_ERROR - offset;
    }

    private static void assumeXdhServed()
    {
        Assumptions.assumeTrue(FIPSTestUtil.moduleServesKeyMgmt("X25519"), "the module serves no XDH key type");
    }

    /** Runs on every module and build: the XDH registration equals the module's answer. */
    @Test
    public void xdhServedIffModuleImplementsIt()
    {
        boolean registered = TestUtil.addFipsProvider().getService("KeyPairGenerator", "X25519") != null;
        Assertions.assertEquals(FIPSTestUtil.moduleServesKeyMgmt("X25519"), registered,
                "the XDH registration disagrees with the loaded module");
    }

    @Test
    public void fips_ctxNewFromName()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        assumeXdhServed();
        try
        {
            // Exercises interface/fips/util/xec.c:44
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            int[] err = new int[1];
            Assertions.assertEquals(0L, xec.ni_generateKeyPair("X25519", err, TestUtil.RNDSrc));
            Assertions.assertEquals(errorAt(3300), err[0]);
        }
        finally
        {
            ops.resetFlags();
        }
    }

    @Test
    public void fips_keygenInit()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        assumeXdhServed();
        try
        {
            // Exercises interface/fips/util/xec.c:51
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            int[] err = new int[1];
            Assertions.assertEquals(0L, xec.ni_generateKeyPair("X25519", err, TestUtil.RNDSrc));
            Assertions.assertEquals(errorAt(3301), err[0]);
        }
        finally
        {
            ops.resetFlags();
        }
    }

    @Test
    public void fips_keygen()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        assumeXdhServed();
        try
        {
            // Exercises interface/fips/util/xec.c:56
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);
            int[] err = new int[1];
            Assertions.assertEquals(0L, xec.ni_generateKeyPair("X25519", err, TestUtil.RNDSrc));
            Assertions.assertEquals(errorAt(3302), err[0]);
        }
        finally
        {
            ops.resetFlags();
        }
    }

    @Test
    public void fips_nullKey()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        assumeXdhServed();
        try
        {
            // Exercises interface/fips/util/xec.c:61
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_4);
            int[] err = new int[1];
            Assertions.assertEquals(0L, xec.ni_generateKeyPair("X25519", err, TestUtil.RNDSrc));
            Assertions.assertEquals(errorAt(3303), err[0]);
        }
        finally
        {
            ops.resetFlags();
        }
    }

    @Test
    public void fips_jni_accessName()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        assumeXdhServed();
        Assumptions.assumeFalse(Loader.isFFM(), "JNI only");
        try
        {
            // Exercises interface/fips/jni/xec_ni_jni.c:43
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            int[] err = new int[1];
            Assertions.assertEquals(0L, xec.ni_generateKeyPair("X25519", err, TestUtil.RNDSrc));
            Assertions.assertEquals(JO_UNABLE_TO_ACCESS_NAME, err[0]);
        }
        finally
        {
            ops.resetFlags();
        }
    }
}
