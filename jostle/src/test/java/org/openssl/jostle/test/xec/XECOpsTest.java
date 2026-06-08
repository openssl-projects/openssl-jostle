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

package org.openssl.jostle.test.xec;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.OpenSSL;
import org.openssl.jostle.jcajce.provider.xec.XECServiceNI;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.test.crypto.TestNISelector;
import org.openssl.jostle.util.ops.OperationsTestNI;

import java.security.Security;

/**
 * Fault-injection (OPS) tests for the XEC key-generation native code. Each
 * test forces one fallible OpenSSL / JVM call inside
 * {@code xec_generate_key} (interface/util/xec.c) or the JNI bridge
 * (interface/jni/xec_ni_jni.c) to fail, and asserts the exact error code the
 * bridge returns in {@code err[0]}.
 *
 * <p>Requires a native build with {@code JOSTLE_OPS_TEST=1}; absent that, the
 * tests skip via {@link Assumptions#assumeTrue}. The kex (derive) path is
 * shared with EC and its OPS sites are covered by {@code ECOpsTest}; XEC adds
 * only key generation.
 *
 * <p>{@code xec_generate_key} uses the 3300 OPS offset block; the expected
 * code for a site at {@code offset} is {@code JO_OPENSSL_ERROR - offset}.
 */
public class XECOpsTest
{
    private static final int JO_OPENSSL_ERROR = -2;
    private static final int JO_UNABLE_TO_ACCESS_NAME = -89;

    private final XECServiceNI xec = TestNISelector.getXECNi();
    private final OperationsTestNI ops = TestNISelector.getOperationsTestNI();


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
        if (ops.opsTestAvailable())
        {
            ops.resetFlags();
        }
    }

    /** Expected code when a fault site at {@code offset} fires. */
    private static int errorAt(int offset)
    {
        return JO_OPENSSL_ERROR - offset;
    }


    // -----------------------------------------------------------------
    // xec_generate_key — OpenSSL failure sites (offsets 3300-3303)
    // -----------------------------------------------------------------

    /**
     * Fault-injects the {@code EVP_PKEY_CTX_new_from_name == NULL} branch
     * inside {@code xec_generate_key} (offset 3300).
     */
    @Test
    public void xec_generateKeyPair_ctxNewFromName_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        // Exercises interface/util/xec.c:44
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);

        int[] err = new int[1];
        long ref = xec.ni_generateKeyPair("X25519", err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(3300), err[0]);
    }

    /**
     * Fault-injects the {@code EVP_PKEY_keygen_init} failure branch inside
     * {@code xec_generate_key} (offset 3301).
     */
    @Test
    public void xec_generateKeyPair_keygenInit_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        // Exercises interface/util/xec.c:51
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);

        int[] err = new int[1];
        long ref = xec.ni_generateKeyPair("X25519", err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(3301), err[0]);
    }

    /**
     * Fault-injects the {@code EVP_PKEY_keygen} failure branch inside
     * {@code xec_generate_key} (offset 3302).
     */
    @Test
    public void xec_generateKeyPair_keygen_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        // Exercises interface/util/xec.c:56
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);

        int[] err = new int[1];
        long ref = xec.ni_generateKeyPair("X25519", err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(3302), err[0]);
    }

    /**
     * Fault-injects the post-keygen {@code spec->key == NULL} sanity check
     * inside {@code xec_generate_key} (offset 3303).
     */
    @Test
    public void xec_generateKeyPair_specKeyNull_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        // Exercises interface/util/xec.c:61
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_4);

        int[] err = new int[1];
        long ref = xec.ni_generateKeyPair("X25519", err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(3303), err[0]);
    }


    // -----------------------------------------------------------------
    // JNI access fault (OPS_FAILED_ACCESS_*) — JNI-only
    //
    // Fault-injects GetStringUTFChars failure on the key-type name at the
    // JNI bridge. FFI takes a raw pointer (no JVM access path), so this is
    // guarded by Loader.isFFI().
    // -----------------------------------------------------------------

    /**
     * Fault-injects the {@code GetStringUTFChars(name)} failure inside
     * {@code ni_generateKeyPair} (JNI bridge).
     */
    @Test
    public void xec_generateKeyPair_accessName_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        try
        {
            // Exercises interface/jni/xec_ni_jni.c:42
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            int[] err = new int[1];
            long ref = xec.ni_generateKeyPair("X25519", err, TestUtil.RNDSrc);
            Assertions.assertEquals(0L, ref);
            Assertions.assertEquals(JO_UNABLE_TO_ACCESS_NAME, err[0]);
        }
        finally
        {
            ops.resetFlags();
        }
    }
}
