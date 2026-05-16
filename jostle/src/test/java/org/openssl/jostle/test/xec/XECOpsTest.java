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
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.OpenSSL;
import org.openssl.jostle.jcajce.provider.ec.ECServiceNI;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.test.crypto.TestNISelector;
import org.openssl.jostle.util.ops.OperationsTestNI;

import java.security.Security;

/**
 * Fault-injection tests for {@code interface/util/xec.c}.
 *
 * <p>Each test sets exactly one {@code OPS_*} flag, drives the X25519
 * keygen path through the EC NI bridge (which dispatches to
 * {@code xec_generate_key} for the Montgomery curves), and asserts
 * the resulting integer error code matches
 * {@code JO_OPENSSL_ERROR + (-offset)}.
 *
 * <p>All tests are guarded by {@link OperationsTestNI#opsTestAvailable()}
 * so they no-op on a release native build.
 *
 * <h2>Target map (mirror of the {@code OPS_OFFSET_*} sites in
 * {@code interface/util/xec.c}; offset range 4000-4003)</h2>
 *
 * <pre>
 *   Offset  xec.c line  Function           Trigger
 *   ----------------------------------------------------------------------
 *   4000    line 89     xec_generate_key   EVP_PKEY_CTX_new_from_name == NULL
 *   4001    line 94     xec_generate_key   EVP_PKEY_keygen_init failed
 *   4002    line 103    xec_generate_key   EVP_PKEY_keygen failed
 *   4003    line 108    xec_generate_key   spec-&gt;key == NULL after keygen
 * </pre>
 *
 * <p>Note: the 4000 numeric block is shared with {@code kdf.c::x963kdf}
 * but with disjoint OPS flags ({@code OPS_OPENSSL_ERROR_7..._9} there
 * vs. {@code _1..._4} here) — CLAUDE.md explicitly permits cross-file
 * offset reuse.
 */
public class XECOpsTest
{
    private static final int JO_OPENSSL_ERROR = -2;

    private final ECServiceNI ec = TestNISelector.getECNi();
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


    /**
     * Target: {@code interface/util/xec.c:89} (offset 4000) —
     * {@code EVP_PKEY_CTX_new_from_name == NULL} inside
     * {@code xec_generate_key} (defined at {@code xec.c:75}).
     */
    @Test
    public void xec_generateKeyPair_ctxNewFromName_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);

        int[] err = new int[1];
        long ref = ec.ni_generateKeyPair("X25519", err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(4000), err[0]);
    }

    /**
     * Target: {@code interface/util/xec.c:94} (offset 4001) —
     * {@code EVP_PKEY_keygen_init} failure branch inside
     * {@code xec_generate_key} (defined at {@code xec.c:75}).
     */
    @Test
    public void xec_generateKeyPair_keygenInit_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);

        int[] err = new int[1];
        long ref = ec.ni_generateKeyPair("X25519", err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(4001), err[0]);
    }

    /**
     * Target: {@code interface/util/xec.c:103} (offset 4002) —
     * {@code EVP_PKEY_keygen} failure branch inside
     * {@code xec_generate_key} (defined at {@code xec.c:75}).
     */
    @Test
    public void xec_generateKeyPair_keygen_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);

        int[] err = new int[1];
        long ref = ec.ni_generateKeyPair("X25519", err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(4002), err[0]);
    }

    /**
     * Target: {@code interface/util/xec.c:108} (offset 4003) —
     * post-keygen {@code spec->key == NULL} sanity check inside
     * {@code xec_generate_key} (defined at {@code xec.c:75}).
     */
    @Test
    public void xec_generateKeyPair_specKeyNull_failure()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_4);

        int[] err = new int[1];
        long ref = ec.ni_generateKeyPair("X25519", err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(4003), err[0]);
    }


    /**
     * Bonus: also drive a quick X448 keygen through the same code path
     * to confirm the dispatch logic in {@code ec_generate_key} routes
     * both Montgomery curves to {@code xec_generate_key}. We use
     * offset 4000 ({@code OPS_OPENSSL_ERROR_1}) since the test target
     * is the SAME C site whichever Montgomery curve drives it.
     */
    @Test
    public void xec_generateKeyPair_x448_alsoHitsCtxNewFromName()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        OpenSSL.getOpenSSLErrors();
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);

        int[] err = new int[1];
        long ref = ec.ni_generateKeyPair("X448", err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(errorAt(4000), err[0]);
    }
}
