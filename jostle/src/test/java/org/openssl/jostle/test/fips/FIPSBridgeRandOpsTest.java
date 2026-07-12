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
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.provider.rand.RandServiceNI;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.util.ops.OperationsTestNI;

/**
 * Operations-test fault injection at the FIPS RAND NI surface, restricted to the
 * <b>context path</b> ({@code rand_ctx_*} in interface/fips/util/rand.c, reached
 * via {@code FIPSNISelector.RandServiceNI.ni_createContext /
 * ni_contextRandomBytes / ni_contextReseed}).
 *
 * <p>This is the context-path subset of the base {@code BridgeRandOpsTest}. The
 * FIPS lib ctx installs <b>no</b> {@code java_rand_bridge} up-call handler (the
 * FIPS module drives its own DRBG from the module lib ctx), so the up-call
 * fault-injection sites the base test exercises (thread-attach, create-bytearray,
 * short-output, rand-up-call-null, out_len/strength overflow) simply do not exist
 * in the FIPS tree. Only the DRBG-context OpenSSL-error / state-check sites and
 * the JNI byte-array access-failure sites apply.
 *
 * <p>The C sites live in interface/fips/util/rand.c and interface/fips/jni/rand_jni.c.
 * rand_jni.c is byte-identical to the nonfips copy; rand.c has diverged (the FIPS
 * copy adds {@code rand_init_fips}), so the util-path line numbers differ from the
 * base test — the {@code // Exercises} comments below name the actual FIPS-tree
 * if-lines. The negative int return codes are unchanged (the OPS offsets are part
 * of the cross-tree contract).
 *
 * <p>Requires a JOSTLE_OPS_TEST build of the FIPS library: gated on
 * {@code TEST_FIPS_LIB} (whole class skips when unset) and, per test, on
 * {@code opsTestAvailable()} (skips against a shipped, non-instrumented FIPS
 * library). The FAILED_ACCESS tests are JNI-only (the FFI bridge takes raw
 * pointers). Flags are set on the FIPS library's own OperationsTestNI, whose flag
 * state is independent of the base library's.
 */
public class FIPSBridgeRandOpsTest
{
    private static final int JO_OPENSSL_ERROR = -2;
    private static final int JO_FAILED_ACCESS_INPUT = -22;
    private static final int JO_FAILED_ACCESS_OUTPUT = -23;
    private static final int JO_UNEXPECTED_STATE = -40;
    private static final int JO_RAND_RESEED = -100;

    private final RandServiceNI randServiceNI = FIPSNISelector.RandServiceNI;
    private final OperationsTestNI operationsTestNI = FIPSNISelector.OperationsTestNI;

    @BeforeAll
    public static void beforeAll()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        TestUtil.addFipsProvider();
    }

    @BeforeEach
    public void beforeEach()
    {
        if (operationsTestNI.opsTestAvailable())
        {
            operationsTestNI.resetFlags();
        }
    }

    //
    // Context path (rand_ctx_*). The FIPS SecureRandom service runs through these
    // functions exclusively; each fallible OpenSSL call and state check gets a
    // fault-injection site.
    //

    @Test
    public void createContextFetchFails()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        int[] err = new int[1];
        // Exercises interface/fips/util/rand.c:155
        operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
        long ref = randServiceNI.ni_createContext("CTR-DRBG", "AES-256-CTR", true, 0, false, null, err);

        Assertions.assertEquals(0, ref);
        Assertions.assertEquals(JO_OPENSSL_ERROR - 3030, err[0]);
    }

    @Test
    public void createContextGetPrivateFails()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        int[] err = new int[1];
        // Exercises interface/fips/util/rand.c:165
        operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_6);
        long ref = randServiceNI.ni_createContext("CTR-DRBG", "AES-256-CTR", true, 0, false, null, err);

        Assertions.assertEquals(0, ref);
        Assertions.assertEquals(JO_OPENSSL_ERROR - 3031, err[0]);
    }

    @Test
    public void createContextCtxNewFails()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        int[] err = new int[1];
        // Exercises interface/fips/util/rand.c:176
        operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_9);
        long ref = randServiceNI.ni_createContext("CTR-DRBG", "AES-256-CTR", true, 0, false, null, err);

        Assertions.assertEquals(0, ref);
        Assertions.assertEquals(JO_OPENSSL_ERROR - 3032, err[0]);
    }

    @Test
    public void createContextEnableLockingFails()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        int[] err = new int[1];
        // Exercises interface/fips/util/rand.c:192
        operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_11);
        long ref = randServiceNI.ni_createContext("CTR-DRBG", "AES-256-CTR", true, 0, false, null, err);

        Assertions.assertEquals(0, ref);
        Assertions.assertEquals(JO_OPENSSL_ERROR - 3034, err[0]);
    }

    @Test
    public void createContextInstantiateFails()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        int[] err = new int[1];
        // Exercises interface/fips/util/rand.c:223
        operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_10);
        long ref = randServiceNI.ni_createContext("CTR-DRBG", "AES-256-CTR", true, 0, false, null, err);

        Assertions.assertEquals(0, ref);
        Assertions.assertEquals(JO_OPENSSL_ERROR - 3033, err[0]);
    }

    @Test
    public void contextRandomBytesGenerateFails()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long ref = randServiceNI.createContext("CTR-DRBG", "AES-256-CTR", true, 0, false, null);
        try
        {
            // Exercises interface/fips/util/rand.c:295
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            int code = randServiceNI.ni_contextRandomBytes(ref, new byte[1], 1, 0, false, null);

            Assertions.assertEquals(JO_OPENSSL_ERROR - 3040, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            randServiceNI.disposeContext(ref);
        }
    }

    @Test
    public void contextRandomBytesUnexpectedStateFails()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long ref = randServiceNI.createContext("CTR-DRBG", "AES-256-CTR", true, 0, false, null);
        try
        {
            // Exercises interface/fips/util/rand.c:278
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_SET_2);
            int code = randServiceNI.ni_contextRandomBytes(ref, new byte[1], 1, 0, false, null);

            Assertions.assertEquals(JO_UNEXPECTED_STATE, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            randServiceNI.disposeContext(ref);
        }
    }

    @Test
    public void contextReseedInstantiateFails()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long ref = randServiceNI.createContext("CTR-DRBG", "AES-256-CTR", true, 0, false, null);
        try
        {
            // Exercises interface/fips/util/rand.c:325
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_INIT_1);
            // Exercises interface/fips/util/rand.c:326
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            int code = randServiceNI.ni_contextReseed(ref, 0, false, null);

            Assertions.assertEquals(JO_OPENSSL_ERROR - 3050, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            randServiceNI.disposeContext(ref);
        }
    }

    @Test
    public void contextReseedReseedFails()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long ref = randServiceNI.createContext("CTR-DRBG", "AES-256-CTR", true, 0, false, null);
        try
        {
            // Exercises interface/fips/util/rand.c:336
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_6);
            int code = randServiceNI.ni_contextReseed(ref, 0, false, null);

            Assertions.assertEquals(JO_RAND_RESEED - 3051, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            randServiceNI.disposeContext(ref);
        }
    }

    @Test
    public void contextReseedUnexpectedStateFails()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long ref = randServiceNI.createContext("CTR-DRBG", "AES-256-CTR", true, 0, false, null);
        try
        {
            // Exercises interface/fips/util/rand.c:322
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_SET_1);
            int code = randServiceNI.ni_contextReseed(ref, 0, false, null);

            Assertions.assertEquals(JO_UNEXPECTED_STATE, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            randServiceNI.disposeContext(ref);
        }
    }

    //
    // JNI byte-array access-failure paths (load_bytearray_ctx). JNI-only — the
    // FFI bridge receives raw pointers and has no OPS_FAILED_ACCESS instrumentation.
    // interface/fips/jni/rand_jni.c is byte-identical to the nonfips copy, so the
    // line numbers match the base test.
    //

    @Test
    public void createContextPersonalizationAccessFails()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI(), "JNI only");

        int[] err = new int[1];
        // Exercises interface/fips/jni/rand_jni.c:66
        operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
        long ref = randServiceNI.ni_createContext("CTR-DRBG", "AES-256-CTR", true, 0, false, new byte[1], err);

        Assertions.assertEquals(0, ref);
        Assertions.assertEquals(JO_FAILED_ACCESS_INPUT, err[0]);
    }

    @Test
    public void contextRandomBytesOutputAccessFails()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI(), "JNI only");

        long ref = randServiceNI.createContext("CTR-DRBG", "AES-256-CTR", true, 0, false, null);
        try
        {
            // Exercises interface/fips/jni/rand_jni.c:144
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            int code = randServiceNI.ni_contextRandomBytes(ref, new byte[1], 1, 0, false, null);

            Assertions.assertEquals(JO_FAILED_ACCESS_OUTPUT, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            randServiceNI.disposeContext(ref);
        }
    }

    @Test
    public void contextRandomBytesAdditionalInputAccessFails()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI(), "JNI only");

        long ref = randServiceNI.createContext("CTR-DRBG", "AES-256-CTR", true, 0, false, null);
        try
        {
            // Exercises interface/fips/jni/rand_jni.c:150
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_2);
            int code = randServiceNI.ni_contextRandomBytes(ref, new byte[1], 1, 0, false, new byte[1]);

            Assertions.assertEquals(JO_FAILED_ACCESS_INPUT, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            randServiceNI.disposeContext(ref);
        }
    }

    @Test
    public void contextReseedAdditionalInputAccessFails()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI(), "JNI only");

        long ref = randServiceNI.createContext("CTR-DRBG", "AES-256-CTR", true, 0, false, null);
        try
        {
            // Exercises interface/fips/jni/rand_jni.c:198
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            int code = randServiceNI.ni_contextReseed(ref, 0, false, new byte[1]);

            Assertions.assertEquals(JO_FAILED_ACCESS_INPUT, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            randServiceNI.disposeContext(ref);
        }
    }
}
