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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.provider.mlxkem.MLXKEMServiceNI;
import org.openssl.jostle.jcajce.spec.MLXKEMParameterSpec;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.rand.RandSource;
import org.openssl.jostle.test.TestUtil;

/**
 * Input validation at the hybrid KEM NI surface of the FIPS interface library
 * ({@link FIPSNISelector#MLXKEMServiceNI}), mirroring the base
 * {@code MLXKEMLimitTest}.
 *
 * <p>The FIPS glue is the base bridge re-included under renamed symbols, so
 * the checks are identical by construction — this pins that they survived into
 * the other library with the same codes and the same messages, which is the
 * only thing that can catch a wrapper that dropped an entry point or a tree
 * that drifted.
 *
 * <p><b>Every test here rejects at the BRIDGE</b>, before any module call, so
 * none depends on the loaded module serving a hybrid group. That matters: 3.1.2
 * serves none, and a limit test gated on the registered set would then cover
 * nothing at all on the validated module. The one test that does need a real
 * key says so and skips.
 *
 * <p>Runs under the {@code integrationTest*} tasks; gated on
 * {@code TEST_FIPS_LIB}.
 */
public class FIPSMLXKEMLimitTest
{
    private static final RandSource RND = TestUtil.RNDSrc;

    private final MLXKEMServiceNI ni = FIPSNISelector.MLXKEMServiceNI;
    private final SpecNI specNI = FIPSNISelector.SpecNI;

    private static final int KS_TYPE = MLXKEMParameterSpec.x25519_mlkem768.getKeyType().getKsType();

    @BeforeAll
    public static void beforeAll()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        TestUtil.addFipsProvider();
    }

    @Test
    public void nullKeySpecHandle_rejectedTypedAtEveryEntryPoint()
    {
        assertTyped(IllegalArgumentException.class, "key spec is null",
                () -> ni.getPublicKey(0, null));
        assertTyped(IllegalArgumentException.class, "key spec is null",
                () -> ni.getPublicKey(0, new byte[16]));
        assertTyped(IllegalArgumentException.class, "key spec is null",
                () -> ni.getPrivateKey(0, null));
        assertTyped(IllegalArgumentException.class, "key spec is null",
                () -> ni.getPrivateKey(0, new byte[16]));
        assertTyped(IllegalArgumentException.class, "key spec is null",
                () -> ni.decode_publicKey(0, KS_TYPE, new byte[16], 0, 16));
        assertTyped(IllegalArgumentException.class, "key spec is null",
                () -> ni.decode_privateKey(0, KS_TYPE, new byte[16], 0, 16));
    }

    @Test
    public void nullRandSource_rejectedTyped()
    {
        assertTyped(IllegalArgumentException.class, "supplied random source was null",
                () -> ni.generateKeyPair(KS_TYPE, null));
    }

    @Test
    public void wrongKeyType_rejectedTyped()
    {
        int mlkem768 = OSSLKeyType.ML_KEM_768.getKsType();
        assertTyped(IllegalArgumentException.class, "invalid key type for a hybrid ML-KEM",
                () -> ni.generateKeyPair(mlkem768, RND));

        long spec = specNI.allocate();
        try
        {
            assertTyped(IllegalArgumentException.class, "invalid key type for a hybrid ML-KEM",
                    () -> ni.decode_publicKey(spec, mlkem768, new byte[16], 0, 16));
            assertTyped(IllegalArgumentException.class, "invalid key type for a hybrid ML-KEM",
                    () -> ni.decode_privateKey(spec, mlkem768, new byte[16], 0, 16));
        }
        finally
        {
            specNI.dispose(spec);
        }
    }

    /**
     * A null array with {@code off == len == 0} — the combination both range
     * checks pass, which would otherwise reach a util assert and abort the JVM.
     */
    @Test
    public void nullInput_atZeroOffsetAndLength_rejectedTyped()
    {
        long spec = specNI.allocate();
        try
        {
            assertTyped(NullPointerException.class, "input is null",
                    () -> ni.decode_publicKey(spec, KS_TYPE, null, 0, 0));
            assertTyped(NullPointerException.class, "input is null",
                    () -> ni.decode_privateKey(spec, KS_TYPE, null, 0, 0));
        }
        finally
        {
            specNI.dispose(spec);
        }
    }

    @Test
    public void negativeOffsetsAndLengths_rejectedTyped()
    {
        long spec = specNI.allocate();
        try
        {
            byte[] in = new byte[16];
            assertTyped(IllegalArgumentException.class, "input offset is negative",
                    () -> ni.decode_publicKey(spec, KS_TYPE, in, -1, 16));
            assertTyped(IllegalArgumentException.class, "input offset is negative",
                    () -> ni.decode_publicKey(spec, KS_TYPE, in, Integer.MIN_VALUE, 16));
            assertTyped(IllegalArgumentException.class, "input len is negative",
                    () -> ni.decode_publicKey(spec, KS_TYPE, in, 0, -1));
            assertTyped(IllegalArgumentException.class, "input len is negative",
                    () -> ni.decode_publicKey(spec, KS_TYPE, in, 0, Integer.MIN_VALUE));
            assertTyped(IllegalArgumentException.class, "input offset is negative",
                    () -> ni.decode_privateKey(spec, KS_TYPE, in, -1, 16));
            assertTyped(IllegalArgumentException.class, "input len is negative",
                    () -> ni.decode_privateKey(spec, KS_TYPE, in, 0, -1));
        }
        finally
        {
            specNI.dispose(spec);
        }
    }

    @Test
    public void offsetPlusLengthPastEnd_rejectedAtTheBoundary()
    {
        long spec = specNI.allocate();
        try
        {
            byte[] in = new byte[16];
            assertTyped(IllegalArgumentException.class, "input offset + length is out of range",
                    () -> ni.decode_publicKey(spec, KS_TYPE, in, 1, 16));
            assertTyped(IllegalArgumentException.class, "input offset + length is out of range",
                    () -> ni.decode_publicKey(spec, KS_TYPE, in, 0, 17));
            assertTyped(IllegalArgumentException.class, "input offset + length is out of range",
                    () -> ni.decode_publicKey(spec, KS_TYPE, in, 17, 0));
            assertTyped(IllegalArgumentException.class, "input offset + length is out of range",
                    () -> ni.decode_privateKey(spec, KS_TYPE, in, 1, 16));
            assertTyped(IllegalArgumentException.class, "input offset + length is out of range",
                    () -> ni.decode_privateKey(spec, KS_TYPE, in, 0, 17));
        }
        finally
        {
            specNI.dispose(spec);
        }
    }

    /**
     * The FIPS twin of the private-export canary. Needs a real key, so it runs
     * only on a module that serves the group — and it must be the module's
     * behaviour that is measured, not the base library's, since the two link
     * different providers and could in principle diverge.
     */
    @Test
    public void privateExportSplitMatchesTheBaseLibrary()
    {
        for (MLXKEMParameterSpec spec : MLXKEMParameterSpec.all())
        {
            if (org.openssl.jostle.test.fips.FIPSTestUtil.assumeFipsProvider()
                    .getService("KeyPairGenerator", spec.getName()) == null)
            {
                continue;
            }

            long ref = ni.generateKeyPair(spec.getKeyType().getKsType(), RND);
            try
            {
                int len = ni.getPrivateKey(ref, null);
                Assertions.assertTrue(len > 0, spec.getName());
                byte[] out = new byte[len];

                if (spec.getName().startsWith("SecP"))
                {
                    Assertions.assertEquals(
                            "this hybrid variant does not expose its private key material",
                            Assertions.assertThrows(UnsupportedOperationException.class,
                                    () -> ni.getPrivateKey(ref, out)).getMessage(),
                            spec.getName());
                }
                else
                {
                    Assertions.assertEquals(len, ni.getPrivateKey(ref, out), spec.getName());
                }
            }
            finally
            {
                specNI.dispose(ref);
            }
        }
    }

    private static void assertTyped(Class<? extends RuntimeException> type, String message,
                                    Executable call)
    {
        Assertions.assertEquals(message, Assertions.assertThrows(type, call).getMessage());
    }
}
