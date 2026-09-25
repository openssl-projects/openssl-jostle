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
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.provider.mlkem.MLKEMServiceNI;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.rand.RandSource;
import org.openssl.jostle.test.TestUtil;

/**
 * Input validation at the ML-KEM NI surface of the FIPS interface library
 * ({@link FIPSNISelector#MLKEMServiceNI}), mirroring {@code MLKEMLimitTest}.
 * <p>
 * The FIPS glue is the base bridge re-included under renamed symbols, so the
 * checks are identical by construction — this pins that they survived into the
 * other library with the same codes and the same messages, which is the only
 * thing that catches a wrapper that dropped an entry point or a tree that
 * drifted. Both bridges validate separately, so it runs on JNI and FFM.
 * <p>
 * <b>Most cells reject at the BRIDGE</b>, before any module call, so they do
 * not depend on the loaded module implementing ML-KEM — and 3.1.2 implements
 * none. The cells that need a real key say so and skip, and
 * {@link #theRegistrationAgreesWithTheModule} keeps that skip honest by
 * asserting the provider surface against the MODULE's own answer.
 * <p>
 * Runs under the {@code integrationTest*} tasks; gated on
 * {@code TEST_FIPS_LIB}.
 */
public class FIPSMLKEMLimitTest
{
    private static final RandSource RND = TestUtil.RNDSrc;

    private final MLKEMServiceNI ni = FIPSNISelector.MLKEMServiceNI;
    private final SpecNI specNI = FIPSNISelector.SpecNI;

    private static final int KT_512 = OSSLKeyType.ML_KEM_512.getKsType();
    private static final int KT_768 = OSSLKeyType.ML_KEM_768.getKsType();
    private static final int KT_1024 = OSSLKeyType.ML_KEM_1024.getKsType();

    @BeforeAll
    public static void beforeAll()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        TestUtil.addFipsProvider();
    }

    /** Does the loaded MODULE implement ML-KEM? 3.1.2 does not. */
    private static boolean moduleServesMlKem()
    {
        return FIPSTestUtil.moduleServesKeyMgmt("ML-KEM-768");
    }

    private static void assumeMlKem()
    {
        Assumptions.assumeTrue(moduleServesMlKem(),
                "the loaded FIPS module implements no ML-KEM (3.1.2)");
    }

    /**
     * The skip the fixture cells take is only sound while the registration
     * agrees with the module. Asking the module rather than the provider is
     * what makes this a check and not a restatement.
     */
    @Test
    public void theRegistrationAgreesWithTheModule()
    {
        boolean registered = FIPSTestUtil.assumeFipsProvider()
                .getService("KeyPairGenerator", "ML-KEM-768") != null;
        Assertions.assertEquals(moduleServesMlKem(), registered,
                "the module and JSLFIPS disagree about ML-KEM: module says "
                        + moduleServesMlKem() + ", provider says " + registered);
    }

    // -----------------------------------------------------------------
    // generateKeyPair
    // -----------------------------------------------------------------

    @Test
    public void generateKeyPair_wrongKeyType_rejectedTyped()
    {
        for (int type : new int[]{-1, 0, 7, Integer.MAX_VALUE, Integer.MIN_VALUE})
        {
            assertTyped(IllegalArgumentException.class, "invalid key type for ML-KEM",
                    () -> ni.generateKeyPair(type, RND));
            assertTyped(IllegalArgumentException.class, "invalid key type for ML-KEM",
                    () -> ni.generateKeyPair(type, new byte[64], 64, RND));
        }
    }

    @Test
    public void generateKeyPair_nullRandSource_rejectedTyped()
    {
        assertTyped(IllegalArgumentException.class, "supplied random source was null",
                () -> ni.generateKeyPair(KT_512, null));
        assertTyped(IllegalArgumentException.class, "supplied random source was null",
                () -> ni.generateKeyPair(KT_512, new byte[64], 64, null));
    }

    @Test
    public void generateKeyPair_seedIsNull_rejectedTyped()
    {
        assertTyped(IllegalArgumentException.class, "seed is null",
                () -> ni.generateKeyPair(KT_512, null, 0, RND));
        // A length with no array: the length must not be believed.
        assertTyped(IllegalArgumentException.class, "seed is null",
                () -> ni.generateKeyPair(KT_512, null, 64, RND));
    }

    @Test
    public void generateKeyPair_negativeSeedLength_rejectedTyped()
    {
        assertTyped(IllegalArgumentException.class, "seed len is negative",
                () -> ni.generateKeyPair(KT_1024, new byte[64], -1, RND));
        assertTyped(IllegalArgumentException.class, "seed len is negative",
                () -> ni.generateKeyPair(KT_1024, new byte[64], Integer.MIN_VALUE, RND));
    }

    @Test
    public void generateKeyPair_seedLengthPastEnd_rejectedAtTheBoundary()
    {
        assertTyped(IllegalArgumentException.class, "seed length is out of range",
                () -> ni.generateKeyPair(KT_512, new byte[64], 65, RND));
    }

    @Test
    public void generateKeyPair_seedLengthNot64_rejectedTyped()
    {
        assertTyped(IllegalArgumentException.class, "invalid seed length",
                () -> ni.generateKeyPair(KT_512, new byte[64], 63, RND));
        assertTyped(IllegalArgumentException.class, "invalid seed length",
                () -> ni.generateKeyPair(KT_512, new byte[64], 0, RND));
    }

    // -----------------------------------------------------------------
    // getPublicKey / getPrivateKey / getSeed
    // -----------------------------------------------------------------

    @Test
    public void nullKeySpecHandle_rejectedTypedAtEveryExporter()
    {
        assertTyped(IllegalArgumentException.class, "key spec is null",
                () -> ni.getPublicKey(0, new byte[0]));
        assertTyped(IllegalArgumentException.class, "key spec is null",
                () -> ni.getPrivateKey(0, new byte[0]));
        assertTyped(IllegalArgumentException.class, "key spec is null",
                () -> ni.getSeed(0, new byte[0]));
        assertTyped(IllegalArgumentException.class, "key spec is null",
                () -> ni.getPublicKey(0, null));
        assertTyped(IllegalArgumentException.class, "key spec is null",
                () -> ni.getPrivateKey(0, null));
        assertTyped(IllegalArgumentException.class, "key spec is null",
                () -> ni.getSeed(0, null));
    }

    @Test
    public void emptyKeySpec_rejectedTypedAtEveryExporter()
    {
        long ref = specNI.allocate();
        try
        {
            assertTyped(IllegalArgumentException.class, "key spec has null key",
                    () -> ni.getPublicKey(ref, new byte[0]));
            assertTyped(IllegalArgumentException.class, "key spec has null key",
                    () -> ni.getPrivateKey(ref, new byte[0]));
            assertTyped(IllegalArgumentException.class, "key spec has null key",
                    () -> ni.getSeed(ref, new byte[0]));
        }
        finally
        {
            specNI.dispose(ref);
        }
    }

    @Test
    public void shortOutputBuffer_rejectedTypedAtEveryExporter()
    {
        assumeMlKem();
        long ref = ni.generateKeyPair(KT_512, RND);
        try
        {
            assertTyped(IllegalArgumentException.class, "output too small",
                    () -> ni.getPublicKey(ref, new byte[10]));
            assertTyped(IllegalArgumentException.class, "output too small",
                    () -> ni.getPrivateKey(ref, new byte[10]));
            assertTyped(IllegalArgumentException.class, "output too small",
                    () -> ni.getSeed(ref, new byte[10]));

            // The boundary the other way: a null output is the size query and
            // must SUCCEED, or the short-buffer pin above proves nothing.
            Assertions.assertTrue(ni.getPublicKey(ref, null) > 0, "the size query must answer");
            Assertions.assertTrue(ni.getPrivateKey(ref, null) > 0, "the size query must answer");
            Assertions.assertTrue(ni.getSeed(ref, null) > 0, "the size query must answer");
        }
        finally
        {
            specNI.dispose(ref);
        }
    }

    /**
     * A key of another family reaches the exporters as a valid handle, so the
     * refusal has to come from the key TYPE check rather than from a null
     * pointer. EC is used because every supported module serves it.
     */
    @Test
    public void foreignKeyType_rejectedWithTheTypedCode()
    {
        long ref = FIPSNISelector.ECServiceNI.generateKeyPair("P-256", RND);
        try
        {
            Assertions.assertTrue(ref > 0);
            Assertions.assertEquals(ErrorCode.JO_INCORRECT_KEY_TYPE.getCode(),
                    ni.ni_getPublicKey(ref, new byte[2048]));
            Assertions.assertEquals(ErrorCode.JO_INCORRECT_KEY_TYPE.getCode(),
                    ni.ni_getPrivateKey(ref, new byte[4096]));
            Assertions.assertEquals(ErrorCode.JO_INCORRECT_KEY_TYPE.getCode(),
                    ni.ni_getSeed(ref, new byte[2048]));
        }
        finally
        {
            specNI.dispose(ref);
        }
    }

    // -----------------------------------------------------------------
    // decode_publicKey / decode_privateKey
    // -----------------------------------------------------------------

    @Test
    public void decode_nullKeySpecHandle_rejectedTyped()
    {
        assertTyped(IllegalArgumentException.class, "key spec is null",
                () -> ni.decode_publicKey(0, KT_512, new byte[1024], 0, 1024, RND));
        assertTyped(IllegalArgumentException.class, "key spec is null",
                () -> ni.decode_privateKey(0, KT_512, new byte[1024], 0, 1024, RND));
    }

    /**
     * A null array with {@code off == len == 0} — the combination both range
     * checks pass, which would otherwise reach a util assert and abort the JVM.
     */
    @Test
    public void decode_nullInput_atZeroOffsetAndLength_rejectedTyped()
    {
        long ref = specNI.allocate();
        try
        {
            assertTyped(NullPointerException.class, "input is null",
                    () -> ni.decode_publicKey(ref, KT_768, null, 0, 0, RND));
            assertTyped(NullPointerException.class, "input is null",
                    () -> ni.decode_privateKey(ref, KT_768, null, 0, 0, RND));
        }
        finally
        {
            specNI.dispose(ref);
        }
    }

    @Test
    public void decode_negativeOffsetsAndLengths_rejectedTyped()
    {
        long ref = specNI.allocate();
        try
        {
            assertTyped(IllegalArgumentException.class, "input offset is negative",
                    () -> ni.decode_publicKey(ref, KT_512, new byte[0], -1, 0, RND));
            assertTyped(IllegalArgumentException.class, "input offset is negative",
                    () -> ni.decode_publicKey(ref, KT_512, new byte[0], Integer.MIN_VALUE, 0, RND));
            assertTyped(IllegalArgumentException.class, "input len is negative",
                    () -> ni.decode_publicKey(ref, KT_512, new byte[0], 0, -1, RND));
            assertTyped(IllegalArgumentException.class, "input len is negative",
                    () -> ni.decode_publicKey(ref, KT_512, new byte[0], 0, Integer.MIN_VALUE, RND));
            assertTyped(IllegalArgumentException.class, "input offset is negative",
                    () -> ni.decode_privateKey(ref, KT_512, new byte[0], -1, 0, RND));
            assertTyped(IllegalArgumentException.class, "input offset is negative",
                    () -> ni.decode_privateKey(ref, KT_512, new byte[0], Integer.MIN_VALUE, 0, RND));
            assertTyped(IllegalArgumentException.class, "input len is negative",
                    () -> ni.decode_privateKey(ref, KT_512, new byte[0], 0, -1, RND));
            assertTyped(IllegalArgumentException.class, "input len is negative",
                    () -> ni.decode_privateKey(ref, KT_512, new byte[0], 0, Integer.MIN_VALUE, RND));
        }
        finally
        {
            specNI.dispose(ref);
        }
    }

    /** Probed at exactly {@code boundary + 1}, on each side of the pair. */
    @Test
    public void decode_offsetPlusLengthPastEnd_rejectedAtTheBoundary()
    {
        long ref = specNI.allocate();
        try
        {
            assertTyped(IllegalArgumentException.class, "input offset + length is out of range",
                    () -> ni.decode_publicKey(ref, KT_512, new byte[10], 1, 10, RND));
            assertTyped(IllegalArgumentException.class, "input offset + length is out of range",
                    () -> ni.decode_publicKey(ref, KT_512, new byte[10], 0, 11, RND));
            assertTyped(IllegalArgumentException.class, "input offset + length is out of range",
                    () -> ni.decode_publicKey(ref, KT_512, new byte[10], 11, 0, RND));
            assertTyped(IllegalArgumentException.class, "input offset + length is out of range",
                    () -> ni.decode_privateKey(ref, KT_512, new byte[10], 1, 10, RND));
            assertTyped(IllegalArgumentException.class, "input offset + length is out of range",
                    () -> ni.decode_privateKey(ref, KT_512, new byte[10], 0, 11, RND));
            assertTyped(IllegalArgumentException.class, "input offset + length is out of range",
                    () -> ni.decode_privateKey(ref, KT_512, new byte[10], 11, 0, RND));
        }
        finally
        {
            specNI.dispose(ref);
        }
    }

    @Test
    public void decode_wrongKeyType_rejectedTyped()
    {
        long ref = specNI.allocate();
        try
        {
            assertTyped(IllegalArgumentException.class, "invalid key type for ML-KEM",
                    () -> ni.decode_publicKey(ref, 99, new byte[10], 0, 10, RND));
            assertTyped(IllegalArgumentException.class, "invalid key type for ML-KEM",
                    () -> ni.decode_privateKey(ref, 99, new byte[10], 0, 10, RND));
        }
        finally
        {
            specNI.dispose(ref);
        }
    }

    @Test
    public void decode_nullRandSource_rejectedTyped()
    {
        long ref = specNI.allocate();
        try
        {
            assertTyped(IllegalArgumentException.class, "supplied random source was null",
                    () -> ni.decode_publicKey(ref, KT_512, new byte[800], 0, 800, null));
            assertTyped(IllegalArgumentException.class, "supplied random source was null",
                    () -> ni.decode_privateKey(ref, KT_512, new byte[1632], 0, 1632, null));
        }
        finally
        {
            specNI.dispose(ref);
        }
    }

    /** Public-key decode is strict equality on the per-variant length. */
    @Test
    public void decode_publicKeyWrongLengthForVariant_rejectedAtTheBoundary()
    {
        int[][] tuples = {{KT_512, 799}, {KT_512, 801}, {KT_768, 1183}, {KT_768, 1185},
                {KT_1024, 1567}, {KT_1024, 1569}};
        for (int[] t : tuples)
        {
            long ref = specNI.allocate();
            try
            {
                assertTyped(IllegalArgumentException.class, "incorrect public key length",
                        () -> ni.decode_publicKey(ref, t[0], new byte[t[1]], 0, t[1], RND));
            }
            finally
            {
                specNI.dispose(ref);
            }
        }
    }

    /** Private-key decode is a minimum, so only the short side is refused. */
    @Test
    public void decode_privateKeyTooShortForVariant_rejectedAtTheBoundary()
    {
        int[][] tuples = {{KT_512, 1631}, {KT_768, 2399}, {KT_1024, 3167}};
        for (int[] t : tuples)
        {
            long ref = specNI.allocate();
            try
            {
                assertTyped(IllegalArgumentException.class, "incorrect private key length",
                        () -> ni.decode_privateKey(ref, t[0], new byte[t[1]], 0, t[1], RND));
            }
            finally
            {
                specNI.dispose(ref);
            }
        }
    }

    /**
     * The positive control for the two length cells above: at the exact length
     * the decode SUCCEEDS, so the refusals are proven to sit at the boundary
     * rather than everywhere. Needs a real key, hence the module gate.
     */
    @Test
    public void decode_atTheExactLength_succeeds()
    {
        assumeMlKem();
        long src = ni.generateKeyPair(KT_768, RND);
        try
        {
            byte[] pub = new byte[ni.getPublicKey(src, null)];
            ni.getPublicKey(src, pub);
            byte[] priv = new byte[ni.getPrivateKey(src, null)];
            ni.getPrivateKey(src, priv);

            long ref = specNI.allocate();
            try
            {
                Assertions.assertTrue(ni.decode_publicKey(ref, KT_768, pub, 0, pub.length, RND) >= 0);
            }
            finally
            {
                specNI.dispose(ref);
            }

            long ref2 = specNI.allocate();
            try
            {
                Assertions.assertTrue(ni.decode_privateKey(ref2, KT_768, priv, 0, priv.length, RND) >= 0);
            }
            finally
            {
                specNI.dispose(ref2);
            }
        }
        finally
        {
            specNI.dispose(src);
        }
    }

    private static void assertTyped(Class<? extends RuntimeException> type, String message,
                                    Executable call)
    {
        Assertions.assertEquals(message, Assertions.assertThrows(type, call).getMessage());
    }
}
