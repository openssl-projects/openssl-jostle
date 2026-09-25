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
import org.openssl.jostle.jcajce.provider.slhdsa.SLHDSAServiceNI;
import org.openssl.jostle.jcajce.provider.slhdsa.SLHDSASignatureSpi;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.rand.RandSource;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.util.Arrays;

import java.security.SecureRandom;

/**
 * Input validation at the SLH-DSA NI surface of the FIPS interface library
 * ({@link FIPSNISelector#SLHDSAServiceNI}), mirroring {@code SLHDSALimitTest}.
 * <p>
 * The FIPS glue is the base bridge re-included under renamed symbols, so the
 * checks are identical by construction — this pins that they survived into the
 * other library with the same codes and the same messages. Both bridges
 * validate separately, so it runs on JNI and FFM.
 * <p>
 * Cells that reject at the BRIDGE before any module call run on both supported
 * modules; the rest need a real key and skip where the module has no SLH-DSA
 * (3.1.2). {@link #theRegistrationAgreesWithTheModule} keeps that skip honest
 * by asking the MODULE, not the provider.
 * <p>
 * Every key-bearing cell uses a "128F" parameter set: the "S" variants sign in
 * seconds and nothing here depends on which set is used.
 * <p>
 * Runs under the {@code integrationTest*} tasks; gated on
 * {@code TEST_FIPS_LIB}.
 */
public class FIPSSLHDSALimitTest
{
    private static final RandSource RND = TestUtil.RNDSrc;

    private final SLHDSAServiceNI ni = FIPSNISelector.SLHDSAServiceNI;
    private final SpecNI specNI = FIPSNISelector.SpecNI;

    private static final int KT_128F = OSSLKeyType.SLH_DSA_SHA2_128f.getKsType();

    private static final int ENC_NONE = SLHDSASignatureSpi.MessageEncoding.NONE.ordinal();
    private static final int ENC_PURE = SLHDSASignatureSpi.MessageEncoding.PURE.ordinal();
    private static final int DET_OFF = SLHDSASignatureSpi.Deterministic.NON_DETERMINISTIC.ordinal();
    private static final int DET_ON = SLHDSASignatureSpi.Deterministic.DETERMINISTIC.ordinal();

    @BeforeAll
    public static void beforeAll()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        TestUtil.addFipsProvider();
    }

    private static boolean moduleServesSlhDsa()
    {
        return FIPSTestUtil.moduleServesKeyMgmt("SLH-DSA-SHA2-128S");
    }

    private static void assumeSlhDsa()
    {
        Assumptions.assumeTrue(moduleServesSlhDsa(),
                "the loaded FIPS module implements no SLH-DSA (3.1.2)");
    }

    @Test
    public void theRegistrationAgreesWithTheModule()
    {
        boolean registered = FIPSTestUtil.assumeFipsProvider()
                .getService("Signature", "SLH-DSA-SHA2-128F") != null;
        Assertions.assertEquals(moduleServesSlhDsa(), registered,
                "the module and JSLFIPS disagree about SLH-DSA: module says "
                        + moduleServesSlhDsa() + ", provider says " + registered);
    }

    // -----------------------------------------------------------------
    // Bridge-only cells: no key needed, so both modules run them.
    // -----------------------------------------------------------------

    @Test
    public void nullSignerContext_rejectedTypedAtEveryEntryPoint()
    {
        byte[] ctx = new byte[0];
        byte[] sig = new byte[8];
        assertTyped(IllegalArgumentException.class, "signer context is null",
                () -> ni.initSign(0, 0, ctx, 0, ENC_PURE, DET_OFF, RND));
        assertTyped(IllegalArgumentException.class, "signer context is null",
                () -> ni.initVerify(0, 0, ctx, 0, ENC_PURE, DET_OFF));
        assertTyped(IllegalArgumentException.class, "signer context is null",
                () -> ni.update(0, new byte[8], 0, 8));
        assertTyped(IllegalArgumentException.class, "signer context is null",
                () -> ni.sign(0, sig, 0, RND));
        assertTyped(IllegalArgumentException.class, "signer context is null",
                () -> ni.verify(0, sig, sig.length));
    }

    @Test
    public void generateKeyPair_wrongKeyType_rejectedTyped()
    {
        for (int type : new int[]{-1, 0, Integer.MAX_VALUE, Integer.MIN_VALUE})
        {
            assertTyped(IllegalArgumentException.class, "invalid key type for SLH-DSA",
                    () -> ni.generateKeyPair(type, RND));
            assertTyped(IllegalArgumentException.class, "invalid key type for SLH-DSA",
                    () -> ni.generateKeyPair(type, new byte[48], 48, RND));
        }
    }

    @Test
    public void generateKeyPair_nullRandSource_rejectedTyped()
    {
        assertTyped(IllegalArgumentException.class, "supplied random source was null",
                () -> ni.generateKeyPair(KT_128F, null));
        assertTyped(IllegalArgumentException.class, "supplied random source was null",
                () -> ni.generateKeyPair(KT_128F, new byte[48], 48, null));
    }

    @Test
    public void generateKeyPair_seedFaults_rejectedTyped()
    {
        assertTyped(IllegalArgumentException.class, "seed is null",
                () -> ni.generateKeyPair(KT_128F, null, 0, RND));
        assertTyped(IllegalArgumentException.class, "seed is null",
                () -> ni.generateKeyPair(KT_128F, null, 48, RND));
        assertTyped(IllegalArgumentException.class, "seed len is negative",
                () -> ni.generateKeyPair(KT_128F, new byte[48], -1, RND));
        assertTyped(IllegalArgumentException.class, "seed len is negative",
                () -> ni.generateKeyPair(KT_128F, new byte[48], Integer.MIN_VALUE, RND));
        assertTyped(IllegalArgumentException.class, "seed length is out of range",
                () -> ni.generateKeyPair(KT_128F, new byte[48], 49, RND));
    }

    /**
     * The seed is 3n bytes, n being the security parameter — 16, 24 or 32 — so
     * the wrong length is refused per level rather than against one constant.
     */
    @Test
    public void generateKeyPair_seedLengthWrongForTheLevel_rejectedAtTheBoundary()
    {
        Object[][] levels = {
                {OSSLKeyType.SLH_DSA_SHA2_128f, 16},
                {OSSLKeyType.SLH_DSA_SHA2_192f, 24},
                {OSSLKeyType.SLH_DSA_SHA2_256f, 32},
                {OSSLKeyType.SLH_DSA_SHAKE_128f, 16},
                {OSSLKeyType.SLH_DSA_SHAKE_192f, 24},
                {OSSLKeyType.SLH_DSA_SHAKE_256f, 32}};

        for (Object[] level : levels)
        {
            int keyType = ((OSSLKeyType) level[0]).getKsType();
            int n = (Integer) level[1];
            byte[] seed = new byte[n * 3];
            assertTyped(IllegalArgumentException.class, "invalid seed length",
                    () -> ni.generateKeyPair(keyType, seed, seed.length - 1, RND));
            assertTyped(IllegalArgumentException.class, "invalid seed length",
                    () -> ni.generateKeyPair(keyType, new byte[n * 3 + 1], n * 3 + 1, RND));
        }
    }

    @Test
    public void nullKeySpecHandle_rejectedTypedAtEveryExporter()
    {
        assertTyped(IllegalArgumentException.class, "key spec is null",
                () -> ni.getPublicKey(0, new byte[0]));
        assertTyped(IllegalArgumentException.class, "key spec is null",
                () -> ni.getPrivateKey(0, new byte[0]));
        assertTyped(IllegalArgumentException.class, "key spec is null",
                () -> ni.decode_publicKey(0, KT_128F, new byte[1024], 0, 1024));
        assertTyped(IllegalArgumentException.class, "key spec is null",
                () -> ni.decode_privateKey(0, KT_128F, new byte[1024], 0, 1024));
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
        }
        finally
        {
            specNI.dispose(ref);
        }
    }

    @Test
    public void decode_nullInput_atZeroOffsetAndLength_rejectedTyped()
    {
        long ref = specNI.allocate();
        try
        {
            assertTyped(NullPointerException.class, "input is null",
                    () -> ni.decode_publicKey(ref, KT_128F, null, 0, 0));
            assertTyped(NullPointerException.class, "input is null",
                    () -> ni.decode_privateKey(ref, KT_128F, null, 0, 0));
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
                    () -> ni.decode_publicKey(ref, KT_128F, new byte[0], -1, 0));
            assertTyped(IllegalArgumentException.class, "input offset is negative",
                    () -> ni.decode_publicKey(ref, KT_128F, new byte[0], Integer.MIN_VALUE, 0));
            assertTyped(IllegalArgumentException.class, "input len is negative",
                    () -> ni.decode_publicKey(ref, KT_128F, new byte[0], 0, -1));
            assertTyped(IllegalArgumentException.class, "input offset is negative",
                    () -> ni.decode_privateKey(ref, KT_128F, new byte[0], -1, 0));
            assertTyped(IllegalArgumentException.class, "input len is negative",
                    () -> ni.decode_privateKey(ref, KT_128F, new byte[0], 0, -1));
        }
        finally
        {
            specNI.dispose(ref);
        }
    }

    @Test
    public void decode_offsetPlusLengthPastEnd_rejectedAtTheBoundary()
    {
        long ref = specNI.allocate();
        try
        {
            assertTyped(IllegalArgumentException.class, "input offset + length is out of range",
                    () -> ni.decode_publicKey(ref, KT_128F, new byte[10], 1, 10));
            assertTyped(IllegalArgumentException.class, "input offset + length is out of range",
                    () -> ni.decode_publicKey(ref, KT_128F, new byte[10], 0, 11));
            assertTyped(IllegalArgumentException.class, "input offset + length is out of range",
                    () -> ni.decode_privateKey(ref, KT_128F, new byte[10], 1, 10));
            assertTyped(IllegalArgumentException.class, "input offset + length is out of range",
                    () -> ni.decode_privateKey(ref, KT_128F, new byte[10], 0, 11));
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
            assertTyped(IllegalArgumentException.class, "invalid key type for SLH-DSA",
                    () -> ni.decode_publicKey(ref, 99, new byte[10], 0, 10));
            assertTyped(IllegalArgumentException.class, "invalid key type for SLH-DSA",
                    () -> ni.decode_privateKey(ref, 99, new byte[10], 0, 10));
        }
        finally
        {
            specNI.dispose(ref);
        }
    }

    /**
     * A NAMED parameter set has its length checked against that set. An
     * unnamed set is refused by type instead, without reaching a length check
     * at all — the next cell.
     */
    @Test
    public void decode_wrongLengthForTheNamedSet_rejectedTyped()
    {
        long ref = specNI.allocate();
        try
        {
            assertTyped(IllegalArgumentException.class, "incorrect public key length",
                    () -> ni.decode_publicKey(ref, KT_128F, new byte[7], 0, 7));
            assertTyped(IllegalArgumentException.class, "incorrect private key length",
                    () -> ni.decode_privateKey(ref, KT_128F, new byte[7], 0, 7));
        }
        finally
        {
            specNI.dispose(ref);
        }
    }

    /**
     * An UNNAMED parameter set is refused BY TYPE on both decoders, and both
     * are measured independently so neither can mask the other.
     * <p>
     * The length cannot identify an SLH-DSA set: each security parameter n
     * (16, 24, 32) is shared by four sets — SHA2 and SHAKE, fast and small —
     * so a 2n-byte public key or a 4n-byte private key is ambiguous four ways.
     * Refusing the unnamed set is the only sound answer, and {@code slhdsa.c}
     * has no length-inference path at all. ML-DSA's lengths ARE unique per
     * set, which is why its decoders infer instead; that difference is between
     * the families, not between these two halves.
     */
    @Test
    public void decode_unnamedSet_refusedByTypeOnBothDecoders()
    {
        int none = OSSLKeyType.NONE.getKsType();
        long ref = specNI.allocate();
        try
        {
            Assertions.assertAll(
                    () -> assertTyped(IllegalArgumentException.class, "invalid key type for SLH-DSA",
                            () -> ni.decode_publicKey(ref, none, new byte[7], 0, 7)),
                    () -> assertTyped(IllegalArgumentException.class, "invalid key type for SLH-DSA",
                            () -> ni.decode_privateKey(ref, none, new byte[7], 0, 7)));
        }
        finally
        {
            specNI.dispose(ref);
        }
    }

    // -----------------------------------------------------------------
    // Cells that need a real key.
    // -----------------------------------------------------------------

    private long signer()
    {
        return ni.allocateSigner();
    }

    private long key()
    {
        return ni.generateKeyPair(KT_128F, RND);
    }

    @Test
    public void shortOutputBuffer_rejectedTypedAtEveryExporter()
    {
        assumeSlhDsa();
        long ref = key();
        try
        {
            assertTyped(IllegalArgumentException.class, "output too small",
                    () -> ni.getPublicKey(ref, new byte[10]));
            assertTyped(IllegalArgumentException.class, "output too small",
                    () -> ni.getPrivateKey(ref, new byte[10]));

            Assertions.assertTrue(ni.getPublicKey(ref, null) > 0);
            Assertions.assertTrue(ni.getPrivateKey(ref, null) > 0);
        }
        finally
        {
            specNI.dispose(ref);
        }
    }

    @Test
    public void foreignKeyType_rejectedWithTheTypedCode()
    {
        long ref = FIPSNISelector.ECServiceNI.generateKeyPair("P-256", RND);
        try
        {
            Assertions.assertTrue(ref > 0);
            Assertions.assertEquals(ErrorCode.JO_INCORRECT_KEY_TYPE.getCode(),
                    ni.ni_getPublicKey(ref, new byte[8192]));
            Assertions.assertEquals(ErrorCode.JO_INCORRECT_KEY_TYPE.getCode(),
                    ni.ni_getPrivateKey(ref, new byte[8192]));
        }
        finally
        {
            specNI.dispose(ref);
        }
    }

    @Test
    public void init_contextFaults_rejectedTyped()
    {
        assumeSlhDsa();
        long sig = signer();
        long k = key();
        try
        {
            assertTyped(IllegalArgumentException.class, "context array is null",
                    () -> ni.initVerify(sig, k, null, 0, ENC_PURE, DET_OFF));
            assertTyped(IllegalArgumentException.class, "context array is null",
                    () -> ni.initSign(sig, k, null, 0, ENC_PURE, DET_OFF, RND));
            assertTyped(IllegalArgumentException.class, "context length is past end of context",
                    () -> ni.initVerify(sig, k, new byte[0], 1, ENC_PURE, DET_OFF));
            assertTyped(IllegalArgumentException.class, "context length is past end of context",
                    () -> ni.initVerify(sig, k, new byte[1], 2, ENC_PURE, DET_OFF));
            assertTyped(IllegalArgumentException.class, "context length is past end of context",
                    () -> ni.initSign(sig, k, new byte[0], 1, ENC_PURE, DET_OFF, RND));
            assertTyped(IllegalArgumentException.class, "context length is too long",
                    () -> ni.initVerify(sig, k, new byte[256], 256, ENC_PURE, DET_OFF));
            assertTyped(IllegalArgumentException.class, "context length is too long",
                    () -> ni.initSign(sig, k, new byte[256], 256, ENC_PURE, DET_OFF, RND));

            Assertions.assertEquals(ErrorCode.JO_SUCCESS.getCode(),
                    ni.initVerify(sig, k, new byte[255], 255, ENC_PURE, DET_OFF),
                    "255 bytes of context must be accepted");
        }
        finally
        {
            ni.disposeSigner(sig);
            specNI.dispose(k);
        }
    }

    @Test
    public void init_keyFaults_rejectedTyped()
    {
        assumeSlhDsa();
        long sig = signer();
        long empty = specNI.allocate();
        try
        {
            assertTyped(IllegalArgumentException.class, "key spec is null",
                    () -> ni.initVerify(sig, 0, new byte[1], 1, ENC_PURE, DET_OFF));
            assertTyped(IllegalArgumentException.class, "key spec is null",
                    () -> ni.initSign(sig, 0, new byte[1], 1, ENC_PURE, DET_OFF, RND));
            assertTyped(IllegalArgumentException.class, "key spec has null key",
                    () -> ni.initVerify(sig, empty, new byte[1], 1, ENC_PURE, DET_OFF));
            assertTyped(IllegalArgumentException.class, "key spec has null key",
                    () -> ni.initSign(sig, empty, new byte[1], 1, ENC_PURE, DET_OFF, RND));
        }
        finally
        {
            ni.disposeSigner(sig);
            specNI.dispose(empty);
        }
    }

    /**
     * The two mode ordinals are separate parameters and are refused separately,
     * so a bridge that validated one and passed the other through is caught.
     */
    @Test
    public void init_modeParameterFaults_rejectedTyped()
    {
        assumeSlhDsa();
        long sig = signer();
        long k = key();
        try
        {
            assertTyped(IllegalArgumentException.class, "invalid message encoding param",
                    () -> ni.initVerify(sig, k, new byte[1], 1, 3, DET_OFF));
            assertTyped(IllegalArgumentException.class, "invalid message encoding param",
                    () -> ni.initVerify(sig, k, new byte[1], 1, -1, DET_OFF));
            assertTyped(IllegalArgumentException.class, "invalid message encoding param",
                    () -> ni.initSign(sig, k, new byte[1], 1, 3, DET_OFF, RND));
            assertTyped(IllegalArgumentException.class, "invalid deterministic param",
                    () -> ni.initVerify(sig, k, new byte[1], 1, ENC_PURE, 3));
            assertTyped(IllegalArgumentException.class, "invalid deterministic param",
                    () -> ni.initVerify(sig, k, new byte[1], 1, ENC_PURE, -1));
            assertTyped(IllegalArgumentException.class, "invalid deterministic param",
                    () -> ni.initSign(sig, k, new byte[1], 1, ENC_PURE, 3, RND));

            // Every legal combination is accepted, or the refusals above prove
            // nothing about where the boundary sits.
            for (int enc : new int[]{ENC_NONE, ENC_PURE})
            {
                for (int det : new int[]{DET_OFF, DET_ON})
                {
                    Assertions.assertEquals(ErrorCode.JO_SUCCESS.getCode(),
                            ni.initVerify(sig, k, new byte[1], 1, enc, det),
                            "encoding " + enc + " / deterministic " + det + " was refused");
                }
            }
        }
        finally
        {
            ni.disposeSigner(sig);
            specNI.dispose(k);
        }
    }

    @Test
    public void initSign_nullRandSource_rejectedTyped()
    {
        assumeSlhDsa();
        long sig = signer();
        long k = key();
        try
        {
            assertTyped(IllegalArgumentException.class, "supplied random source was null",
                    () -> ni.initSign(sig, k, new byte[0], 0, ENC_PURE, DET_OFF, null));
        }
        finally
        {
            ni.disposeSigner(sig);
            specNI.dispose(k);
        }
    }

    @Test
    public void update_beforeInit_andBadRanges_rejectedTyped()
    {
        assumeSlhDsa();
        long sig = signer();
        long k = key();
        try
        {
            assertTyped(IllegalStateException.class, "not initialized",
                    () -> ni.update(sig, new byte[0], 0, 0));

            ni.initSign(sig, k, new byte[0], 0, ENC_PURE, DET_OFF, RND);
            assertTyped(NullPointerException.class, "input is null",
                    () -> ni.update(sig, null, 0, 0));
            assertTyped(IllegalArgumentException.class, "input offset is negative",
                    () -> ni.update(sig, new byte[0], -1, 0));
            assertTyped(IllegalArgumentException.class, "input len is negative",
                    () -> ni.update(sig, new byte[0], 0, -1));
            assertTyped(IllegalArgumentException.class, "input offset + length is out of range",
                    () -> ni.update(sig, new byte[10], 0, 11));
            assertTyped(IllegalArgumentException.class, "input offset + length is out of range",
                    () -> ni.update(sig, new byte[10], 1, 10));
        }
        finally
        {
            ni.disposeSigner(sig);
            specNI.dispose(k);
        }
    }

    @Test
    public void sign_stateAndRangeFaults_rejectedTyped()
    {
        assumeSlhDsa();
        long k = key();
        try
        {
            long bare = signer();
            try
            {
                assertTyped(IllegalStateException.class, "not initialized",
                        () -> ni.sign(bare, new byte[0], 0, RND));
            }
            finally
            {
                ni.disposeSigner(bare);
            }

            long verifying = signer();
            try
            {
                ni.initVerify(verifying, k, new byte[0], 0, ENC_PURE, DET_OFF);
                assertTyped(IllegalStateException.class, "unexpected state",
                        () -> ni.sign(verifying, new byte[0], 0, RND));
            }
            finally
            {
                ni.disposeSigner(verifying);
            }

            long signing = signer();
            try
            {
                ni.initSign(signing, k, new byte[0], 0, ENC_PURE, DET_OFF, RND);
                assertTyped(IllegalArgumentException.class, "output offset is negative",
                        () -> ni.sign(signing, new byte[0], -1, RND));
                assertTyped(IllegalArgumentException.class, "output offset + length is out of range",
                        () -> ni.sign(signing, new byte[0], 1, RND));
                assertTyped(IllegalArgumentException.class, "supplied random source was null",
                        () -> ni.sign(signing, new byte[0], 0, null));

                long len = ni.sign(signing, null, 0, RND);
                Assertions.assertTrue(len > 0, "the signature size query must answer");
                byte[] tooSmall = new byte[(int) len - 1];
                assertTyped(IllegalArgumentException.class, "output too small",
                        () -> ni.sign(signing, tooSmall, 0, RND));
                Assertions.assertTrue(ni.sign(signing, new byte[(int) len], 0, RND) > 0,
                        "a buffer of exactly the reported size must be accepted");
            }
            finally
            {
                ni.disposeSigner(signing);
            }
        }
        finally
        {
            specNI.dispose(k);
        }
    }

    @Test
    public void verify_stateAndRangeFaults_rejectedTyped()
    {
        assumeSlhDsa();
        long k = key();
        try
        {
            long bare = signer();
            try
            {
                assertTyped(IllegalStateException.class, "not initialized",
                        () -> ni.verify(bare, new byte[1], 1));
            }
            finally
            {
                ni.disposeSigner(bare);
            }

            long signing = signer();
            try
            {
                ni.initSign(signing, k, new byte[0], 0, ENC_PURE, DET_OFF, RND);
                assertTyped(IllegalStateException.class, "unexpected state",
                        () -> ni.verify(signing, new byte[1], 1));
            }
            finally
            {
                ni.disposeSigner(signing);
            }

            long verifying = signer();
            try
            {
                ni.initVerify(verifying, k, new byte[0], 0, ENC_PURE, DET_OFF);
                assertTyped(IllegalArgumentException.class, "sig is null",
                        () -> ni.verify(verifying, null, 0));
                assertTyped(IllegalArgumentException.class, "sig length is negative",
                        () -> ni.verify(verifying, new byte[10], -1));
                assertTyped(IllegalArgumentException.class, "sig out of range",
                        () -> ni.verify(verifying, new byte[10], 11));
            }
            finally
            {
                ni.disposeSigner(verifying);
            }
        }
        finally
        {
            specNI.dispose(k);
        }
    }

    /**
     * The offset-write contract: nothing outside the written region moves, the
     * bytes written verify, and a window one byte early does NOT.
     */
    @Test
    public void sign_writesAtOffsetWithoutClobberingThePrefix()
    {
        assumeSlhDsa();
        SecureRandom sr = new SecureRandom();
        long k = key();
        long signing = signer();
        long verifying = signer();
        try
        {
            byte[] msg = new byte[64];
            sr.nextBytes(msg);

            ni.initSign(signing, k, new byte[0], 0, ENC_PURE, DET_OFF, RND);
            ni.update(signing, msg, 0, msg.length);
            int len = (int) ni.sign(signing, null, 0, RND);

            int prefix = 37;
            byte[] big = new byte[prefix + len + 11];
            sr.nextBytes(big);
            byte[] expectedPrefix = java.util.Arrays.copyOf(big, prefix);
            byte[] expectedSuffix = java.util.Arrays.copyOfRange(big, prefix + len, big.length);

            ni.sign(signing, big, prefix, RND);

            Assertions.assertArrayEquals(expectedPrefix, java.util.Arrays.copyOf(big, prefix),
                    "the bytes before the offset were clobbered");
            Assertions.assertArrayEquals(expectedSuffix,
                    java.util.Arrays.copyOfRange(big, prefix + len, big.length),
                    "the bytes after the written region were clobbered");

            byte[] written = java.util.Arrays.copyOfRange(big, prefix, prefix + len);
            ni.initVerify(verifying, k, new byte[0], 0, ENC_PURE, DET_OFF);
            ni.update(verifying, msg, 0, msg.length);
            Assertions.assertEquals(ErrorCode.JO_SUCCESS.getCode(),
                    ni.verify(verifying, written, written.length),
                    "the signature extracted at the offset did not verify");

            byte[] shifted = java.util.Arrays.copyOfRange(big, prefix - 1, prefix - 1 + len);
            Assertions.assertFalse(Arrays.areEqual(written, shifted),
                    "the shifted window is identical — the probe cannot discriminate");
            long verifying2 = signer();
            try
            {
                ni.initVerify(verifying2, k, new byte[0], 0, ENC_PURE, DET_OFF);
                ni.update(verifying2, msg, 0, msg.length);
                Assertions.assertEquals(ErrorCode.JO_FAIL.getCode(),
                        ni.verify(verifying2, shifted, shifted.length),
                        "a window starting one byte early verified — the write is off by one");
            }
            finally
            {
                ni.disposeSigner(verifying2);
            }
        }
        finally
        {
            ni.disposeSigner(signing);
            ni.disposeSigner(verifying);
            specNI.dispose(k);
        }
    }

    private static void assertTyped(Class<? extends RuntimeException> type, String message,
                                    Executable call)
    {
        Assertions.assertEquals(message, Assertions.assertThrows(type, call).getMessage());
    }
}
