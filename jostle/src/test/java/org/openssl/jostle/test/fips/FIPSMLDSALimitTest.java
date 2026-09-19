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
import org.openssl.jostle.jcajce.provider.mldsa.MLDSAServiceNI;
import org.openssl.jostle.jcajce.provider.mldsa.MLDSASignatureSpi;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.rand.RandSource;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.util.Arrays;

import java.security.SecureRandom;

/**
 * Input validation at the ML-DSA NI surface of the FIPS interface library
 * ({@link FIPSNISelector#MLDSAServiceNI}), mirroring {@code MLDSALimitTest}.
 * <p>
 * The FIPS glue is the base bridge re-included under renamed symbols, so the
 * checks are identical by construction — this pins that they survived into the
 * other library with the same codes and the same messages. Both bridges
 * validate separately, so it runs on JNI and FFI.
 * <p>
 * Cells that reject at the BRIDGE before any module call run on both supported
 * modules; the rest need a real key and skip where the module has no ML-DSA
 * (3.1.2). {@link #theRegistrationAgreesWithTheModule} keeps that skip honest
 * by asking the MODULE, not the provider.
 * <p>
 * Runs under the {@code integrationTest*} tasks; gated on
 * {@code TEST_FIPS_LIB}.
 */
public class FIPSMLDSALimitTest
{
    private static final RandSource RND = TestUtil.RNDSrc;

    private final MLDSAServiceNI ni = FIPSNISelector.MLDSAServiceNI;
    private final SpecNI specNI = FIPSNISelector.SpecNI;

    private static final int KT_44 = OSSLKeyType.ML_DSA_44.getKsType();

    private static final int MU_INTERNAL = MLDSASignatureSpi.MuHandling.INTERNAL.ordinal();
    private static final int MU_CALCULATE = MLDSASignatureSpi.MuHandling.CALCULATE_MU.ordinal();
    private static final int MU_EXTERNAL = MLDSASignatureSpi.MuHandling.EXTERNAL_MU.ordinal();

    @BeforeAll
    public static void beforeAll()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        TestUtil.addFipsProvider();
    }

    private static boolean moduleServesMlDsa()
    {
        return FIPSTestUtil.moduleServesKeyMgmt("ML-DSA-65");
    }

    private static void assumeMlDsa()
    {
        Assumptions.assumeTrue(moduleServesMlDsa(),
                "the loaded FIPS module implements no ML-DSA (3.1.2)");
    }

    @Test
    public void theRegistrationAgreesWithTheModule()
    {
        boolean registered = FIPSTestUtil.assumeFipsProvider()
                .getService("Signature", "ML-DSA-65") != null;
        Assertions.assertEquals(moduleServesMlDsa(), registered,
                "the module and JSLFIPS disagree about ML-DSA: module says "
                        + moduleServesMlDsa() + ", provider says " + registered);
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
                () -> ni.initSign(0, 0, ctx, 0, MU_INTERNAL, RND));
        assertTyped(IllegalArgumentException.class, "signer context is null",
                () -> ni.initVerify(0, 0, ctx, 0, MU_INTERNAL));
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
        for (int type : new int[]{-1, 0, 7, Integer.MAX_VALUE, Integer.MIN_VALUE})
        {
            assertTyped(IllegalArgumentException.class, "invalid key type for ML-DSA",
                    () -> ni.generateKeyPair(type, RND));
            assertTyped(IllegalArgumentException.class, "invalid key type for ML-DSA",
                    () -> ni.generateKeyPair(type, new byte[32], 32, RND));
        }
    }

    @Test
    public void generateKeyPair_nullRandSource_rejectedTyped()
    {
        assertTyped(IllegalArgumentException.class, "supplied random source was null",
                () -> ni.generateKeyPair(KT_44, null));
        assertTyped(IllegalArgumentException.class, "supplied random source was null",
                () -> ni.generateKeyPair(KT_44, new byte[32], 32, null));
    }

    @Test
    public void generateKeyPair_seedFaults_rejectedTyped()
    {
        assertTyped(IllegalArgumentException.class, "seed is null",
                () -> ni.generateKeyPair(KT_44, null, 0, RND));
        assertTyped(IllegalArgumentException.class, "seed is null",
                () -> ni.generateKeyPair(KT_44, null, 32, RND));
        assertTyped(IllegalArgumentException.class, "seed len is negative",
                () -> ni.generateKeyPair(KT_44, new byte[32], -1, RND));
        assertTyped(IllegalArgumentException.class, "seed len is negative",
                () -> ni.generateKeyPair(KT_44, new byte[32], Integer.MIN_VALUE, RND));
        assertTyped(IllegalArgumentException.class, "seed length is out of range",
                () -> ni.generateKeyPair(KT_44, new byte[32], 33, RND));
        assertTyped(IllegalArgumentException.class, "invalid seed length",
                () -> ni.generateKeyPair(KT_44, new byte[32], 31, RND));
    }

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
                () -> ni.decode_publicKey(0, KT_44, new byte[1024], 0, 1024));
        assertTyped(IllegalArgumentException.class, "key spec is null",
                () -> ni.decode_privateKey(0, KT_44, new byte[1024], 0, 1024));
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

    /** A null array with {@code off == len == 0} slips past both range checks. */
    @Test
    public void decode_nullInput_atZeroOffsetAndLength_rejectedTyped()
    {
        long ref = specNI.allocate();
        try
        {
            assertTyped(NullPointerException.class, "input is null",
                    () -> ni.decode_publicKey(ref, KT_44, null, 0, 0));
            assertTyped(NullPointerException.class, "input is null",
                    () -> ni.decode_privateKey(ref, KT_44, null, 0, 0));
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
                    () -> ni.decode_publicKey(ref, KT_44, new byte[0], -1, 0));
            assertTyped(IllegalArgumentException.class, "input offset is negative",
                    () -> ni.decode_publicKey(ref, KT_44, new byte[0], Integer.MIN_VALUE, 0));
            assertTyped(IllegalArgumentException.class, "input len is negative",
                    () -> ni.decode_publicKey(ref, KT_44, new byte[0], 0, -1));
            assertTyped(IllegalArgumentException.class, "input len is negative",
                    () -> ni.decode_publicKey(ref, KT_44, new byte[0], 0, Integer.MIN_VALUE));
            assertTyped(IllegalArgumentException.class, "input offset is negative",
                    () -> ni.decode_privateKey(ref, KT_44, new byte[0], -1, 0));
            assertTyped(IllegalArgumentException.class, "input offset is negative",
                    () -> ni.decode_privateKey(ref, KT_44, new byte[0], Integer.MIN_VALUE, 0));
            assertTyped(IllegalArgumentException.class, "input len is negative",
                    () -> ni.decode_privateKey(ref, KT_44, new byte[0], 0, -1));
            assertTyped(IllegalArgumentException.class, "input len is negative",
                    () -> ni.decode_privateKey(ref, KT_44, new byte[0], 0, Integer.MIN_VALUE));
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
                    () -> ni.decode_publicKey(ref, KT_44, new byte[10], 1, 10));
            assertTyped(IllegalArgumentException.class, "input offset + length is out of range",
                    () -> ni.decode_publicKey(ref, KT_44, new byte[10], 0, 11));
            assertTyped(IllegalArgumentException.class, "input offset + length is out of range",
                    () -> ni.decode_privateKey(ref, KT_44, new byte[10], 1, 10));
            assertTyped(IllegalArgumentException.class, "input offset + length is out of range",
                    () -> ni.decode_privateKey(ref, KT_44, new byte[10], 0, 11));
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
            assertTyped(IllegalArgumentException.class, "invalid key type for ML-DSA",
                    () -> ni.decode_publicKey(ref, 99, new byte[10], 0, 10));
            assertTyped(IllegalArgumentException.class, "invalid key type for ML-DSA",
                    () -> ni.decode_privateKey(ref, 99, new byte[10], 0, 10));
        }
        finally
        {
            specNI.dispose(ref);
        }
    }

    /**
     * Two different refusals, and which one fires depends on whether the
     * caller NAMED a parameter set. With a set named the length is checked
     * against that set; with {@code NONE} the length has to identify the set
     * by itself, and a length matching none of them is refused differently.
     * Pinning only one of the two would leave the other arm unexercised.
     */
    @Test
    public void decode_wrongLengthForTheNamedSet_rejectedTyped()
    {
        long ref = specNI.allocate();
        try
        {
            assertTyped(IllegalArgumentException.class, "incorrect public key length",
                    () -> ni.decode_publicKey(ref, KT_44, new byte[7], 0, 7));
            assertTyped(IllegalArgumentException.class, "incorrect private key length",
                    () -> ni.decode_privateKey(ref, KT_44, new byte[7], 0, 7));
        }
        finally
        {
            specNI.dispose(ref);
        }
    }

    @Test
    public void decode_unnamedSetWithALengthMatchingNone_rejectedTyped()
    {
        int none = OSSLKeyType.NONE.getKsType();
        long ref = specNI.allocate();
        try
        {
            assertTyped(IllegalArgumentException.class, "unknown key length",
                    () -> ni.decode_publicKey(ref, none, new byte[7], 0, 7));
            assertTyped(IllegalArgumentException.class, "unknown key length",
                    () -> ni.decode_privateKey(ref, none, new byte[7], 0, 7));
        }
        finally
        {
            specNI.dispose(ref);
        }
    }

    // -----------------------------------------------------------------
    // Cells that need a real key.
    // -----------------------------------------------------------------

    /** A signer handle and an ML-DSA-44 keypair, both disposed by the caller. */
    private long signer()
    {
        return ni.allocateSigner();
    }

    private long key()
    {
        return ni.generateKeyPair(KT_44, RND);
    }

    @Test
    public void shortOutputBuffer_rejectedTypedAtEveryExporter()
    {
        assumeMlDsa();
        long ref = key();
        try
        {
            assertTyped(IllegalArgumentException.class, "output too small",
                    () -> ni.getPublicKey(ref, new byte[10]));
            assertTyped(IllegalArgumentException.class, "output too small",
                    () -> ni.getPrivateKey(ref, new byte[10]));
            assertTyped(IllegalArgumentException.class, "output too small",
                    () -> ni.getSeed(ref, new byte[10]));

            // The size query is the positive control for those three.
            Assertions.assertTrue(ni.getPublicKey(ref, null) > 0);
            Assertions.assertTrue(ni.getPrivateKey(ref, null) > 0);
            Assertions.assertTrue(ni.getSeed(ref, null) > 0);
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
        assumeMlDsa();
        long sig = signer();
        long k = key();
        try
        {
            assertTyped(IllegalArgumentException.class, "context array is null",
                    () -> ni.initVerify(sig, k, null, 0, MU_INTERNAL));
            assertTyped(IllegalArgumentException.class, "context array is null",
                    () -> ni.initSign(sig, k, null, 0, MU_INTERNAL, RND));
            assertTyped(IllegalArgumentException.class, "context length is past end of context",
                    () -> ni.initVerify(sig, k, new byte[0], 1, MU_INTERNAL));
            assertTyped(IllegalArgumentException.class, "context length is past end of context",
                    () -> ni.initVerify(sig, k, new byte[1], 2, MU_INTERNAL));
            assertTyped(IllegalArgumentException.class, "context length is past end of context",
                    () -> ni.initSign(sig, k, new byte[0], 1, MU_INTERNAL, RND));
            assertTyped(IllegalArgumentException.class, "context length is too long",
                    () -> ni.initVerify(sig, k, new byte[256], 256, MU_INTERNAL));
            assertTyped(IllegalArgumentException.class, "context length is too long",
                    () -> ni.initSign(sig, k, new byte[256], 256, MU_INTERNAL, RND));

            // The boundary the other way: 255 is the longest legal context.
            Assertions.assertEquals(ErrorCode.JO_SUCCESS.getCode(),
                    ni.initVerify(sig, k, new byte[255], 255, MU_INTERNAL),
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
        assumeMlDsa();
        long sig = signer();
        long empty = specNI.allocate();
        try
        {
            assertTyped(IllegalArgumentException.class, "key spec is null",
                    () -> ni.initVerify(sig, 0, new byte[1], 1, MU_INTERNAL));
            assertTyped(IllegalArgumentException.class, "key spec is null",
                    () -> ni.initSign(sig, 0, new byte[1], 1, MU_INTERNAL, RND));
            assertTyped(IllegalArgumentException.class, "key spec has null key",
                    () -> ni.initVerify(sig, empty, new byte[1], 1, MU_INTERNAL));
            assertTyped(IllegalArgumentException.class, "key spec has null key",
                    () -> ni.initSign(sig, empty, new byte[1], 1, MU_INTERNAL, RND));
        }
        finally
        {
            ni.disposeSigner(sig);
            specNI.dispose(empty);
        }
    }

    @Test
    public void init_muModeFaults_rejectedTyped()
    {
        assumeMlDsa();
        long sig = signer();
        long k = key();
        try
        {
            assertTyped(IllegalArgumentException.class, "unknown Mu mode",
                    () -> ni.initVerify(sig, k, new byte[1], 1, 3));
            assertTyped(IllegalArgumentException.class, "unknown Mu mode",
                    () -> ni.initSign(sig, k, new byte[1], 1, 3, RND));
            assertTyped(IllegalArgumentException.class, "unknown Mu mode",
                    () -> ni.initVerify(sig, k, new byte[1], 1, -1));
            // CALCULATE_MU is a signing-side mode only.
            assertTyped(IllegalArgumentException.class, "invalid Mu mode for verify",
                    () -> ni.initVerify(sig, k, new byte[1], 1, MU_CALCULATE));
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
        assumeMlDsa();
        long sig = signer();
        long k = key();
        try
        {
            assertTyped(IllegalArgumentException.class, "supplied random source was null",
                    () -> ni.initSign(sig, k, new byte[0], 0, MU_INTERNAL, null));
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
        assumeMlDsa();
        long sig = signer();
        long k = key();
        try
        {
            assertTyped(IllegalStateException.class, "not initialized",
                    () -> ni.update(sig, new byte[0], 0, 0));

            ni.initSign(sig, k, new byte[0], 0, MU_INTERNAL, RND);
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
        assumeMlDsa();
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
                ni.initVerify(verifying, k, new byte[0], 0, MU_INTERNAL);
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
                ni.initSign(signing, k, new byte[0], 0, MU_INTERNAL, RND);
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
                // The boundary the other way.
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
    public void sign_calculateMuShortBuffer_rejectedTyped()
    {
        assumeMlDsa();
        long sig = signer();
        long k = key();
        try
        {
            ni.initSign(sig, k, new byte[0], 0, MU_CALCULATE, RND);
            long len = ni.sign(sig, null, 0, RND);
            Assertions.assertEquals(64, len, "mu is 64 bytes");
            assertTyped(IllegalArgumentException.class, "output too small",
                    () -> ni.sign(sig, new byte[63], 0, RND));
        }
        finally
        {
            ni.disposeSigner(sig);
            specNI.dispose(k);
        }
    }

    @Test
    public void externalMu_wrongLength_rejectedTyped()
    {
        assumeMlDsa();
        long k = key();
        try
        {
            long signing = signer();
            try
            {
                ni.initSign(signing, k, new byte[0], 0, MU_EXTERNAL, RND);
                ni.update(signing, new byte[63], 0, 63);
                long len = ni.sign(signing, null, 0, RND);
                assertTyped(IllegalArgumentException.class, "external Mu invalid length",
                        () -> ni.sign(signing, new byte[(int) len], 0, RND));
            }
            finally
            {
                ni.disposeSigner(signing);
            }

            long verifying = signer();
            try
            {
                ni.initVerify(verifying, k, new byte[0], 0, MU_EXTERNAL);
                ni.update(verifying, new byte[10], 0, 10);
                assertTyped(IllegalArgumentException.class, "external Mu invalid length",
                        () -> ni.verify(verifying, new byte[1], 1));
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

    @Test
    public void verify_stateAndRangeFaults_rejectedTyped()
    {
        assumeMlDsa();
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
                ni.initSign(signing, k, new byte[0], 0, MU_INTERNAL, RND);
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
                ni.initVerify(verifying, k, new byte[0], 0, MU_INTERNAL);
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
     * The offset-write contract: nothing before {@code outOff} moves, the bytes
     * written verify, and a window one byte early does NOT — which is what
     * catches an off-by-one in the bridge.
     */
    @Test
    public void sign_writesAtOffsetWithoutClobberingThePrefix()
    {
        assumeMlDsa();
        SecureRandom sr = new SecureRandom();
        long k = key();
        long signing = signer();
        long verifying = signer();
        try
        {
            byte[] msg = new byte[64];
            sr.nextBytes(msg);

            ni.initSign(signing, k, new byte[0], 0, MU_INTERNAL, RND);
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
            ni.initVerify(verifying, k, new byte[0], 0, MU_INTERNAL);
            ni.update(verifying, msg, 0, msg.length);
            Assertions.assertEquals(ErrorCode.JO_SUCCESS.getCode(),
                    ni.verify(verifying, written, written.length),
                    "the signature extracted at the offset did not verify");

            // One byte early must NOT verify, or the write could have landed there.
            byte[] shifted = java.util.Arrays.copyOfRange(big, prefix - 1, prefix - 1 + len);
            Assertions.assertFalse(Arrays.areEqual(written, shifted),
                    "the shifted window is identical — the probe cannot discriminate");
            long verifying2 = signer();
            try
            {
                ni.initVerify(verifying2, k, new byte[0], 0, MU_INTERNAL);
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
