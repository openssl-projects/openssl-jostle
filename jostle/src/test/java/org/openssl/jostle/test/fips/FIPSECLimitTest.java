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
import org.openssl.jostle.jcajce.provider.ec.ECServiceNI;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.rand.RandSource;
import org.openssl.jostle.test.TestUtil;

import java.security.SecureRandom;

/**
 * Input-validation limit tests at the FIPS EC service NI surface
 * ({@link FIPSNISelector#ECServiceNI}). The FIPS JNI glue is the base
 * ec_ni_jni.c re-included under renamed symbols, so the bridge's null / range /
 * negative / state checks and typed-error mapping are identical by construction
 * — this pins that they survived into the FIPS interface library with the same
 * messages. Mirrors the base {@code ECLimitTest}.
 *
 * <p>FIPS notes: all curve work uses P-256 (fips=yes approved). The
 * {@code RandSource} parameter is still null-checked by the bridge on every
 * entry point that takes one (see the null-rand tests), but the FIPS entropy
 * path never consults it — the module's own DRBG serves entropy inside the
 * boundary; {@link TestUtil#RNDSrc} is supplied only to satisfy that
 * null-check.
 *
 * <p>Runs under the {@code integrationTest*} tasks; gated on
 * {@code TEST_FIPS_LIB} (whole class skips when unset). Discipline (testing.md):
 * exact-message assertions, {@code Integer.MIN_VALUE} alongside {@code -1} on
 * int offsets/lengths, range checks at {@code boundary + 1}, and functional
 * offset-write verification (prefix untouched, output verifies, shifted-window
 * does not).
 */
public class FIPSECLimitTest
{
    private static final RandSource RND = TestUtil.RNDSrc;
    private static final String CURVE = "P-256";
    private static final String DIGEST = "SHA-256";

    @BeforeAll
    public static void beforeAll()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        TestUtil.addFipsProvider();
    }

    private final ECServiceNI ec = FIPSNISelector.ECServiceNI;
    private final SpecNI specNI = FIPSNISelector.SpecNI;

    // -----------------------------------------------------------------
    // curveSupported / generateKeyPair
    // -----------------------------------------------------------------

    @Test
    public void curveSupported_nullName()
    {
        // Boolean wrapper must return false for null — must NOT throw.
        Assertions.assertFalse(ec.curveSupported(null));
    }

    @Test
    public void ni_curveSupported_nullName_returnsTypedCode()
    {
        Assertions.assertEquals(ErrorCode.JO_NAME_IS_NULL.getCode(),
                ec.ni_curveSupported(null));
    }

    @Test
    public void ni_curveSupported_unknownCurve_returnsCurveNotSupported()
    {
        Assertions.assertEquals(ErrorCode.JO_CURVE_NOT_SUPPORTED.getCode(),
                ec.ni_curveSupported("definitely-not-a-real-curve"));
        Assertions.assertFalse(ec.curveSupported("definitely-not-a-real-curve"));
    }

    @Test
    public void ni_curveSupported_knownCurve_returns1()
    {
        // P-256 is fips=yes approved on the 3.1.2 module.
        Assertions.assertEquals(1, ec.ni_curveSupported(CURVE));
    }

    @Test
    public void generateKeyPair_nullCurveName()
    {
        assertNPE("name is null", () -> ec.generateKeyPair(null, RND));
    }

    @Test
    public void generateKeyPair_nullRand()
    {
        assertIAE("supplied random source was null", () -> ec.generateKeyPair(CURVE, null));
    }

    // -----------------------------------------------------------------
    // makePrivateFromComponents
    // -----------------------------------------------------------------

    @Test
    public void makePrivateFromComponents_nullCurveName()
    {
        assertNPE("name is null",
                () -> ec.makePrivateFromComponents(null, new byte[]{0x01, 0x02}, RND));
    }

    @Test
    public void makePrivateFromComponents_nullScalar()
    {
        assertNPE("input is null",
                () -> ec.makePrivateFromComponents(CURVE, null, RND));
    }

    @Test
    public void makePrivateFromComponents_nullRand()
    {
        assertIAE("supplied random source was null",
                () -> ec.makePrivateFromComponents(CURVE, new byte[]{0x01, 0x02}, null));
    }

    // -----------------------------------------------------------------
    // getComponent
    // -----------------------------------------------------------------

    @Test
    public void getComponent_nullSpec()
    {
        assertIAE("key spec is null",
                () -> ec.getComponent(0L, ECServiceNI.COMP_PUBLIC_X, new byte[64]));
    }

    @Test
    public void getComponent_invalidSelector()
    {
        // Any selector outside {0,1,2,3} → typed JO_UNEXPECTED_STATE, surfaced
        // by the error handler as IllegalStateException("unexpected state").
        long keyRef = genKey();
        try
        {
            assertISE("unexpected state",
                    () -> ec.getComponent(keyRef, 999, new byte[64]));
        }
        finally
        {
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void getComponent_outputTooSmall()
    {
        long keyRef = genKey();
        try
        {
            // Probe relative to the real length: a BIGNUM's minimal encoding is
            // shorter when the top byte happens to be zero (~1 key in 256), so
            // a hardcoded 31 would occasionally be large enough and flake.
            int actualLen = ec.getComponent(keyRef, ECServiceNI.COMP_PUBLIC_X, new byte[64]);
            assertIAE("output too small",
                    () -> ec.getComponent(keyRef, ECServiceNI.COMP_PUBLIC_X, new byte[actualLen - 1]));
        }
        finally
        {
            specNI.dispose(keyRef);
        }
    }

    // -----------------------------------------------------------------
    // Null native-context handle (0L for signer / kex ref). Bridge must
    // surface IllegalArgumentException, never abort via jo_assert.
    // -----------------------------------------------------------------

    @Test
    public void initSign_nullSignerCtx()
    {
        withKey(keyRef -> assertIAE("signer context is null",
                () -> ec.initSign(0L, keyRef, DIGEST, RND)));
    }

    @Test
    public void initVerify_nullSignerCtx()
    {
        withKey(keyRef -> assertIAE("signer context is null",
                () -> ec.initVerify(0L, keyRef, DIGEST)));
    }

    @Test
    public void update_nullSignerCtx()
    {
        assertIAE("signer context is null",
                () -> ec.update(0L, new byte[]{0x01}, 0, 1));
    }

    @Test
    public void sign_nullSignerCtx()
    {
        assertIAE("signer context is null",
                () -> ec.sign(0L, new byte[64], 0, RND));
    }

    @Test
    public void verify_nullSignerCtx()
    {
        assertIAE("signer context is null",
                () -> ec.verify(0L, new byte[64], 64, RND));
    }

    @Test
    public void kexInit_nullKexCtx()
    {
        withKey(keyRef -> assertIAE("key-agreement context is null",
                () -> ec.kexInit(0L, keyRef, RND)));
    }

    @Test
    public void kexSetPeer_nullKexCtx()
    {
        withKey(peerRef -> assertIAE("key-agreement context is null",
                () -> ec.kexSetPeer(0L, peerRef, RND)));
    }

    @Test
    public void kexDerive_nullKexCtx()
    {
        assertIAE("key-agreement context is null",
                () -> ec.kexDerive(0L, new byte[64], 0, RND));
    }

    // -----------------------------------------------------------------
    // Sign / verify session — pre-init (null spec / digest / rand)
    // -----------------------------------------------------------------

    @Test
    public void initSign_nullKeyRef()
    {
        withSigner(ref -> assertIAE("key spec is null",
                () -> ec.initSign(ref, 0L, DIGEST, RND)));
    }

    @Test
    public void initSign_nullDigestName()
    {
        withSignerAndKey((ref, keyRef) -> assertNPE("name is null",
                () -> ec.initSign(ref, keyRef, null, RND)));
    }

    @Test
    public void initSign_nullRand()
    {
        withSignerAndKey((ref, keyRef) -> assertIAE("supplied random source was null",
                () -> ec.initSign(ref, keyRef, DIGEST, null)));
    }

    @Test
    public void initVerify_nullKeyRef()
    {
        withSigner(ref -> assertIAE("key spec is null",
                () -> ec.initVerify(ref, 0L, DIGEST)));
    }

    @Test
    public void initVerify_nullDigestName()
    {
        withSignerAndKey((ref, keyRef) -> assertNPE("name is null",
                () -> ec.initVerify(ref, keyRef, null)));
    }

    // -----------------------------------------------------------------
    // ec_ctx state-machine guards (pre-init, opp mismatch)
    // -----------------------------------------------------------------

    @Test
    public void update_beforeInit_isNotInitialized()
    {
        withSigner(ref -> assertISE("not initialized",
                () -> ec.update(ref, new byte[]{0x01}, 0, 1)));
    }

    @Test
    public void sign_beforeInit_isNotInitialized()
    {
        withSigner(ref -> assertISE("not initialized",
                () -> ec.sign(ref, new byte[128], 0, RND)));
    }

    @Test
    public void verify_beforeInit_isNotInitialized()
    {
        withSigner(ref -> assertISE("not initialized",
                () -> ec.verify(ref, new byte[64], 64, RND)));
    }

    @Test
    public void sign_afterInitVerify_isUnexpectedState()
    {
        // Init for verify, then call sign — ec_ctx_sign rejects with
        // JO_UNEXPECTED_STATE because ctx->opp != EC_OP_SIGN.
        withSignerAndKey((ref, keyRef) ->
        {
            ec.initVerify(ref, keyRef, DIGEST);
            ec.update(ref, new byte[]{0x01}, 0, 1);
            assertISE("unexpected state", () -> ec.sign(ref, new byte[128], 0, RND));
        });
    }

    @Test
    public void verify_afterInitSign_isUnexpectedState()
    {
        withSignerAndKey((ref, keyRef) ->
        {
            ec.initSign(ref, keyRef, DIGEST, RND);
            ec.update(ref, new byte[]{0x01}, 0, 1);
            assertISE("unexpected state", () -> ec.verify(ref, new byte[64], 64, RND));
        });
    }

    // -----------------------------------------------------------------
    // update — null / negative / out-of-range (MIN_VALUE + boundary+1)
    // -----------------------------------------------------------------

    @Test
    public void update_nullInput()
    {
        withInitedSigner((ref, keyRef) -> assertNPE("input is null",
                () -> ec.update(ref, null, 0, 0)));
    }

    @Test
    public void update_negativeOffset()
    {
        withInitedSigner((ref, keyRef) ->
        {
            for (int off : new int[]{-1, Integer.MIN_VALUE})
            {
                assertIAE("input offset is negative",
                        () -> ec.update(ref, new byte[16], off, 0));
            }
        });
    }

    @Test
    public void update_negativeLen()
    {
        withInitedSigner((ref, keyRef) ->
        {
            for (int len : new int[]{-1, Integer.MIN_VALUE})
            {
                assertIAE("input len is negative",
                        () -> ec.update(ref, new byte[16], 0, len));
            }
        });
    }

    @Test
    public void update_negativeOffsetWithValidLen()
    {
        // Negative off + valid len: only an explicit off<0 guard catches this.
        withInitedSigner((ref, keyRef) -> assertIAE("input offset is negative",
                () -> ec.update(ref, new byte[16], -1, 8)));
    }

    @Test
    public void update_offsetPlusLenOutOfRange()
    {
        // Boundary probe: off + len = 1 + 16 > 16, and 0 + 17 > 16.
        withInitedSigner((ref, keyRef) ->
        {
            assertIAE("input offset + length is out of range",
                    () -> ec.update(ref, new byte[16], 1, 16));
            assertIAE("input offset + length is out of range",
                    () -> ec.update(ref, new byte[16], 0, 17));
        });
    }

    // -----------------------------------------------------------------
    // sign — null rand / negative offset / out-of-range (MIN_VALUE + boundary+1)
    // -----------------------------------------------------------------

    @Test
    public void sign_nullRand()
    {
        withInitedSigner((ref, keyRef) ->
        {
            ec.update(ref, new byte[]{0x01, 0x02, 0x03}, 0, 3);
            assertIAE("supplied random source was null",
                    () -> ec.sign(ref, new byte[128], 0, null));
        });
    }

    @Test
    public void sign_negativeOffset()
    {
        withInitedSigner((ref, keyRef) ->
        {
            ec.update(ref, new byte[]{0x01}, 0, 1);
            for (int off : new int[]{-1, Integer.MIN_VALUE})
            {
                assertIAE("output offset is negative",
                        () -> ec.sign(ref, new byte[128], off, RND));
            }
        });
    }

    @Test
    public void sign_offsetPastEnd()
    {
        // Boundary probe: out_off = size + 1 is the smallest value past the end.
        withInitedSigner((ref, keyRef) ->
        {
            ec.update(ref, new byte[]{0x01}, 0, 1);
            assertIAE("output offset + length is out of range",
                    () -> ec.sign(ref, new byte[128], 129, RND));
        });
    }

    // -----------------------------------------------------------------
    // verify — null rand / null sig / negative len / out-of-range
    // -----------------------------------------------------------------

    @Test
    public void verify_nullRand()
    {
        withInitedVerifier((ref, keyRef) ->
        {
            ec.update(ref, new byte[]{0x01}, 0, 1);
            assertIAE("supplied random source was null",
                    () -> ec.verify(ref, new byte[64], 64, null));
        });
    }

    @Test
    public void verify_nullSig()
    {
        withInitedVerifier((ref, keyRef) ->
        {
            ec.update(ref, new byte[]{0x01}, 0, 1);
            assertIAE("sig is null", () -> ec.verify(ref, null, 0, RND));
        });
    }

    @Test
    public void verify_negativeLen()
    {
        withInitedVerifier((ref, keyRef) ->
        {
            ec.update(ref, new byte[]{0x01}, 0, 1);
            for (int len : new int[]{-1, Integer.MIN_VALUE})
            {
                assertIAE("sig length is negative",
                        () -> ec.verify(ref, new byte[64], len, RND));
            }
        });
    }

    @Test
    public void verify_lenOutOfRange()
    {
        // Boundary probe: sig_len = 17 is the smallest value past the 16-byte buffer.
        withInitedVerifier((ref, keyRef) ->
        {
            ec.update(ref, new byte[]{0x01}, 0, 1);
            assertIAE("sig out of range", () -> ec.verify(ref, new byte[16], 17, RND));
        });
    }

    // -----------------------------------------------------------------
    // Key agreement (kex) — null spec / null rand / state
    // -----------------------------------------------------------------

    @Test
    public void kexInit_nullKeyRef()
    {
        withKex(ref -> assertIAE("key spec is null",
                () -> ec.kexInit(ref, 0L, RND)));
    }

    @Test
    public void kexInit_nullRand()
    {
        withKexAndKey((ref, keyRef) -> assertIAE("supplied random source was null",
                () -> ec.kexInit(ref, keyRef, null)));
    }

    @Test
    public void kexSetPeer_nullPeerRef()
    {
        withKexAndKey((ref, keyRef) ->
        {
            ec.kexInit(ref, keyRef, RND);
            assertIAE("key spec is null", () -> ec.kexSetPeer(ref, 0L, RND));
        });
    }

    @Test
    public void kexSetPeer_nullRand()
    {
        withKexAndKey((ref, keyRef) ->
        {
            long peerRef = genKey();
            try
            {
                ec.kexInit(ref, keyRef, RND);
                // RAND is required even on set_peer because binary-field
                // curves trigger an internal EVP_PKEY_public_check.
                assertIAE("supplied random source was null",
                        () -> ec.kexSetPeer(ref, peerRef, null));
            }
            finally
            {
                specNI.dispose(peerRef);
            }
        });
    }

    @Test
    public void kexSetPeer_beforeInit_isNotInitialized()
    {
        withKexAndKey((ref, keyRef) ->
        {
            // No kexInit beforehand — set_peer must surface "not initialized".
            assertISE("not initialized", () -> ec.kexSetPeer(ref, keyRef, RND));
        });
    }

    @Test
    public void kexDerive_nullRand()
    {
        withKexAndKey((ref, keyRef) ->
        {
            long peerRef = genKey();
            try
            {
                ec.kexInit(ref, keyRef, RND);
                ec.kexSetPeer(ref, peerRef, RND);
                assertIAE("supplied random source was null",
                        () -> ec.kexDerive(ref, new byte[64], 0, null));
            }
            finally
            {
                specNI.dispose(peerRef);
            }
        });
    }

    @Test
    public void kexDerive_negativeOffset()
    {
        withKexAndKey((ref, keyRef) ->
        {
            long peerRef = genKey();
            try
            {
                ec.kexInit(ref, keyRef, RND);
                ec.kexSetPeer(ref, peerRef, RND);
                for (int off : new int[]{-1, Integer.MIN_VALUE})
                {
                    assertIAE("output offset is negative",
                            () -> ec.kexDerive(ref, new byte[64], off, RND));
                }
            }
            finally
            {
                specNI.dispose(peerRef);
            }
        });
    }

    @Test
    public void kexDerive_offsetPastEnd()
    {
        withKexAndKey((ref, keyRef) ->
        {
            long peerRef = genKey();
            try
            {
                ec.kexInit(ref, keyRef, RND);
                ec.kexSetPeer(ref, peerRef, RND);
                // Boundary probe: out_off = 65 is the smallest value past the
                // 64-byte buffer.
                assertIAE("output offset + length is out of range",
                        () -> ec.kexDerive(ref, new byte[64], 65, RND));
            }
            finally
            {
                specNI.dispose(peerRef);
            }
        });
    }

    @Test
    public void kexDerive_beforeSetPeer_isUnexpectedState()
    {
        withKexAndKey((ref, keyRef) ->
        {
            ec.kexInit(ref, keyRef, RND);
            // No kexSetPeer — derive must reject as "unexpected state".
            assertISE("unexpected state", () -> ec.kexDerive(ref, new byte[64], 0, RND));
        });
    }

    // -----------------------------------------------------------------
    // Functional offset-write contract (SHA-256 ECDSA path).
    //
    // Base ECLimitTest uses the RAW ("NONE") ECDSA branch; this exercises the
    // hashed SHA-256 path instead. The bridge offset / length arithmetic under
    // test is digest-independent (shared C for both branches), so the contract
    // is the same. ECDSA DER length is variable: the probe returns an upper
    // bound. (The raw branch is approved under cert #4985 — see the
    // NoneWithECDSA registration in ProvFIPSEC — so this is now a coverage
    // choice, not a restriction.)
    // -----------------------------------------------------------------

    @Test
    public void sign_writesAtOffsetWithoutClobberingPrefix() throws Exception
    {
        long signRef = 0;
        long verifyRef = 0;
        long keyRef = 0;
        try
        {
            signRef = ec.allocateSigner();
            verifyRef = ec.allocateSigner();
            keyRef = genKey();

            byte[] msg = new byte[48];
            new SecureRandom().nextBytes(msg);

            ec.initSign(signRef, keyRef, DIGEST, RND);
            ec.update(signRef, msg, 0, msg.length);
            int needed = ec.sign(signRef, null, 0, RND);
            Assertions.assertTrue(needed > 0, "unexpected probe length " + needed);

            int prefix = 7;
            byte[] big = new byte[needed + prefix];
            new SecureRandom().nextBytes(big);
            byte[] expectedPrefix = new byte[prefix];
            System.arraycopy(big, 0, expectedPrefix, 0, prefix);

            int written = ec.sign(signRef, big, prefix, RND);
            Assertions.assertTrue(written > 0 && written <= needed,
                    "unexpected ECDSA DER length " + written);

            // (1) Prefix untouched.
            byte[] actualPrefix = new byte[prefix];
            System.arraycopy(big, 0, actualPrefix, 0, prefix);
            Assertions.assertArrayEquals(expectedPrefix, actualPrefix,
                    "ECDSA sign modified bytes preceding outOff");

            // (2) The signature window at big[prefix..prefix+written] verifies.
            byte[] sig = new byte[written];
            System.arraycopy(big, prefix, sig, 0, written);
            ec.initVerify(verifyRef, keyRef, DIGEST);
            ec.update(verifyRef, msg, 0, msg.length);
            Assertions.assertEquals(ErrorCode.JO_SUCCESS.getCode(),
                    ec.verify(verifyRef, sig, sig.length, RND),
                    "ECDSA signature at offset " + prefix + " did not verify");

            // (3) A window shifted one byte into the prefix must NOT verify.
            byte[] shifted = new byte[written];
            System.arraycopy(big, prefix - 1, shifted, 0, written);
            ec.initVerify(verifyRef, keyRef, DIGEST);
            ec.update(verifyRef, msg, 0, msg.length);
            Assertions.assertEquals(ErrorCode.JO_FAIL.getCode(), safeVerify(verifyRef, shifted),
                    "ECDSA window shifted by 1 verified — wrote at outOff-1");
        }
        finally
        {
            if (signRef != 0)
            {
                ec.disposeSigner(signRef);
            }
            if (verifyRef != 0)
            {
                ec.disposeSigner(verifyRef);
            }
            if (keyRef != 0)
            {
                specNI.dispose(keyRef);
            }
        }
    }

    // -----------------------------------------------------------------
    // Aliased-buffer signing (testing.md). ECDSA has no single in->out
    // transform (update only reads, sign only writes), so the meaningful
    // aliased case is a caller reusing the update-input (message) array as the
    // sign-output array — appending the signature past the message, or
    // overwriting the already-consumed message with its signature. ECDSA's DER
    // signature is variable-length and randomised, so correctness is checked by
    // VERIFYING the aliased signature against the original message (not a
    // byte-compare to a reference), and every byte of the destination outside
    // the signature region must be untouched.
    // -----------------------------------------------------------------

    @Test
    public void sign_aliased_sigAfterMessage()
    {
        assertAliasedSignVerifies(40, 40);
    }

    @Test
    public void sign_aliased_sigOverwritesMessageStart()
    {
        assertAliasedSignVerifies(40, 0);
    }

    @Test
    public void sign_aliased_sigMidMessage()
    {
        assertAliasedSignVerifies(64, 16);
    }

    private void assertAliasedSignVerifies(int msgLen, int sigOff)
    {
        long signRef = 0;
        long verifyRef = 0;
        long keyRef = 0;
        try
        {
            signRef = ec.allocateSigner();
            verifyRef = ec.allocateSigner();
            keyRef = genKey();

            byte[] msg = new byte[msgLen];
            new SecureRandom().nextBytes(msg);

            // Probe the signature length via a separate buffer.
            ec.initSign(signRef, keyRef, DIGEST, RND);
            ec.update(signRef, msg, 0, msg.length);
            int needed = ec.sign(signRef, null, 0, RND);

            int cap = Math.max(msgLen, sigOff + needed) + 8;
            byte[] buf = new byte[cap];
            new SecureRandom().nextBytes(buf);
            System.arraycopy(msg, 0, buf, 0, msgLen);
            byte[] snapshot = buf.clone();

            // Sign in place: update reads buf[0..msgLen), sign writes into the
            // SAME buf at sigOff.
            ec.initSign(signRef, keyRef, DIGEST, RND);
            ec.update(signRef, buf, 0, msgLen);
            int written = ec.sign(signRef, buf, sigOff, RND);
            String where = "msgLen=" + msgLen + " sigOff=" + sigOff;
            Assertions.assertTrue(written > 0 && written <= needed, where + " unexpected DER length " + written);

            // (1) The aliased signature verifies against the original message.
            byte[] sig = new byte[written];
            System.arraycopy(buf, sigOff, sig, 0, written);
            ec.initVerify(verifyRef, keyRef, DIGEST);
            ec.update(verifyRef, msg, 0, msg.length);
            Assertions.assertEquals(ErrorCode.JO_SUCCESS.getCode(),
                    ec.verify(verifyRef, sig, sig.length, RND),
                    where + ": aliased signature did not verify");

            // (2) WHOLE destination: everything outside the signature region is
            //     byte-identical to the pre-call snapshot.
            byte[] preExpected = new byte[sigOff];
            byte[] preActual = new byte[sigOff];
            System.arraycopy(snapshot, 0, preExpected, 0, sigOff);
            System.arraycopy(buf, 0, preActual, 0, sigOff);
            Assertions.assertArrayEquals(preExpected, preActual, where + ": bytes before sigOff were clobbered");

            int tail = cap - (sigOff + written);
            byte[] postExpected = new byte[tail];
            byte[] postActual = new byte[tail];
            System.arraycopy(snapshot, sigOff + written, postExpected, 0, tail);
            System.arraycopy(buf, sigOff + written, postActual, 0, tail);
            Assertions.assertArrayEquals(postExpected, postActual, where + ": bytes after the signature were clobbered");
        }
        finally
        {
            if (signRef != 0)
            {
                ec.disposeSigner(signRef);
            }
            if (verifyRef != 0)
            {
                ec.disposeSigner(verifyRef);
            }
            if (keyRef != 0)
            {
                specNI.dispose(keyRef);
            }
        }
    }

    // -----------------------------------------------------------------
    // helpers
    // -----------------------------------------------------------------

    private int safeVerify(long verifyRef, byte[] sig)
    {
        // A malformed signature may return JO_FAIL or surface a structural
        // OpenSSL error; both are correct rejections.
        try
        {
            return ec.verify(verifyRef, sig, sig.length, RND);
        }
        catch (Exception expected)
        {
            return ErrorCode.JO_FAIL.getCode();
        }
    }

    private long genKey()
    {
        long keyRef = ec.generateKeyPair(CURVE, RND);
        Assertions.assertTrue(keyRef > 0);
        return keyRef;
    }

    private interface SpecBody
    {
        void run(long ref) throws Exception;
    }

    private interface PairBody
    {
        void run(long ref, long keyRef) throws Exception;
    }

    private void withSigner(SpecBody body)
    {
        long ref = ec.allocateSigner();
        try
        {
            body.run(ref);
        }
        catch (Exception e)
        {
            rethrow(e);
        }
        finally
        {
            ec.disposeSigner(ref);
        }
    }

    private void withKey(SpecBody body)
    {
        long keyRef = genKey();
        try
        {
            body.run(keyRef);
        }
        catch (Exception e)
        {
            rethrow(e);
        }
        finally
        {
            specNI.dispose(keyRef);
        }
    }

    private void withSignerAndKey(PairBody body)
    {
        long ref = ec.allocateSigner();
        long keyRef = genKey();
        try
        {
            body.run(ref, keyRef);
        }
        catch (Exception e)
        {
            rethrow(e);
        }
        finally
        {
            ec.disposeSigner(ref);
            specNI.dispose(keyRef);
        }
    }

    private void withInitedSigner(PairBody body)
    {
        withSignerAndKey((ref, keyRef) ->
        {
            ec.initSign(ref, keyRef, DIGEST, RND);
            body.run(ref, keyRef);
        });
    }

    private void withInitedVerifier(PairBody body)
    {
        withSignerAndKey((ref, keyRef) ->
        {
            ec.initVerify(ref, keyRef, DIGEST);
            body.run(ref, keyRef);
        });
    }

    private void withKex(SpecBody body)
    {
        long ref = ec.allocateKex();
        try
        {
            body.run(ref);
        }
        catch (Exception e)
        {
            rethrow(e);
        }
        finally
        {
            ec.disposeKex(ref);
        }
    }

    private void withKexAndKey(PairBody body)
    {
        long ref = ec.allocateKex();
        long keyRef = genKey();
        try
        {
            body.run(ref, keyRef);
        }
        catch (Exception e)
        {
            rethrow(e);
        }
        finally
        {
            ec.disposeKex(ref);
            specNI.dispose(keyRef);
        }
    }

    private static void rethrow(Exception e)
    {
        if (e instanceof RuntimeException)
        {
            throw (RuntimeException) e;
        }
        throw new RuntimeException(e);
    }

    private static void assertIAE(String message, Executable action)
    {
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class, action);
        Assertions.assertEquals(message, e.getMessage());
    }

    private static void assertNPE(String message, Executable action)
    {
        NullPointerException e = Assertions.assertThrows(NullPointerException.class, action);
        Assertions.assertEquals(message, e.getMessage());
    }

    private static void assertISE(String message, Executable action)
    {
        IllegalStateException e = Assertions.assertThrows(IllegalStateException.class, action);
        Assertions.assertEquals(message, e.getMessage());
    }
}
