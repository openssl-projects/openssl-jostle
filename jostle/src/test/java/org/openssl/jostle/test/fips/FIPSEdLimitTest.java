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

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.ed.EDServiceNI;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.provider.fips.OpenSSLFIPSNI;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.rand.RandSource;
import org.openssl.jostle.test.TestUtil;

import java.security.SecureRandom;

/**
 * Input-validation limit tests at the FIPS EdDSA service NI surface
 * ({@code FIPSNISelector.EDServiceNI}). The FIPS glue is the base
 * {@code ed_jni.c} / {@code ed_ni_ffi.c} re-included under renamed symbols, so
 * the bridge's null / range / negative / type / state checks and their typed
 * messages are identical by construction — this pins that they survived into
 * the FIPS interface library unchanged. Mirrors the base {@code EdDSALimitTest}.
 *
 * <p>Gated twice, and both gates are needed. The class skips when
 * {@code TEST_FIPS_LIB} is unset, and again when the loaded module does not
 * implement the Ed family — 3.1.2 refuses ED25519 and ED448 outright while
 * 3.5.7 serves them (probe: {@code fips-c-review/probes/ed_gate_probe.c}). The
 * second skip is legitimate only because
 * {@code FIPSEdSignatureTest.edServedIffModuleImplementsIt} runs on both
 * modules and pins the absence against the module itself.
 *
 * <p>The {@code RandSource} parameter is still null-checked by the bridge (see
 * {@link #sign_nullRand}), but the FIPS entropy path never consults it — the
 * module's own DRBG serves entropy inside the boundary.
 *
 * <p>Runs under the {@code integrationTest*} tasks. Discipline (testing.md):
 * exact-message assertions, {@code Integer.MIN_VALUE} alongside {@code -1} on
 * every int offset/length, range probes at {@code boundary + 1} with
 * positive-side companions, functional offset-write verification with a
 * shifted-window negative, and the aliased update-then-sign layouts.
 */
public class FIPSEdLimitTest
{
    private static final RandSource RND = TestUtil.RNDSrc;

    /** Resolved in {@code @BeforeAll} AFTER the FIPS-skip assumption. */
    private static EDServiceNI ed;
    private static SpecNI specNI;

    /** Class-wide Ed25519 keypair; allocated in beforeAll, disposed after. */
    private static long keyRef = 0;

    @BeforeAll
    public static void beforeAll()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        TestUtil.addFipsProvider();
        Assumptions.assumeTrue(
                FIPSNISelector.OpenSSLFIPSNI.canFetch(OpenSSLFIPSNI.OP_KEYMGMT, "ED25519") != 0,
                "the loaded FIPS module does not implement Ed25519/Ed448");
        ed = FIPSNISelector.EDServiceNI;
        specNI = FIPSNISelector.SpecNI;
        keyRef = ed.generateKeyPair(OSSLKeyType.ED25519.getKsType(), RND);
        Assertions.assertTrue(keyRef > 0, "could not generate the Ed25519 fixture key");
    }

    @AfterAll
    public static void afterAll()
    {
        if (keyRef != 0)
        {
            specNI.dispose(keyRef);
            keyRef = 0;
        }
    }

    // -----------------------------------------------------------------
    // Native handles: EVERY entry point that takes one must type-check it.
    // A jo_assert here would abort the JVM instead of throwing.
    // -----------------------------------------------------------------

    @Test
    public void nullSignerCtx_allEntryPointsRejectedTyped()
    {
        byte[] sig = new byte[64];
        byte[] ctx = new byte[0];

        assertIAE("signer context is null",
                () -> ed.initSign(0, keyRef, "Ed25519", ctx, 0, RND));
        assertIAE("signer context is null",
                () -> ed.initVerify(0, keyRef, "Ed25519", ctx, 0));
        assertIAE("signer context is null",
                () -> ed.update(0, new byte[8], 0, 8));
        assertIAE("signer context is null",
                () -> ed.sign(0, sig, 0, RND));
        assertIAE("signer context is null",
                () -> ed.verify(0, sig, sig.length));
    }

    @Test
    public void nullKeySpec_rejectedTyped()
    {
        withSigner(ref ->
        {
            assertIAE("key spec is null",
                    () -> ed.initSign(ref, 0, "Ed25519", new byte[0], 0, RND));
            assertIAE("key spec is null",
                    () -> ed.initVerify(ref, 0, "Ed25519", new byte[0], 0));
        });
        assertIAE("key spec is null", () -> ed.getPublicKey(0, null));
        assertIAE("key spec is null", () -> ed.getPrivateKey(0, null));
        assertIAE("key spec is null",
                () -> ed.decode_publicKey(0, OSSLKeyType.ED25519.getKsType(), new byte[32], 0, 32));
        assertIAE("key spec is null",
                () -> ed.decode_privateKey(0, OSSLKeyType.ED25519.getKsType(), new byte[32], 0, 32));
    }

    // -----------------------------------------------------------------
    // Null input arrays. The load succeeds for a null Java array and
    // check_in_range(0, 0, 0) passes, so only an explicit pointer null-check
    // catches this — which is exactly why it needs its own test.
    // -----------------------------------------------------------------

    @Test
    public void nullInputArrays_rejectedTyped()
    {
        withInitedSigner(ref -> assertNPE("input is null", () -> ed.update(ref, null, 0, 0)));

        assertNPE("input is null",
                () -> ed.decode_publicKey(newSpec(), OSSLKeyType.ED25519.getKsType(), null, 0, 0));
        assertNPE("input is null",
                () -> ed.decode_privateKey(newSpec(), OSSLKeyType.ED25519.getKsType(), null, 0, 0));
    }

    @Test
    public void verify_nullSignature_rejectedTyped()
    {
        // IllegalArgumentException, not NPE — JO_SIG_IS_NULL's handler arm.
        withInitedVerifier(ref -> assertIAE("sig is null", () -> ed.verify(ref, null, 0)));
    }

    @Test
    public void initSign_nullName_rejectedTyped()
    {
        withSigner(ref ->
        {
            assertNPE("name is null",
                    () -> ed.initSign(ref, keyRef, null, new byte[0], 0, RND));
            assertNPE("name is null",
                    () -> ed.initVerify(ref, keyRef, null, new byte[0], 0));
            // Length 0 is non-null, so it clears the pointer guard and trips
            // the name_len <= 0 check instead — same typed rejection.
            assertNPE("name is null",
                    () -> ed.initSign(ref, keyRef, "", new byte[0], 0, RND));
            assertNPE("name is null",
                    () -> ed.initVerify(ref, keyRef, "", new byte[0], 0));
        });
    }

    @Test
    public void sign_nullRand()
    {
        // IllegalArgumentException, not NPE: JO_RANDOM_IS_NULL maps to the
        // IAE arm of the base error handler, matching the base EdDSALimitTest.
        withSigner(ref -> assertIAE("supplied random source was null",
                () -> ed.initSign(ref, keyRef, "Ed25519", new byte[0], 0, null)));
        withInitedSigner(ref ->
        {
            byte[] out = new byte[64];
            assertIAE("supplied random source was null", () -> ed.sign(ref, out, 0, null));
        });
    }

    // -----------------------------------------------------------------
    // Negative and out-of-range integers on update.
    // -----------------------------------------------------------------

    @Test
    public void update_negativeOffsetAndLength()
    {
        withInitedSigner(ref ->
        {
            byte[] in = new byte[16];
            for (int bad : new int[]{-1, Integer.MIN_VALUE})
            {
                assertIAE("input offset is negative", () -> ed.update(ref, in, bad, 4));
                assertIAE("input len is negative", () -> ed.update(ref, in, 0, bad));
                // Both negative at once. Both bridges check OFFSET first, so
                // that is the message. Pinned because the order is part of what
                // a caller sees, and because JNI and FFI must agree: the FFI
                // side checked LENGTH first until 2026-08-23, so the same input
                // produced different codes from the two bridges.
                assertIAE("input offset is negative", () -> ed.update(ref, in, bad, bad));
            }
        });
    }

    @Test
    public void update_outOfRangeAtBoundaryPlusOne()
    {
        withInitedSigner(ref ->
        {
            byte[] in = new byte[10];
            // len side: 0 + 11 > 10, the smallest rejected length.
            assertIAE("input offset + length is out of range", () -> ed.update(ref, in, 0, 11));
            // offset side: 1 + 10 > 10, the smallest rejected offset for that length.
            assertIAE("input offset + length is out of range", () -> ed.update(ref, in, 1, 10));
            // Positive-side companions: the boundary sits exactly here, and not
            // one value to either side.
            Assertions.assertEquals(ErrorCode.JO_SUCCESS.getCode(), ed.update(ref, in, 0, 10),
                    "offset 0 length 10 must be accepted on a 10-byte array");
            Assertions.assertEquals(ErrorCode.JO_SUCCESS.getCode(), ed.update(ref, in, 10, 0),
                    "offset == length with a zero length must be accepted");
        });
    }

    // -----------------------------------------------------------------
    // Negative and out-of-range integers on sign / verify.
    // -----------------------------------------------------------------

    @Test
    public void sign_negativeOutputOffset()
    {
        withInitedSigner(ref ->
        {
            byte[] out = new byte[128];
            for (int bad : new int[]{-1, Integer.MIN_VALUE})
            {
                assertIAE("output offset is negative", () -> ed.sign(ref, out, bad, RND));
            }
        });
    }

    @Test
    public void sign_outputOffsetPastEnd()
    {
        withInitedSigner(ref ->
        {
            byte[] out = new byte[64];
            assertIAE("output offset + length is out of range", () -> ed.sign(ref, out, 65, RND));
        });
    }

    @Test
    public void verify_negativeAndOutOfRangeSigLength()
    {
        withInitedVerifier(ref ->
        {
            byte[] sig = new byte[64];
            for (int bad : new int[]{-1, Integer.MIN_VALUE})
            {
                assertIAE("sig length is negative", () -> ed.verify(ref, sig, bad));
            }
            // boundary + 1 on a 64-byte array.
            assertIAE("sig out of range", () -> ed.verify(ref, sig, 65));
        });
    }

    // -----------------------------------------------------------------
    // Offset-write contract: the four-step functional check.
    // -----------------------------------------------------------------

    @Test
    public void sign_writesAtOffsetWithoutClobberingPrefix()
    {
        long signRef = 0;
        long verifyRef = 0;
        try
        {
            signRef = ed.allocateSigner();
            verifyRef = ed.allocateSigner();

            byte[] msg = new byte[48];
            new SecureRandom().nextBytes(msg);

            ed.initSign(signRef, keyRef, "Ed25519", null, 0, RND);
            ed.update(signRef, msg, 0, msg.length);
            int needed = ed.sign(signRef, null, 0, RND);
            Assertions.assertTrue(needed > 0, "unexpected probe length " + needed);

            int prefix = 7;
            byte[] big = new byte[needed + prefix];
            new SecureRandom().nextBytes(big);
            byte[] expectedPrefix = new byte[prefix];
            System.arraycopy(big, 0, expectedPrefix, 0, prefix);

            int written = ed.sign(signRef, big, prefix, RND);
            Assertions.assertEquals(needed, written, "unexpected EdDSA signature length");

            // (1) Prefix untouched — compared against the saved random bytes,
            //     not a sentinel (a sentinel has a 1-in-256 false pass rate).
            byte[] actualPrefix = new byte[prefix];
            System.arraycopy(big, 0, actualPrefix, 0, prefix);
            Assertions.assertArrayEquals(expectedPrefix, actualPrefix,
                    "EdDSA sign modified bytes preceding outOff");

            // (2) The window at big[prefix..prefix+written] is the real signature.
            byte[] sig = new byte[written];
            System.arraycopy(big, prefix, sig, 0, written);
            ed.initVerify(verifyRef, keyRef, "Ed25519", null, 0);
            ed.update(verifyRef, msg, 0, msg.length);
            Assertions.assertEquals(ErrorCode.JO_SUCCESS.getCode(),
                    ed.verify(verifyRef, sig, sig.length),
                    "EdDSA signature at offset " + prefix + " did not verify");

            // (3) A window shifted one byte into the prefix must NOT verify —
            //     without this, a bridge that wrote at outOff-1 would still pass.
            byte[] shifted = new byte[written];
            System.arraycopy(big, prefix - 1, shifted, 0, written);
            ed.initVerify(verifyRef, keyRef, "Ed25519", null, 0);
            ed.update(verifyRef, msg, 0, msg.length);
            Assertions.assertEquals(ErrorCode.JO_FAIL.getCode(), ed.verify(verifyRef, shifted, shifted.length),
                    "EdDSA window shifted by 1 verified — the bridge wrote at outOff-1");
        }
        finally
        {
            disposeSigner(signRef);
            disposeSigner(verifyRef);
        }
    }

    // -----------------------------------------------------------------
    // Aliasing: the caller reuses the update-input array as the sign output.
    // A separate-buffer test never exercises this, and it is a real caller
    // pattern (in-place framing, buffer pooling).
    // -----------------------------------------------------------------

    @Test
    public void sign_aliasedAfterConsumedRegion()
    {
        assertAliasedSignVerifies(64, 64);
    }

    @Test
    public void sign_aliasedOverwritingConsumedStart()
    {
        assertAliasedSignVerifies(128, 0);
    }

    @Test
    public void sign_aliasedInsideConsumedRegion()
    {
        assertAliasedSignVerifies(256, 32);
    }

    /**
     * Reference the signature with a SEPARATE output buffer, then repeat the
     * update-then-sign into one oversized buffer at {@code sigOff} and require
     * (1) the written window equals the reference and (2) every byte outside
     * {@code [sigOff, sigOff+len)} is byte-identical to the pre-call snapshot.
     */
    private static void assertAliasedSignVerifies(int msgLen, int sigOff)
    {
        long signRef = 0;
        try
        {
            signRef = ed.allocateSigner();

            byte[] msg = new byte[msgLen];
            new SecureRandom().nextBytes(msg);

            // Reference: separate input and output buffers.
            ed.initSign(signRef, keyRef, "Ed25519", null, 0, RND);
            ed.update(signRef, msg, 0, msg.length);
            int len = ed.sign(signRef, null, 0, RND);
            byte[] reference = new byte[len];
            Assertions.assertEquals(len, ed.sign(signRef, reference, 0, RND));

            // Aliased: msg lives inside a bigger random-filled buffer and the
            // signature lands in that same buffer.
            int pad = 11;
            byte[] buf = new byte[Math.max(msgLen, sigOff + len) + pad];
            new SecureRandom().nextBytes(buf);
            System.arraycopy(msg, 0, buf, 0, msgLen);
            byte[] snapshot = buf.clone();

            ed.initSign(signRef, keyRef, "Ed25519", null, 0, RND);
            ed.update(signRef, buf, 0, msgLen);
            Assertions.assertEquals(len, ed.sign(signRef, buf, sigOff, RND));

            byte[] written = new byte[len];
            System.arraycopy(buf, sigOff, written, 0, len);
            Assertions.assertArrayEquals(reference, written,
                    "aliased sign at offset " + sigOff + " produced a different signature");

            // Whole destination outside the written window is untouched.
            for (int i = 0; i < buf.length; i++)
            {
                if (i >= sigOff && i < sigOff + len)
                {
                    continue;
                }
                Assertions.assertEquals(snapshot[i], buf[i],
                        "aliased sign at offset " + sigOff + " clobbered byte " + i
                                + " (outside [" + sigOff + ", " + (sigOff + len) + "))");
            }
        }
        finally
        {
            disposeSigner(signRef);
        }
    }

    // -----------------------------------------------------------------
    // State machine.
    // -----------------------------------------------------------------

    @Test
    public void update_beforeInit_rejectedTyped()
    {
        withSigner(ref -> assertISE("not initialized", () -> ed.update(ref, new byte[8], 0, 8)));
    }

    @Test
    public void sign_onVerifierRejectedTyped()
    {
        withInitedVerifier(ref ->
                assertISE("unexpected state", () -> ed.sign(ref, new byte[64], 0, RND)));
    }

    @Test
    public void verify_onSignerRejectedTyped()
    {
        withInitedSigner(ref ->
                assertISE("unexpected state", () -> ed.verify(ref, new byte[64], 64)));
    }

    // -----------------------------------------------------------------
    // Key decoding: wrong lengths and wrong types.
    // -----------------------------------------------------------------

    @Test
    public void decode_wrongKeyLength_rejectedTyped()
    {
        // Ed25519 raw keys are 32 bytes; probe exactly one either side.
        for (int len : new int[]{31, 33})
        {
            assertIAE("incorrect public key length",
                    () -> ed.decode_publicKey(newSpec(), OSSLKeyType.ED25519.getKsType(),
                            new byte[len], 0, len));
            assertIAE("incorrect private key length",
                    () -> ed.decode_privateKey(newSpec(), OSSLKeyType.ED25519.getKsType(),
                            new byte[len], 0, len));
        }
    }

    @Test
    public void decode_wrongKeyType_rejectedTyped()
    {
        assertIAE("invalid key type for EDDSA",
                () -> ed.decode_publicKey(newSpec(), OSSLKeyType.RSA.getKsType(), new byte[32], 0, 32));
    }

    @Test
    public void generateKeyPair_wrongKeyType_rejectedTyped()
    {
        assertIAE("invalid key type for EDDSA",
                () -> ed.generateKeyPair(OSSLKeyType.RSA.getKsType(), RND));
    }

    // -----------------------------------------------------------------
    // Fixtures and helpers.
    // -----------------------------------------------------------------

    /** A fresh, empty key spec handle. Leaked deliberately: these are
     *  rejection paths, and the spec is a few bytes each. */
    private static long newSpec()
    {
        return specNI.allocate();
    }

    private interface RefAction
    {
        void run(long ref);
    }

    private static void withSigner(RefAction action)
    {
        long ref = 0;
        try
        {
            ref = ed.allocateSigner();
            Assertions.assertTrue(ref > 0);
            action.run(ref);
        }
        finally
        {
            disposeSigner(ref);
        }
    }

    private static void withInitedSigner(RefAction action)
    {
        withSigner(ref ->
        {
            ed.initSign(ref, keyRef, "Ed25519", null, 0, RND);
            action.run(ref);
        });
    }

    private static void withInitedVerifier(RefAction action)
    {
        withSigner(ref ->
        {
            ed.initVerify(ref, keyRef, "Ed25519", null, 0);
            action.run(ref);
        });
    }

    private static void disposeSigner(long ref)
    {
        if (ref != 0)
        {
            ed.disposeSigner(ref);
        }
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
