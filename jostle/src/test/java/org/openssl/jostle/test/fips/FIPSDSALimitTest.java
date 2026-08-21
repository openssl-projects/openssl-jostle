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
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.dsa.DSAServiceNI;
import org.openssl.jostle.jcajce.provider.ec.ECServiceNI;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.rand.RandSource;
import org.openssl.jostle.test.TestUtil;

import java.security.SecureRandom;

/**
 * Input-validation limit tests at the FIPS DSA service NI surface
 * ({@link FIPSNISelector#DSAServiceNI}). The FIPS JNI glue is the base
 * dsa_ni_jni.c re-included under renamed symbols, so the bridge's null / range /
 * negative / type / state checks and typed-error mapping are identical by
 * construction — this pins that they survived into the FIPS interface library
 * with the same messages. Mirrors the base {@code DSALimitTest}.
 *
 * <p>FIPS divergences from the base test:
 * <ol>
 *   <li>Domain parameters are <b>2048/256</b> — FIPS 186-4 approved sizes; the
 *       base 1024/160 is rejected by the module. Generated once for the class
 *       (paramgen is a prime search) and disposed in {@code @AfterAll}.</li>
 *   <li>The offset-write functional test uses the <b>SHA-256</b> path (the
 *       raw {@code NoneWithDSA} branch the base uses is exercised only for the
 *       bridge offset arithmetic, which is digest-independent).</li>
 * </ol>
 * The {@code RandSource} parameter is still null-checked by the bridge (see the
 * null-rand tests), but the FIPS entropy path never consults it — the module's
 * own DRBG serves entropy inside the boundary.
 *
 * <p>Runs under the {@code integrationTest*} tasks; gated on
 * {@code TEST_FIPS_LIB} (whole class skips when unset). Discipline (testing.md):
 * exact-message assertions, {@code Integer.MIN_VALUE} alongside {@code -1} on
 * int offsets/lengths, range checks at {@code boundary + 1}, and functional
 * offset-write verification.
 */
public class FIPSDSALimitTest
{
    private static final RandSource RND = TestUtil.RNDSrc;
    private static final String DIGEST = "SHA-256";

    /** Resolved in {@code @BeforeAll} AFTER the FIPS-skip assumption. */
    private static DSAServiceNI dsa;
    private static SpecNI specNI;

    /** Class-wide 2048/256 domain parameters; allocated in beforeAll. */
    private static long paramsRef = 0;
    /** Class-wide keypair generated on paramsRef. */
    private static long keyRef = 0;

    @BeforeAll
    public static void beforeAll() throws Exception
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        TestUtil.addFipsProvider();
        dsa = FIPSNISelector.DSAServiceNI;
        specNI = FIPSNISelector.SpecNI;
        // Imported, not generated: OpenSSL's 3.5.x FIPS module refuses both
        // generateParameters and generateKeyPair while still importing keys and
        // verifying, so a generated fixture would make this whole class
        // unrunnable there. The handles are equivalent either way — the bridge
        // validation these tests exercise is downstream of how the key arrived.
        long[] handles = FIPSTestUtil.dsaNiHandles(dsa, RND);
        paramsRef = handles[0];
        keyRef = handles[1];
    }

    @AfterAll
    public static void afterAll()
    {
        if (keyRef != 0)
        {
            specNI.dispose(keyRef);
            keyRef = 0;
        }
        if (paramsRef != 0)
        {
            specNI.dispose(paramsRef);
            paramsRef = 0;
        }
    }

    // -----------------------------------------------------------------
    // generateParameters
    // -----------------------------------------------------------------

    @Test
    public void generateParameters_zeroPBits()
    {
        // Boundary probe: 0 is the largest non-positive value.
        assertIAE("DSA parameter bit size out of range",
                () -> dsa.generateParameters(0, 256, RND));
    }

    @Test
    public void generateParameters_negativePBits()
    {
        for (int bits : new int[]{-1, Integer.MIN_VALUE})
        {
            assertIAE("DSA parameter bit size out of range",
                    () -> dsa.generateParameters(bits, 256, RND));
        }
    }

    @Test
    public void generateParameters_zeroOrNegativeQBits()
    {
        for (int bits : new int[]{0, -1, Integer.MIN_VALUE})
        {
            assertIAE("DSA parameter bit size out of range",
                    () -> dsa.generateParameters(2048, bits, RND));
        }
    }

    @Test
    public void generateParameters_nullRand()
    {
        assertIAE("supplied random source was null",
                () -> dsa.generateParameters(2048, 256, null));
    }

    // -----------------------------------------------------------------
    // makeParamsFromComponents
    // -----------------------------------------------------------------

    @Test
    public void makeParamsFromComponents_nullComponent()
    {
        byte[] ok = {0x07};
        byte[][][] combos = {
                {null, ok, ok},
                {ok, null, ok},
                {ok, ok, null},
        };
        for (byte[][] c : combos)
        {
            assertNPE("input is null", () -> dsa.makeParamsFromComponents(c[0], c[1], c[2]));
        }
    }

    @Test
    public void makeParamsFromComponents_emptyComponent()
    {
        byte[] ok = {0x07};
        byte[] empty = new byte[0];
        byte[][][] combos = {
                {empty, ok, ok},
                {ok, empty, ok},
                {ok, ok, empty},
        };
        for (byte[][] c : combos)
        {
            assertIAE("input len is negative", () -> dsa.makeParamsFromComponents(c[0], c[1], c[2]));
        }
    }

    // -----------------------------------------------------------------
    // generateKeyPair
    // -----------------------------------------------------------------

    @Test
    public void generateKeyPair_nullParamsRef()
    {
        assertIAE("key spec is null", () -> dsa.generateKeyPair(0L, RND));
    }

    @Test
    public void generateKeyPair_nullRand()
    {
        assertIAE("supplied random source was null", () -> dsa.generateKeyPair(paramsRef, null));
    }

    @Test
    public void generateKeyPair_wrongKeyType()
    {
        // A non-DSA spec (EC keypair) handed to DSA keygen must be rejected.
        ECServiceNI ec = FIPSNISelector.ECServiceNI;
        long ecRef = 0;
        try
        {
            ecRef = ec.generateKeyPair("P-256", RND);
            final long ref = ecRef;
            assertIAE("invalid key type for DSA", () -> dsa.generateKeyPair(ref, RND));
        }
        finally
        {
            if (ecRef != 0)
            {
                specNI.dispose(ecRef);
            }
        }
    }

    // -----------------------------------------------------------------
    // makePrivateFromComponents / makePublicFromComponents
    // -----------------------------------------------------------------

    @Test
    public void makePrivateFromComponents_nullComponent()
    {
        byte[] ok = {0x07};
        byte[][][] combos = {
                {null, ok, ok, ok},
                {ok, null, ok, ok},
                {ok, ok, null, ok},
                {ok, ok, ok, null},
        };
        for (byte[][] c : combos)
        {
            assertNPE("input is null",
                    () -> dsa.makePrivateFromComponents(c[0], c[1], c[2], c[3], RND));
        }
    }

    @Test
    public void makePrivateFromComponents_emptyComponent()
    {
        byte[] ok = {0x07};
        byte[] empty = new byte[0];
        byte[][][] combos = {
                {empty, ok, ok, ok},
                {ok, empty, ok, ok},
                {ok, ok, empty, ok},
                {ok, ok, ok, empty},
        };
        for (byte[][] c : combos)
        {
            assertIAE("input len is negative",
                    () -> dsa.makePrivateFromComponents(c[0], c[1], c[2], c[3], RND));
        }
    }

    @Test
    public void makePrivateFromComponents_nullRand()
    {
        byte[] ok = {0x07};
        assertIAE("supplied random source was null",
                () -> dsa.makePrivateFromComponents(ok, ok, ok, ok, null));
    }

    @Test
    public void makePublicFromComponents_nullComponent()
    {
        byte[] ok = {0x07};
        byte[][][] combos = {
                {null, ok, ok, ok},
                {ok, null, ok, ok},
                {ok, ok, null, ok},
                {ok, ok, ok, null},
        };
        for (byte[][] c : combos)
        {
            assertNPE("input is null",
                    () -> dsa.makePublicFromComponents(c[0], c[1], c[2], c[3]));
        }
    }

    @Test
    public void makePublicFromComponents_emptyComponent()
    {
        byte[] ok = {0x07};
        byte[] empty = new byte[0];
        assertIAE("input len is negative",
                () -> dsa.makePublicFromComponents(ok, ok, ok, empty));
    }

    // -----------------------------------------------------------------
    // getComponent
    // -----------------------------------------------------------------

    @Test
    public void getComponent_nullSpec()
    {
        assertIAE("key spec is null",
                () -> dsa.getComponent(0L, DSAServiceNI.COMP_P, new byte[128]));
    }

    @Test
    public void getComponent_invalidSelector()
    {
        // Any selector outside {0..4} → JO_FAIL → IllegalStateException.
        assertISE("unexpected error code JO_FAIL: -1",
                () -> dsa.getComponent(keyRef, 999, new byte[128]));
    }

    @Test
    public void getComponent_outputTooSmall()
    {
        // Boundary probe: q for the 2048/256 parameters is exactly 32 bytes
        // (an N-bit prime has its MSB set), so 31 is the largest rejected size.
        assertIAE("output too small",
                () -> dsa.getComponent(keyRef, DSAServiceNI.COMP_Q, new byte[31]));
    }

    @Test
    public void getComponent_privateValueAbsentOnPublicKey()
    {
        // A public-only spec has no x — OpenSSL's get_bn_param fails and
        // surfaces as a real OpenSSL error (prefix-match: queue detail is
        // volatile).
        long pubRef = 0;
        try
        {
            byte[] p = new byte[dsa.getComponent(keyRef, DSAServiceNI.COMP_P, null)];
            byte[] q = new byte[dsa.getComponent(keyRef, DSAServiceNI.COMP_Q, null)];
            byte[] g = new byte[dsa.getComponent(keyRef, DSAServiceNI.COMP_G, null)];
            byte[] y = new byte[dsa.getComponent(keyRef, DSAServiceNI.COMP_PUBLIC_VALUE, null)];
            dsa.getComponent(keyRef, DSAServiceNI.COMP_P, p);
            dsa.getComponent(keyRef, DSAServiceNI.COMP_Q, q);
            dsa.getComponent(keyRef, DSAServiceNI.COMP_G, g);
            dsa.getComponent(keyRef, DSAServiceNI.COMP_PUBLIC_VALUE, y);

            pubRef = dsa.makePublicFromComponents(p, q, g, y);
            final long ref = pubRef;
            OpenSSLException e = Assertions.assertThrows(OpenSSLException.class,
                    () -> dsa.getComponent(ref, DSAServiceNI.COMP_PRIVATE_VALUE, new byte[128]));
            Assertions.assertTrue(e.getMessage().startsWith("OpenSSL Error:"),
                    "unexpected message: " + e.getMessage());
        }
        finally
        {
            if (pubRef != 0)
            {
                specNI.dispose(pubRef);
            }
        }
    }

    // -----------------------------------------------------------------
    // Null native-context handle (0L for dsa_ref)
    // -----------------------------------------------------------------

    @Test
    public void initSign_nullSignerCtx()
    {
        assertIAE("signer context is null", () -> dsa.initSign(0L, keyRef, DIGEST, RND));
    }

    @Test
    public void initVerify_nullSignerCtx()
    {
        assertIAE("signer context is null", () -> dsa.initVerify(0L, keyRef, DIGEST));
    }

    @Test
    public void update_nullSignerCtx()
    {
        assertIAE("signer context is null", () -> dsa.update(0L, new byte[]{0x01}, 0, 1));
    }

    @Test
    public void sign_nullSignerCtx()
    {
        assertIAE("signer context is null", () -> dsa.sign(0L, new byte[64], 0, RND));
    }

    @Test
    public void verify_nullSignerCtx()
    {
        assertIAE("signer context is null", () -> dsa.verify(0L, new byte[64], 64, RND));
    }

    // -----------------------------------------------------------------
    // Sign / verify session — pre-init (null spec / digest / rand / type)
    // -----------------------------------------------------------------

    @Test
    public void initSign_nullKeyRef()
    {
        withSigner(ref -> assertIAE("key spec is null",
                () -> dsa.initSign(ref, 0L, DIGEST, RND)));
    }

    @Test
    public void initSign_nullDigestName()
    {
        withSigner(ref -> assertNPE("name is null",
                () -> dsa.initSign(ref, keyRef, null, RND)));
    }

    @Test
    public void initSign_nullRand()
    {
        withSigner(ref -> assertIAE("supplied random source was null",
                () -> dsa.initSign(ref, keyRef, DIGEST, null)));
    }

    @Test
    public void initSign_wrongKeyType()
    {
        ECServiceNI ec = FIPSNISelector.ECServiceNI;
        long ecRef = 0;
        try
        {
            ecRef = ec.generateKeyPair("P-256", RND);
            final long ecKey = ecRef;
            withSigner(ref -> assertIAE("invalid key type for DSA",
                    () -> dsa.initSign(ref, ecKey, DIGEST, RND)));
        }
        finally
        {
            if (ecRef != 0)
            {
                specNI.dispose(ecRef);
            }
        }
    }

    @Test
    public void initVerify_nullKeyRef()
    {
        withSigner(ref -> assertIAE("key spec is null",
                () -> dsa.initVerify(ref, 0L, DIGEST)));
    }

    @Test
    public void initVerify_nullDigestName()
    {
        withSigner(ref -> assertNPE("name is null",
                () -> dsa.initVerify(ref, keyRef, null)));
    }

    // -----------------------------------------------------------------
    // dsa_ctx state-machine guards (pre-init, opp mismatch)
    // -----------------------------------------------------------------

    @Test
    public void update_beforeInit_isNotInitialized()
    {
        withSigner(ref -> assertISE("not initialized",
                () -> dsa.update(ref, new byte[]{0x01}, 0, 1)));
    }

    @Test
    public void sign_beforeInit_isNotInitialized()
    {
        withSigner(ref -> assertISE("not initialized",
                () -> dsa.sign(ref, new byte[128], 0, RND)));
    }

    @Test
    public void verify_beforeInit_isNotInitialized()
    {
        withSigner(ref -> assertISE("not initialized",
                () -> dsa.verify(ref, new byte[64], 64, RND)));
    }

    @Test
    public void sign_afterInitVerify_isUnexpectedState()
    {
        withSigner(ref ->
        {
            dsa.initVerify(ref, keyRef, DIGEST);
            dsa.update(ref, new byte[]{0x01}, 0, 1);
            assertISE("unexpected state", () -> dsa.sign(ref, new byte[128], 0, RND));
        });
    }

    @Test
    public void verify_afterInitSign_isUnexpectedState()
    {
        assumeDsaSigns();
        withSigner(ref ->
        {
            dsa.initSign(ref, keyRef, DIGEST, RND);
            dsa.update(ref, new byte[]{0x01}, 0, 1);
            assertISE("unexpected state", () -> dsa.verify(ref, new byte[64], 64, RND));
        });
    }

    // -----------------------------------------------------------------
    // update — null / negative / out-of-range (MIN_VALUE + boundary+1)
    // -----------------------------------------------------------------

    @Test
    public void update_nullInput()
    {
        withInitedStream(ref -> assertNPE("input is null",
                () -> dsa.update(ref, null, 0, 0)));
    }

    @Test
    public void update_negativeOffset()
    {
        withInitedStream(ref ->
        {
            for (int off : new int[]{-1, Integer.MIN_VALUE})
            {
                assertIAE("input offset is negative", () -> dsa.update(ref, new byte[16], off, 0));
            }
        });
    }

    @Test
    public void update_negativeLen()
    {
        withInitedStream(ref ->
        {
            for (int len : new int[]{-1, Integer.MIN_VALUE})
            {
                assertIAE("input len is negative", () -> dsa.update(ref, new byte[16], 0, len));
            }
        });
    }

    @Test
    public void update_offsetPlusLenOutOfRange()
    {
        // Boundary probe: 1 + 16 > 16, and 0 + 17 > 16.
        withInitedStream(ref ->
        {
            assertIAE("input offset + length is out of range",
                    () -> dsa.update(ref, new byte[16], 1, 16));
            assertIAE("input offset + length is out of range",
                    () -> dsa.update(ref, new byte[16], 0, 17));
        });
    }

    // -----------------------------------------------------------------
    // sign — null rand / negative offset / out-of-range
    // -----------------------------------------------------------------

    @Test
    public void sign_nullRand()
    {
        withInitedSigner(ref ->
        {
            dsa.update(ref, new byte[]{0x01, 0x02, 0x03}, 0, 3);
            assertIAE("supplied random source was null",
                    () -> dsa.sign(ref, new byte[128], 0, null));
        });
    }

    @Test
    public void sign_negativeOffset()
    {
        withInitedSigner(ref ->
        {
            dsa.update(ref, new byte[]{0x01}, 0, 1);
            for (int off : new int[]{-1, Integer.MIN_VALUE})
            {
                assertIAE("output offset is negative", () -> dsa.sign(ref, new byte[128], off, RND));
            }
        });
    }

    @Test
    public void sign_offsetPastEnd()
    {
        // Boundary probe: out_off = 129 is the smallest value past the 128-byte buffer.
        withInitedSigner(ref ->
        {
            dsa.update(ref, new byte[]{0x01}, 0, 1);
            assertIAE("output offset + length is out of range",
                    () -> dsa.sign(ref, new byte[128], 129, RND));
        });
    }

    // -----------------------------------------------------------------
    // verify — null rand / null sig / negative len / out-of-range
    // -----------------------------------------------------------------

    @Test
    public void verify_nullRand()
    {
        withInitedVerifier(ref ->
        {
            dsa.update(ref, new byte[]{0x01}, 0, 1);
            assertIAE("supplied random source was null",
                    () -> dsa.verify(ref, new byte[64], 64, null));
        });
    }

    @Test
    public void verify_nullSig()
    {
        withInitedVerifier(ref ->
        {
            dsa.update(ref, new byte[]{0x01}, 0, 1);
            assertIAE("sig is null", () -> dsa.verify(ref, null, 0, RND));
        });
    }

    @Test
    public void verify_negativeLen()
    {
        withInitedVerifier(ref ->
        {
            dsa.update(ref, new byte[]{0x01}, 0, 1);
            for (int len : new int[]{-1, Integer.MIN_VALUE})
            {
                assertIAE("sig length is negative", () -> dsa.verify(ref, new byte[64], len, RND));
            }
        });
    }

    @Test
    public void verify_lenOutOfRange()
    {
        // Boundary probe: sig_len = 17 is the smallest value past the 16-byte buffer.
        withInitedVerifier(ref ->
        {
            dsa.update(ref, new byte[]{0x01}, 0, 1);
            assertIAE("sig out of range", () -> dsa.verify(ref, new byte[16], 17, RND));
        });
    }

    // -----------------------------------------------------------------
    // Functional offset-write contract (SHA-256 DSA path).
    // -----------------------------------------------------------------

    @Test
    public void sign_writesAtOffsetWithoutClobberingPrefix() throws Exception
    {
        assumeDsaSigns();
        long signRef = 0;
        long verifyRef = 0;
        try
        {
            signRef = dsa.allocateSigner();
            verifyRef = dsa.allocateSigner();

            byte[] msg = new byte[48];
            new SecureRandom().nextBytes(msg);

            dsa.initSign(signRef, keyRef, DIGEST, RND);
            dsa.update(signRef, msg, 0, msg.length);
            int needed = dsa.sign(signRef, null, 0, RND);
            Assertions.assertTrue(needed > 0, "unexpected probe length " + needed);

            int prefix = 7;
            byte[] big = new byte[needed + prefix];
            new SecureRandom().nextBytes(big);
            byte[] expectedPrefix = new byte[prefix];
            System.arraycopy(big, 0, expectedPrefix, 0, prefix);

            int written = dsa.sign(signRef, big, prefix, RND);
            Assertions.assertTrue(written > 0 && written <= needed,
                    "unexpected DSA DER length " + written);

            // (1) Prefix untouched.
            byte[] actualPrefix = new byte[prefix];
            System.arraycopy(big, 0, actualPrefix, 0, prefix);
            Assertions.assertArrayEquals(expectedPrefix, actualPrefix,
                    "DSA sign modified bytes preceding outOff");

            // (2) The signature window at big[prefix..prefix+written] verifies.
            byte[] sig = new byte[written];
            System.arraycopy(big, prefix, sig, 0, written);
            dsa.initVerify(verifyRef, keyRef, DIGEST);
            dsa.update(verifyRef, msg, 0, msg.length);
            Assertions.assertEquals(ErrorCode.JO_SUCCESS.getCode(),
                    dsa.verify(verifyRef, sig, sig.length, RND),
                    "DSA signature at offset " + prefix + " did not verify");

            // (3) A window shifted one byte into the prefix must NOT verify.
            byte[] shifted = new byte[written];
            System.arraycopy(big, prefix - 1, shifted, 0, written);
            dsa.initVerify(verifyRef, keyRef, DIGEST);
            dsa.update(verifyRef, msg, 0, msg.length);
            Assertions.assertEquals(ErrorCode.JO_FAIL.getCode(), safeVerify(verifyRef, shifted),
                    "DSA window shifted by 1 verified — wrote at outOff-1");
        }
        finally
        {
            if (signRef != 0)
            {
                dsa.disposeSigner(signRef);
            }
            if (verifyRef != 0)
            {
                dsa.disposeSigner(verifyRef);
            }
        }
    }

    // -----------------------------------------------------------------
    // Aliased-buffer signing (testing.md). DSA has no single in->out
    // transform (update only reads, sign only writes), so the meaningful
    // aliased case is a caller reusing the update-input (message) array as the
    // sign-output array. DSA's DER signature is variable-length and randomised,
    // so correctness is checked by VERIFYING the aliased signature against the
    // original message, and every byte of the destination outside the
    // signature region must be untouched.
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

    private static void assertAliasedSignVerifies(int msgLen, int sigOff)
    {
        assumeDsaSigns();
        long signRef = 0;
        long verifyRef = 0;
        try
        {
            signRef = dsa.allocateSigner();
            verifyRef = dsa.allocateSigner();

            byte[] msg = new byte[msgLen];
            new SecureRandom().nextBytes(msg);

            // Probe the signature length via a separate buffer.
            dsa.initSign(signRef, keyRef, DIGEST, RND);
            dsa.update(signRef, msg, 0, msg.length);
            int needed = dsa.sign(signRef, null, 0, RND);

            int cap = Math.max(msgLen, sigOff + needed) + 8;
            byte[] buf = new byte[cap];
            new SecureRandom().nextBytes(buf);
            System.arraycopy(msg, 0, buf, 0, msgLen);
            byte[] snapshot = buf.clone();

            // Sign in place: update reads buf[0..msgLen), sign writes into the
            // SAME buf at sigOff.
            dsa.initSign(signRef, keyRef, DIGEST, RND);
            dsa.update(signRef, buf, 0, msgLen);
            int written = dsa.sign(signRef, buf, sigOff, RND);
            String where = "msgLen=" + msgLen + " sigOff=" + sigOff;
            Assertions.assertTrue(written > 0 && written <= needed, where + " unexpected DER length " + written);

            // (1) The aliased signature verifies against the original message.
            byte[] sig = new byte[written];
            System.arraycopy(buf, sigOff, sig, 0, written);
            dsa.initVerify(verifyRef, keyRef, DIGEST);
            dsa.update(verifyRef, msg, 0, msg.length);
            Assertions.assertEquals(ErrorCode.JO_SUCCESS.getCode(),
                    dsa.verify(verifyRef, sig, sig.length, RND),
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
                dsa.disposeSigner(signRef);
            }
            if (verifyRef != 0)
            {
                dsa.disposeSigner(verifyRef);
            }
        }
    }

    // -----------------------------------------------------------------
    // helpers
    // -----------------------------------------------------------------

    private static int safeVerify(long verifyRef, byte[] sig)
    {
        try
        {
            return dsa.verify(verifyRef, sig, sig.length, RND);
        }
        catch (Exception expected)
        {
            return ErrorCode.JO_FAIL.getCode();
        }
    }

    private interface SignerBody
    {
        void run(long ref) throws Exception;
    }

    private static void withSigner(SignerBody body)
    {
        long ref = dsa.allocateSigner();
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
            dsa.disposeSigner(ref);
        }
    }

    /**
     * A signer context bound for SIGNING. Skips the calling test when the
     * loaded module is verify-only for DSA — OpenSSL's 3.5.x FIPS module
     * refuses {@code initSign} outright, so a sign-path bridge check simply
     * cannot be reached there.
     * <p>
     * The skip is not silent about its cause: {@link FIPSTestUtil#fipsDsaCanSign()}
     * pins the refusal's type and message before answering false, and
     * {@code FIPSDSAAgreementTest.dsaSigningRefusedTypedOrWorks} locks it at the
     * JCE surface. Bridge checks that do not care about direction use
     * {@link #withInitedStream} instead and keep running on both modules.
     */
    private static void withInitedSigner(SignerBody body)
    {
        assumeDsaSigns();
        withSigner(ref ->
        {
            dsa.initSign(ref, keyRef, DIGEST, RND);
            body.run(ref);
        });
    }

    /**
     * A signer context bound for whichever direction the module supports —
     * signing where available, verification otherwise.
     * <p>
     * For the update-side bridge checks (null input, negative offset/length,
     * offset+length range) the direction is irrelevant: {@code dsa_ctx_update}
     * and its bridge run the same validation either way. Binding whichever
     * direction works keeps that coverage alive on a verify-only module rather
     * than skipping it along with the genuinely sign-only tests.
     */
    private static void withInitedStream(SignerBody body)
    {
        withSigner(ref ->
        {
            if (dsaSigns())
            {
                dsa.initSign(ref, keyRef, DIGEST, RND);
            }
            else
            {
                dsa.initVerify(ref, keyRef, DIGEST);
            }
            body.run(ref);
        });
    }

    private static boolean dsaSigns()
    {
        try
        {
            return FIPSTestUtil.fipsDsaCanSign();
        }
        catch (Exception e)
        {
            throw new IllegalStateException("could not probe DSA signing", e);
        }
    }

    private static void assumeDsaSigns()
    {
        Assumptions.assumeTrue(dsaSigns(),
                "the loaded FIPS module is verify-only for DSA, so initSign cannot be reached"
                        + " (the refusal itself is pinned by FIPSTestUtil.fipsDsaCanSign and"
                        + " FIPSDSAAgreementTest.dsaSigningRefusedTypedOrWorks)");
    }

    private static void withInitedVerifier(SignerBody body)
    {
        withSigner(ref ->
        {
            dsa.initVerify(ref, keyRef, DIGEST);
            body.run(ref);
        });
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
