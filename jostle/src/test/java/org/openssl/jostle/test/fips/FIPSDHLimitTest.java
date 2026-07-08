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
import org.openssl.jostle.jcajce.provider.dh.DHServiceNI;
import org.openssl.jostle.jcajce.provider.ec.ECServiceNI;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.rand.RandSource;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.util.Arrays;

import java.security.SecureRandom;

/**
 * Input-validation limit tests at the FIPS DH service NI surface
 * ({@link FIPSNISelector#DHServiceNI}). The FIPS JNI glue is the base
 * dh_ni_jni.c re-included under renamed symbols, so the bridge's null / range /
 * negative / type / state checks and typed-error mapping are identical by
 * construction — this pins that they survived into the FIPS interface library
 * with the same messages. Mirrors the base {@code DHLimitTest}.
 *
 * <p>A class-wide <b>ffdhe2048</b> keypair (RFC 7919 named group, FIPS-approved,
 * instant — no prime search) provides the components and key references; a
 * second keypair on the same group is the kex peer. Both are disposed in
 * {@code @AfterAll}. The {@code RandSource} parameter is still null-checked by
 * the bridge (see the null-rand tests), but the FIPS entropy path never
 * consults it — the module's own DRBG serves entropy inside the boundary.
 *
 * <p>Runs under the {@code integrationTest*} tasks; gated on
 * {@code TEST_FIPS_LIB} (whole class skips when unset). Discipline (testing.md):
 * exact-message assertions, {@code Integer.MIN_VALUE} alongside {@code -1} on
 * int offsets, range checks at {@code boundary + 1}, and functional
 * offset-write verification.
 */
public class FIPSDHLimitTest
{
    private static final RandSource RND = TestUtil.RNDSrc;
    private static final String GROUP = "ffdhe2048";

    private static DHServiceNI dh;
    private static SpecNI specNI;

    /** Class-wide ffdhe2048 keypair. */
    private static long keyRef = 0;
    /** Second keypair on the same group — the kex peer. */
    private static long peerRef = 0;

    @BeforeAll
    public static void beforeAll()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        TestUtil.addFipsProvider();
        dh = FIPSNISelector.DHServiceNI;
        specNI = FIPSNISelector.SpecNI;
        keyRef = dh.generateKeyPairByGroup(GROUP, RND);
        peerRef = dh.generateKeyPairByGroup(GROUP, RND);
    }

    @AfterAll
    public static void afterAll()
    {
        if (keyRef != 0)
        {
            specNI.dispose(keyRef);
            keyRef = 0;
        }
        if (peerRef != 0)
        {
            specNI.dispose(peerRef);
            peerRef = 0;
        }
    }

    // -----------------------------------------------------------------
    // groupSupported / generateKeyPairByGroup
    // -----------------------------------------------------------------

    @Test
    public void groupSupported_nullName()
    {
        Assertions.assertFalse(dh.groupSupported(null));
    }

    @Test
    public void ni_groupSupported_nullName_returnsTypedCode()
    {
        Assertions.assertEquals(ErrorCode.JO_NAME_IS_NULL.getCode(), dh.ni_groupSupported(null));
    }

    @Test
    public void ni_groupSupported_unknownGroup_returnsNotSupported()
    {
        Assertions.assertEquals(ErrorCode.JO_CURVE_NOT_SUPPORTED.getCode(),
                dh.ni_groupSupported("definitely-not-a-real-group"));
        Assertions.assertFalse(dh.groupSupported("definitely-not-a-real-group"));
    }

    @Test
    public void ni_groupSupported_knownGroup_returns1()
    {
        Assertions.assertEquals(1, dh.ni_groupSupported(GROUP));
    }

    @Test
    public void generateKeyPairByGroup_nullName()
    {
        assertNPE("name is null", () -> dh.generateKeyPairByGroup(null, RND));
    }

    @Test
    public void generateKeyPairByGroup_nullRand()
    {
        assertIAE("supplied random source was null", () -> dh.generateKeyPairByGroup(GROUP, null));
    }

    // -----------------------------------------------------------------
    // generateParameters
    // -----------------------------------------------------------------

    @Test
    public void generateParameters_zeroOrNegativeBits()
    {
        for (int bits : new int[]{0, -1, Integer.MIN_VALUE})
        {
            assertIAE("DH parameter bit size out of range",
                    () -> dh.generateParameters(bits, RND));
        }
    }

    @Test
    public void generateParameters_nullRand()
    {
        // Null-rand is caught at the bridge before any prime search.
        assertIAE("supplied random source was null", () -> dh.generateParameters(2048, null));
    }

    // -----------------------------------------------------------------
    // makeParamsFromComponents / make{Private,Public}FromComponents
    // -----------------------------------------------------------------

    @Test
    public void makeParamsFromComponents_nullComponent()
    {
        byte[] ok = {0x07};
        byte[][][] combos = {
                {null, ok},
                {ok, null},
        };
        for (byte[][] c : combos)
        {
            assertNPE("input is null", () -> dh.makeParamsFromComponents(c[0], c[1]));
        }
    }

    @Test
    public void makeParamsFromComponents_emptyComponent()
    {
        byte[] ok = {0x07};
        byte[] empty = new byte[0];
        byte[][][] combos = {
                {empty, ok},
                {ok, empty},
        };
        for (byte[][] c : combos)
        {
            assertIAE("input len is negative", () -> dh.makeParamsFromComponents(c[0], c[1]));
        }
    }

    @Test
    public void makePrivateFromComponents_nullComponent()
    {
        byte[] ok = {0x07};
        byte[][][] combos = {
                {null, ok, ok},
                {ok, null, ok},
                {ok, ok, null},
        };
        for (byte[][] c : combos)
        {
            assertNPE("input is null",
                    () -> dh.makePrivateFromComponents(c[0], c[1], c[2], RND));
        }
    }

    @Test
    public void makePrivateFromComponents_emptyComponent()
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
            assertIAE("input len is negative",
                    () -> dh.makePrivateFromComponents(c[0], c[1], c[2], RND));
        }
    }

    @Test
    public void makePrivateFromComponents_nullRand()
    {
        byte[] ok = {0x07};
        assertIAE("supplied random source was null",
                () -> dh.makePrivateFromComponents(ok, ok, ok, null));
    }

    @Test
    public void makePublicFromComponents_nullComponent()
    {
        byte[] ok = {0x07};
        assertNPE("input is null", () -> dh.makePublicFromComponents(ok, ok, null));
    }

    @Test
    public void makePublicFromComponents_emptyComponent()
    {
        byte[] ok = {0x07};
        assertIAE("input len is negative", () -> dh.makePublicFromComponents(ok, ok, new byte[0]));
    }

    // -----------------------------------------------------------------
    // generateKeyPair (from params)
    // -----------------------------------------------------------------

    @Test
    public void generateKeyPair_nullParamsRef()
    {
        assertIAE("key spec is null", () -> dh.generateKeyPair(0L, RND));
    }

    @Test
    public void generateKeyPair_nullRand()
    {
        assertIAE("supplied random source was null", () -> dh.generateKeyPair(keyRef, null));
    }

    @Test
    public void generateKeyPair_wrongKeyType()
    {
        ECServiceNI ec = FIPSNISelector.ECServiceNI;
        long ecRef = 0;
        try
        {
            ecRef = ec.generateKeyPair("P-256", RND);
            final long ref = ecRef;
            assertIAE("invalid key type for DH", () -> dh.generateKeyPair(ref, RND));
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
    // getComponent
    // -----------------------------------------------------------------

    @Test
    public void getComponent_nullSpec()
    {
        assertIAE("key spec is null",
                () -> dh.getComponent(0L, DHServiceNI.COMP_P, new byte[256]));
    }

    @Test
    public void getComponent_invalidSelector()
    {
        assertISE("unexpected error code JO_FAIL: -1",
                () -> dh.getComponent(keyRef, 999, new byte[256]));
    }

    @Test
    public void getComponent_outputTooSmall()
    {
        // Boundary probe: p for ffdhe2048 is exactly 256 bytes, so 255 is the
        // largest rejected size.
        assertIAE("output too small",
                () -> dh.getComponent(keyRef, DHServiceNI.COMP_P, new byte[255]));
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
            byte[] p = new byte[dh.getComponent(keyRef, DHServiceNI.COMP_P, null)];
            byte[] g = new byte[dh.getComponent(keyRef, DHServiceNI.COMP_G, null)];
            byte[] y = new byte[dh.getComponent(keyRef, DHServiceNI.COMP_PUBLIC_VALUE, null)];
            dh.getComponent(keyRef, DHServiceNI.COMP_P, p);
            dh.getComponent(keyRef, DHServiceNI.COMP_G, g);
            dh.getComponent(keyRef, DHServiceNI.COMP_PUBLIC_VALUE, y);

            pubRef = dh.makePublicFromComponents(p, g, y);
            final long ref = pubRef;
            OpenSSLException e = Assertions.assertThrows(OpenSSLException.class,
                    () -> dh.getComponent(ref, DHServiceNI.COMP_PRIVATE_VALUE, new byte[256]));
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
    // Kex — null ctx / null key / null rand / type / state machine
    // -----------------------------------------------------------------

    @Test
    public void kexInit_nullKexCtx()
    {
        assertIAE("key-agreement context is null", () -> dh.kexInit(0L, keyRef, RND));
    }

    @Test
    public void kexInit_nullKeyRef()
    {
        withKex(ref -> assertIAE("key spec is null", () -> dh.kexInit(ref, 0L, RND)));
    }

    @Test
    public void kexInit_nullRand()
    {
        withKex(ref -> assertIAE("supplied random source was null",
                () -> dh.kexInit(ref, keyRef, null)));
    }

    @Test
    public void kexInit_wrongKeyType()
    {
        ECServiceNI ec = FIPSNISelector.ECServiceNI;
        long ecRef = 0;
        try
        {
            ecRef = ec.generateKeyPair("P-256", RND);
            final long ecKey = ecRef;
            withKex(ref -> assertIAE("invalid key type for DH",
                    () -> dh.kexInit(ref, ecKey, RND)));
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
    public void kexSetPeer_beforeInit_isNotInitialized()
    {
        withKex(ref -> assertISE("not initialized",
                () -> dh.kexSetPeer(ref, peerRef, RND)));
    }

    @Test
    public void kexSetPeer_nullPeerRef()
    {
        withKex(ref ->
        {
            dh.kexInit(ref, keyRef, RND);
            assertIAE("key spec is null", () -> dh.kexSetPeer(ref, 0L, RND));
        });
    }

    @Test
    public void kexSetPeer_nullRand()
    {
        withKex(ref ->
        {
            dh.kexInit(ref, keyRef, RND);
            assertIAE("supplied random source was null",
                    () -> dh.kexSetPeer(ref, peerRef, null));
        });
    }

    @Test
    public void kexDerive_beforeSetPeer_isUnexpectedState()
    {
        withKex(ref ->
        {
            dh.kexInit(ref, keyRef, RND);
            assertISE("unexpected state", () -> dh.kexDerive(ref, new byte[256], 0, RND));
        });
    }

    @Test
    public void kexDerive_nullRand()
    {
        withKex(ref ->
        {
            dh.kexInit(ref, keyRef, RND);
            dh.kexSetPeer(ref, peerRef, RND);
            assertIAE("supplied random source was null",
                    () -> dh.kexDerive(ref, new byte[256], 0, null));
        });
    }

    @Test
    public void kexDerive_negativeOffset()
    {
        withKex(ref ->
        {
            dh.kexInit(ref, keyRef, RND);
            dh.kexSetPeer(ref, peerRef, RND);
            for (int off : new int[]{-1, Integer.MIN_VALUE})
            {
                assertIAE("output offset is negative", () -> dh.kexDerive(ref, new byte[256], off, RND));
            }
        });
    }

    @Test
    public void kexDerive_offsetPastEnd()
    {
        withKex(ref ->
        {
            dh.kexInit(ref, keyRef, RND);
            dh.kexSetPeer(ref, peerRef, RND);
            // Boundary probe: out_off = 257 is the smallest value past the
            // 256-byte buffer.
            assertIAE("output offset + length is out of range",
                    () -> dh.kexDerive(ref, new byte[256], 257, RND));
        });
    }

    /**
     * Offset-write contract for kexDerive: random fill, prefix snapshot, derive
     * at offset, compare the window against an independent derive at offset 0,
     * shifted-by-one window differs. Also pins the padded-output property: both
     * derives must report exactly the prime length (256).
     */
    @Test
    public void kexDerive_writesAtOffsetWithoutClobberingPrefix()
    {
        long refA = 0;
        long refB = 0;
        try
        {
            // Reference secret at offset 0.
            refA = dh.allocateKex();
            dh.kexInit(refA, keyRef, RND);
            dh.kexSetPeer(refA, peerRef, RND);
            int need = dh.kexDerive(refA, null, 0, RND);
            Assertions.assertEquals(256, need, "padded secret must be prime-length");
            byte[] expected = new byte[need];
            Assertions.assertEquals(need, dh.kexDerive(refA, expected, 0, RND));

            // Derive into an offset window.
            refB = dh.allocateKex();
            dh.kexInit(refB, keyRef, RND);
            dh.kexSetPeer(refB, peerRef, RND);

            int prefix = 7;
            byte[] big = new byte[need + prefix + 3];
            new SecureRandom().nextBytes(big);
            byte[] expectedPrefix = new byte[prefix];
            System.arraycopy(big, 0, expectedPrefix, 0, prefix);

            int written = dh.kexDerive(refB, big, prefix, RND);
            Assertions.assertEquals(need, written);

            byte[] actualPrefix = new byte[prefix];
            System.arraycopy(big, 0, actualPrefix, 0, prefix);
            Assertions.assertArrayEquals(expectedPrefix, actualPrefix,
                    "kexDerive modified bytes preceding outOff");

            byte[] window = new byte[written];
            System.arraycopy(big, prefix, window, 0, written);
            Assertions.assertArrayEquals(expected, window,
                    "secret at offset must equal the offset-0 secret");

            byte[] shifted = new byte[written];
            System.arraycopy(big, prefix - 1, shifted, 0, written);
            Assertions.assertFalse(Arrays.areEqual(expected, shifted),
                    "window shifted by 1 matched — wrote at outOff-1");
        }
        finally
        {
            if (refA != 0)
            {
                dh.disposeKex(refA);
            }
            if (refB != 0)
            {
                dh.disposeKex(refB);
            }
        }
    }

    // -----------------------------------------------------------------
    // helpers
    // -----------------------------------------------------------------

    private interface KexBody
    {
        void run(long ref) throws Exception;
    }

    private static void withKex(KexBody body)
    {
        long ref = dh.allocateKex();
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
            dh.disposeKex(ref);
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
