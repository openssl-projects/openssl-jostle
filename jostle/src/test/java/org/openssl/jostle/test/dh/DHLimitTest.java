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

package org.openssl.jostle.test.dh;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.dh.DHServiceNI;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.test.crypto.TestNISelector;
import org.openssl.jostle.util.Arrays;

import java.security.Security;

/**
 * NI-layer input-validation tests for the DH service. Calls
 * {@link DHServiceNI} default-method wrappers directly so the C bridge
 * layer's null / range / type checks surface as the same JCE-friendly
 * exceptions exercised by the higher-level SPI tests.
 *
 * <p>A class-wide ffdhe2048 keypair (instant — named group, no prime
 * search) provides the components and key references; per-test kex
 * allocations are disposed in {@code finally}.
 */
public class DHLimitTest
{
    /**
     * Resolved in {@code @BeforeAll} AFTER the provider is registered —
     * a static field initializer would touch {@code NISelector} before
     * the native loader has decided JNI vs FFI.
     */
    private static DHServiceNI dh;

    /** Class-wide ffdhe2048 keypair. */
    private static long keyRef = 0;
    /** Second keypair on the same group — the kex peer. */
    private static long peerRef = 0;


    @BeforeAll
    public static void beforeAll()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        dh = TestNISelector.getDHNi();
        keyRef = dh.generateKeyPairByGroup("ffdhe2048", TestUtil.RNDSrc);
        peerRef = dh.generateKeyPairByGroup("ffdhe2048", TestUtil.RNDSrc);
    }

    @AfterAll
    public static void afterAll()
    {
        if (keyRef != 0)
        {
            disposeSpec(keyRef);
            keyRef = 0;
        }
        if (peerRef != 0)
        {
            disposeSpec(peerRef);
            peerRef = 0;
        }
    }

    private static void disposeSpec(long ref)
    {
        TestNISelector.getSpecNI().dispose(ref);
    }


    // -----------------------------------------------------------------
    // groupSupported / generateKeyPairByGroup
    // -----------------------------------------------------------------

    @Test
    public void DHServiceNI_groupSupported_nullName()
    {
        // Boolean wrapper must return false for null — must NOT throw.
        Assertions.assertFalse(dh.groupSupported(null));
    }

    @Test
    public void DHServiceNI_ni_groupSupported_nullName_returnsTypedCode()
    {
        Assertions.assertEquals(ErrorCode.JO_NAME_IS_NULL.getCode(),
                dh.ni_groupSupported(null));
    }

    @Test
    public void DHServiceNI_ni_groupSupported_unknownGroup_returnsNotSupported()
    {
        Assertions.assertEquals(ErrorCode.JO_CURVE_NOT_SUPPORTED.getCode(),
                dh.ni_groupSupported("definitely-not-a-real-group"));
        Assertions.assertFalse(dh.groupSupported("definitely-not-a-real-group"));
    }

    @Test
    public void DHServiceNI_ni_groupSupported_knownGroup_returns1()
    {
        Assertions.assertEquals(1, dh.ni_groupSupported("ffdhe2048"));
    }

    @Test
    public void DHServiceNI_generateKeyPairByGroup_nullName()
    {
        try
        {
            dh.generateKeyPairByGroup(null, TestUtil.RNDSrc);
            Assertions.fail("expected NullPointerException");
        }
        catch (NullPointerException expected)
        {
            Assertions.assertEquals("name is null", expected.getMessage());
        }
    }

    @Test
    public void DHServiceNI_generateKeyPairByGroup_nullRand()
    {
        try
        {
            dh.generateKeyPairByGroup("ffdhe2048", null);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("supplied random source was null", expected.getMessage());
        }
    }


    // -----------------------------------------------------------------
    // generateParameters
    // -----------------------------------------------------------------

    @Test
    public void DHServiceNI_generateParameters_zeroOrNegativeBits()
    {
        for (int bits : new int[]{0, -1, Integer.MIN_VALUE})
        {
            try
            {
                dh.generateParameters(bits, TestUtil.RNDSrc);
                Assertions.fail("expected IllegalArgumentException for pBits=" + bits);
            }
            catch (IllegalArgumentException expected)
            {
                Assertions.assertEquals("DH parameter bit size out of range", expected.getMessage());
            }
        }
    }

    @Test
    public void DHServiceNI_generateParameters_nullRand()
    {
        try
        {
            dh.generateParameters(512, null);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("supplied random source was null", expected.getMessage());
        }
    }


    // -----------------------------------------------------------------
    // makeParamsFromComponents / make{Private,Public}FromComponents
    // -----------------------------------------------------------------

    @Test
    public void DHServiceNI_makeParamsFromComponents_nullComponent()
    {
        byte[] ok = new byte[]{0x07};
        byte[][][] combos = {
                {null, ok},
                {ok, null},
        };
        for (byte[][] combo : combos)
        {
            try
            {
                dh.makeParamsFromComponents(combo[0], combo[1]);
                Assertions.fail("expected NullPointerException");
            }
            catch (NullPointerException expected)
            {
                Assertions.assertEquals("input is null", expected.getMessage());
            }
        }
    }

    @Test
    public void DHServiceNI_makeParamsFromComponents_emptyComponent()
    {
        byte[] ok = new byte[]{0x07};
        byte[] empty = new byte[0];
        byte[][][] combos = {
                {empty, ok},
                {ok, empty},
        };
        for (byte[][] combo : combos)
        {
            try
            {
                dh.makeParamsFromComponents(combo[0], combo[1]);
                Assertions.fail("expected IllegalArgumentException");
            }
            catch (IllegalArgumentException expected)
            {
                Assertions.assertEquals("input len is negative", expected.getMessage());
            }
        }
    }

    @Test
    public void DHServiceNI_makePrivateFromComponents_nullComponent()
    {
        byte[] ok = new byte[]{0x07};
        byte[][][] combos = {
                {null, ok, ok},
                {ok, null, ok},
                {ok, ok, null},
        };
        for (byte[][] combo : combos)
        {
            try
            {
                dh.makePrivateFromComponents(combo[0], combo[1], combo[2], TestUtil.RNDSrc);
                Assertions.fail("expected NullPointerException");
            }
            catch (NullPointerException expected)
            {
                Assertions.assertEquals("input is null", expected.getMessage());
            }
        }
    }

    @Test
    public void DHServiceNI_makePrivateFromComponents_emptyComponent()
    {
        byte[] ok = new byte[]{0x07};
        byte[] empty = new byte[0];
        byte[][][] combos = {
                {empty, ok, ok},
                {ok, empty, ok},
                {ok, ok, empty},
        };
        for (byte[][] combo : combos)
        {
            try
            {
                dh.makePrivateFromComponents(combo[0], combo[1], combo[2], TestUtil.RNDSrc);
                Assertions.fail("expected IllegalArgumentException");
            }
            catch (IllegalArgumentException expected)
            {
                Assertions.assertEquals("input len is negative", expected.getMessage());
            }
        }
    }

    @Test
    public void DHServiceNI_makePrivateFromComponents_nullRand()
    {
        byte[] ok = new byte[]{0x07};
        try
        {
            dh.makePrivateFromComponents(ok, ok, ok, null);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("supplied random source was null", expected.getMessage());
        }
    }

    @Test
    public void DHServiceNI_makePublicFromComponents_nullComponent()
    {
        byte[] ok = new byte[]{0x07};
        try
        {
            dh.makePublicFromComponents(ok, ok, null);
            Assertions.fail("expected NullPointerException");
        }
        catch (NullPointerException expected)
        {
            Assertions.assertEquals("input is null", expected.getMessage());
        }
    }

    @Test
    public void DHServiceNI_makePublicFromComponents_emptyComponent()
    {
        byte[] ok = new byte[]{0x07};
        try
        {
            dh.makePublicFromComponents(ok, ok, new byte[0]);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("input len is negative", expected.getMessage());
        }
    }


    // -----------------------------------------------------------------
    // generateKeyPair (from params)
    // -----------------------------------------------------------------

    @Test
    public void DHServiceNI_generateKeyPair_nullParamsRef()
    {
        try
        {
            dh.generateKeyPair(0L, TestUtil.RNDSrc);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("key spec is null", expected.getMessage());
        }
    }

    @Test
    public void DHServiceNI_generateKeyPair_nullRand()
    {
        try
        {
            dh.generateKeyPair(keyRef, null);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("supplied random source was null", expected.getMessage());
        }
    }

    @Test
    public void DHServiceNI_generateKeyPair_wrongKeyType()
    {
        long ecRef = 0;
        try
        {
            ecRef = TestNISelector.getECNi().generateKeyPair("P-256", TestUtil.RNDSrc);
            dh.generateKeyPair(ecRef, TestUtil.RNDSrc);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("invalid key type for DH", expected.getMessage());
        }
        finally
        {
            if (ecRef != 0)
            {
                disposeSpec(ecRef);
            }
        }
    }


    // -----------------------------------------------------------------
    // getComponent
    // -----------------------------------------------------------------

    @Test
    public void DHServiceNI_getComponent_nullSpec()
    {
        try
        {
            dh.getComponent(0L, DHServiceNI.COMP_P, new byte[256]);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("key spec is null", expected.getMessage());
        }
    }

    @Test
    public void DHServiceNI_getComponent_invalidSelector()
    {
        try
        {
            dh.getComponent(keyRef, 999, new byte[256]);
            Assertions.fail("expected IllegalStateException for invalid selector");
        }
        catch (IllegalStateException expected)
        {
            Assertions.assertEquals("unexpected error code JO_FAIL: -1",
                    expected.getMessage());
        }
    }

    @Test
    public void DHServiceNI_getComponent_outputTooSmall()
    {
        // Boundary probe: p for ffdhe2048 is exactly 256 bytes, so 255
        // is the largest size that should be rejected.
        try
        {
            dh.getComponent(keyRef, DHServiceNI.COMP_P, new byte[255]);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("output too small", expected.getMessage());
        }
    }

    @Test
    public void DHServiceNI_getComponent_privateValueAbsentOnPublicKey()
    {
        // A public-only spec has no x — OpenSSL's get_bn_param fails and
        // surfaces as a real OpenSSL error (prefix-match per the
        // Limit-test message rules).
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
            dh.getComponent(pubRef, DHServiceNI.COMP_PRIVATE_VALUE, new byte[256]);
            Assertions.fail("expected OpenSSLException");
        }
        catch (OpenSSLException expected)
        {
            Assertions.assertTrue(expected.getMessage().startsWith("OpenSSL Error:"),
                    "unexpected message: " + expected.getMessage());
        }
        finally
        {
            if (pubRef != 0)
            {
                disposeSpec(pubRef);
            }
        }
    }


    // -----------------------------------------------------------------
    // Kex — null ctx / null key / null rand / state machine
    // -----------------------------------------------------------------

    @Test
    public void DHServiceNI_kexInit_nullKexCtx()
    {
        try
        {
            dh.kexInit(0L, keyRef, TestUtil.RNDSrc);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("key-agreement context is null", expected.getMessage());
        }
    }

    @Test
    public void DHServiceNI_kexInit_nullKeyRef()
    {
        long ref = 0;
        try
        {
            ref = dh.allocateKex();
            dh.kexInit(ref, 0L, TestUtil.RNDSrc);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("key spec is null", expected.getMessage());
        }
        finally
        {
            if (ref != 0)
            {
                dh.disposeKex(ref);
            }
        }
    }

    @Test
    public void DHServiceNI_kexInit_nullRand()
    {
        long ref = 0;
        try
        {
            ref = dh.allocateKex();
            dh.kexInit(ref, keyRef, null);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("supplied random source was null", expected.getMessage());
        }
        finally
        {
            if (ref != 0)
            {
                dh.disposeKex(ref);
            }
        }
    }

    @Test
    public void DHServiceNI_kexInit_wrongKeyType()
    {
        long ref = 0;
        long ecRef = 0;
        try
        {
            ref = dh.allocateKex();
            ecRef = TestNISelector.getECNi().generateKeyPair("P-256", TestUtil.RNDSrc);
            dh.kexInit(ref, ecRef, TestUtil.RNDSrc);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("invalid key type for DH", expected.getMessage());
        }
        finally
        {
            if (ref != 0)
            {
                dh.disposeKex(ref);
            }
            if (ecRef != 0)
            {
                disposeSpec(ecRef);
            }
        }
    }

    @Test
    public void DHServiceNI_kexSetPeer_beforeInit_isNotInitialized()
    {
        long ref = 0;
        try
        {
            ref = dh.allocateKex();
            dh.kexSetPeer(ref, peerRef, TestUtil.RNDSrc);
            Assertions.fail("expected IllegalStateException");
        }
        catch (IllegalStateException expected)
        {
            Assertions.assertEquals("not initialized", expected.getMessage());
        }
        finally
        {
            if (ref != 0)
            {
                dh.disposeKex(ref);
            }
        }
    }

    @Test
    public void DHServiceNI_kexSetPeer_nullPeerRef()
    {
        long ref = 0;
        try
        {
            ref = dh.allocateKex();
            dh.kexInit(ref, keyRef, TestUtil.RNDSrc);
            dh.kexSetPeer(ref, 0L, TestUtil.RNDSrc);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("key spec is null", expected.getMessage());
        }
        finally
        {
            if (ref != 0)
            {
                dh.disposeKex(ref);
            }
        }
    }

    @Test
    public void DHServiceNI_kexSetPeer_nullRand()
    {
        long ref = 0;
        try
        {
            ref = dh.allocateKex();
            dh.kexInit(ref, keyRef, TestUtil.RNDSrc);
            dh.kexSetPeer(ref, peerRef, null);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("supplied random source was null", expected.getMessage());
        }
        finally
        {
            if (ref != 0)
            {
                dh.disposeKex(ref);
            }
        }
    }

    @Test
    public void DHServiceNI_kexDerive_beforeSetPeer_isUnexpectedState()
    {
        long ref = 0;
        try
        {
            ref = dh.allocateKex();
            dh.kexInit(ref, keyRef, TestUtil.RNDSrc);
            dh.kexDerive(ref, new byte[256], 0, TestUtil.RNDSrc);
            Assertions.fail("expected IllegalStateException");
        }
        catch (IllegalStateException expected)
        {
            Assertions.assertEquals("unexpected state", expected.getMessage());
        }
        finally
        {
            if (ref != 0)
            {
                dh.disposeKex(ref);
            }
        }
    }

    @Test
    public void DHServiceNI_kexDerive_nullRand()
    {
        long ref = 0;
        try
        {
            ref = dh.allocateKex();
            dh.kexInit(ref, keyRef, TestUtil.RNDSrc);
            dh.kexSetPeer(ref, peerRef, TestUtil.RNDSrc);
            dh.kexDerive(ref, new byte[256], 0, null);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("supplied random source was null", expected.getMessage());
        }
        finally
        {
            if (ref != 0)
            {
                dh.disposeKex(ref);
            }
        }
    }

    @Test
    public void DHServiceNI_kexDerive_negativeOffset()
    {
        long ref = 0;
        try
        {
            ref = dh.allocateKex();
            dh.kexInit(ref, keyRef, TestUtil.RNDSrc);
            dh.kexSetPeer(ref, peerRef, TestUtil.RNDSrc);
            dh.kexDerive(ref, new byte[256], -1, TestUtil.RNDSrc);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("output offset is negative", expected.getMessage());
        }
        finally
        {
            if (ref != 0)
            {
                dh.disposeKex(ref);
            }
        }
    }

    @Test
    public void DHServiceNI_kexDerive_offsetPastEnd()
    {
        long ref = 0;
        try
        {
            ref = dh.allocateKex();
            dh.kexInit(ref, keyRef, TestUtil.RNDSrc);
            dh.kexSetPeer(ref, peerRef, TestUtil.RNDSrc);
            // Boundary probe: out_off = 257 is the smallest value that
            // exceeds the 256-byte buffer (the bridge accepts
            // out_off == buffer.length as "write at end with zero
            // capacity").
            dh.kexDerive(ref, new byte[256], 257, TestUtil.RNDSrc);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("output offset + length is out of range", expected.getMessage());
        }
        finally
        {
            if (ref != 0)
            {
                dh.disposeKex(ref);
            }
        }
    }

    /**
     * Offset-write contract for kexDerive: random fill, prefix
     * snapshot, derive at offset, compare the window against an
     * independent derive at offset 0, shifted-by-one window differs.
     * Also pins the padded-output property at the NI surface: both
     * derives must report exactly the prime length (256).
     */
    @Test
    public void DHServiceNI_kexDerive_writesAtOffsetWithoutClobberingPrefix()
    {
        long refA = 0;
        long refB = 0;
        try
        {
            // Reference secret at offset 0.
            refA = dh.allocateKex();
            dh.kexInit(refA, keyRef, TestUtil.RNDSrc);
            dh.kexSetPeer(refA, peerRef, TestUtil.RNDSrc);
            int need = dh.kexDerive(refA, null, 0, TestUtil.RNDSrc);
            Assertions.assertEquals(256, need, "padded secret must be prime-length");
            byte[] expected = new byte[need];
            Assertions.assertEquals(need, dh.kexDerive(refA, expected, 0, TestUtil.RNDSrc));

            // Derive into an offset window.
            refB = dh.allocateKex();
            dh.kexInit(refB, keyRef, TestUtil.RNDSrc);
            dh.kexSetPeer(refB, peerRef, TestUtil.RNDSrc);

            int prefix = 7;
            byte[] big = new byte[need + prefix + 3];
            new java.security.SecureRandom().nextBytes(big);
            byte[] expectedPrefix = new byte[prefix];
            System.arraycopy(big, 0, expectedPrefix, 0, prefix);

            int written = dh.kexDerive(refB, big, prefix, TestUtil.RNDSrc);
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
}
