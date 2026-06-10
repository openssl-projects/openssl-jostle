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

package org.openssl.jostle.test.dsa;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.dsa.DSAServiceNI;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.test.crypto.TestNISelector;

import java.security.SecureRandom;
import java.security.Security;

/**
 * NI-layer input-validation tests for the DSA service. Calls
 * {@link DSAServiceNI} default-method wrappers directly so the C bridge
 * layer's null / range / type checks surface as the same JCE-friendly
 * exceptions exercised by the higher-level SPI tests.
 *
 * <p>Domain parameters are generated once for the class (paramgen is a
 * prime search) and disposed in {@code @AfterAll}; per-test signer ctx
 * / key allocations are disposed in {@code finally}.
 */
public class DSALimitTest
{
    /**
     * Resolved in {@code @BeforeAll} AFTER the provider is registered —
     * a static field initializer would touch {@code NISelector} before
     * the native loader has decided JNI vs FFI.
     */
    private static DSAServiceNI dsa;

    /** Class-wide 1024/160 domain parameters; allocated in beforeAll. */
    private static long paramsRef = 0;
    /** Class-wide keypair generated on paramsRef. */
    private static long keyRef = 0;


    @BeforeAll
    public static void beforeAll()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        dsa = TestNISelector.getDSANi();
        paramsRef = dsa.generateParameters(1024, 160, TestUtil.RNDSrc);
        keyRef = dsa.generateKeyPair(paramsRef, TestUtil.RNDSrc);
    }

    @AfterAll
    public static void afterAll()
    {
        if (keyRef != 0)
        {
            disposeSpec(keyRef);
            keyRef = 0;
        }
        if (paramsRef != 0)
        {
            disposeSpec(paramsRef);
            paramsRef = 0;
        }
    }

    private static void disposeSpec(long ref)
    {
        TestNISelector.getSpecNI().dispose(ref);
    }


    // -----------------------------------------------------------------
    // generateParameters
    // -----------------------------------------------------------------

    @Test
    public void DSAServiceNI_generateParameters_zeroPBits()
    {
        try
        {
            // Boundary probe: 0 is the largest non-positive value —
            // the bridge rejects p_bits <= 0.
            dsa.generateParameters(0, 160, TestUtil.RNDSrc);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("DSA parameter bit size out of range", expected.getMessage());
        }
    }

    @Test
    public void DSAServiceNI_generateParameters_negativePBits()
    {
        for (int bits : new int[]{-1, Integer.MIN_VALUE})
        {
            try
            {
                dsa.generateParameters(bits, 160, TestUtil.RNDSrc);
                Assertions.fail("expected IllegalArgumentException for pBits=" + bits);
            }
            catch (IllegalArgumentException expected)
            {
                Assertions.assertEquals("DSA parameter bit size out of range", expected.getMessage());
            }
        }
    }

    @Test
    public void DSAServiceNI_generateParameters_zeroOrNegativeQBits()
    {
        for (int bits : new int[]{0, -1, Integer.MIN_VALUE})
        {
            try
            {
                dsa.generateParameters(1024, bits, TestUtil.RNDSrc);
                Assertions.fail("expected IllegalArgumentException for qBits=" + bits);
            }
            catch (IllegalArgumentException expected)
            {
                Assertions.assertEquals("DSA parameter bit size out of range", expected.getMessage());
            }
        }
    }

    @Test
    public void DSAServiceNI_generateParameters_nullRand()
    {
        try
        {
            dsa.generateParameters(1024, 160, null);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("supplied random source was null", expected.getMessage());
        }
    }


    // -----------------------------------------------------------------
    // makeParamsFromComponents
    // -----------------------------------------------------------------

    @Test
    public void DSAServiceNI_makeParamsFromComponents_nullComponent()
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
                dsa.makeParamsFromComponents(combo[0], combo[1], combo[2]);
                Assertions.fail("expected NullPointerException");
            }
            catch (NullPointerException expected)
            {
                Assertions.assertEquals("input is null", expected.getMessage());
            }
        }
    }

    @Test
    public void DSAServiceNI_makeParamsFromComponents_emptyComponent()
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
                dsa.makeParamsFromComponents(combo[0], combo[1], combo[2]);
                Assertions.fail("expected IllegalArgumentException");
            }
            catch (IllegalArgumentException expected)
            {
                Assertions.assertEquals("input len is negative", expected.getMessage());
            }
        }
    }


    // -----------------------------------------------------------------
    // generateKeyPair
    // -----------------------------------------------------------------

    @Test
    public void DSAServiceNI_generateKeyPair_nullParamsRef()
    {
        try
        {
            dsa.generateKeyPair(0L, TestUtil.RNDSrc);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("key spec is null", expected.getMessage());
        }
    }

    @Test
    public void DSAServiceNI_generateKeyPair_nullRand()
    {
        try
        {
            dsa.generateKeyPair(paramsRef, null);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("supplied random source was null", expected.getMessage());
        }
    }

    @Test
    public void DSAServiceNI_generateKeyPair_wrongKeyType()
    {
        // A non-DSA spec (EC keypair) handed to the DSA keygen must be
        // rejected with the DSA-specific type message.
        long ecRef = 0;
        try
        {
            ecRef = TestNISelector.getECNi().generateKeyPair("P-256", TestUtil.RNDSrc);
            dsa.generateKeyPair(ecRef, TestUtil.RNDSrc);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("invalid key type for DSA", expected.getMessage());
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
    // makePrivateFromComponents / makePublicFromComponents
    // -----------------------------------------------------------------

    @Test
    public void DSAServiceNI_makePrivateFromComponents_nullComponent()
    {
        byte[] ok = new byte[]{0x07};
        byte[][][] combos = {
                {null, ok, ok, ok},
                {ok, null, ok, ok},
                {ok, ok, null, ok},
                {ok, ok, ok, null},
        };
        for (byte[][] combo : combos)
        {
            try
            {
                dsa.makePrivateFromComponents(combo[0], combo[1], combo[2], combo[3],
                        TestUtil.RNDSrc);
                Assertions.fail("expected NullPointerException");
            }
            catch (NullPointerException expected)
            {
                Assertions.assertEquals("input is null", expected.getMessage());
            }
        }
    }

    @Test
    public void DSAServiceNI_makePrivateFromComponents_emptyComponent()
    {
        byte[] ok = new byte[]{0x07};
        byte[] empty = new byte[0];
        byte[][][] combos = {
                {empty, ok, ok, ok},
                {ok, empty, ok, ok},
                {ok, ok, empty, ok},
                {ok, ok, ok, empty},
        };
        for (byte[][] combo : combos)
        {
            try
            {
                dsa.makePrivateFromComponents(combo[0], combo[1], combo[2], combo[3],
                        TestUtil.RNDSrc);
                Assertions.fail("expected IllegalArgumentException");
            }
            catch (IllegalArgumentException expected)
            {
                Assertions.assertEquals("input len is negative", expected.getMessage());
            }
        }
    }

    @Test
    public void DSAServiceNI_makePrivateFromComponents_nullRand()
    {
        byte[] ok = new byte[]{0x07};
        try
        {
            dsa.makePrivateFromComponents(ok, ok, ok, ok, null);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("supplied random source was null", expected.getMessage());
        }
    }

    @Test
    public void DSAServiceNI_makePublicFromComponents_nullComponent()
    {
        byte[] ok = new byte[]{0x07};
        byte[][][] combos = {
                {null, ok, ok, ok},
                {ok, null, ok, ok},
                {ok, ok, null, ok},
                {ok, ok, ok, null},
        };
        for (byte[][] combo : combos)
        {
            try
            {
                dsa.makePublicFromComponents(combo[0], combo[1], combo[2], combo[3]);
                Assertions.fail("expected NullPointerException");
            }
            catch (NullPointerException expected)
            {
                Assertions.assertEquals("input is null", expected.getMessage());
            }
        }
    }

    @Test
    public void DSAServiceNI_makePublicFromComponents_emptyComponent()
    {
        byte[] ok = new byte[]{0x07};
        byte[] empty = new byte[0];
        try
        {
            dsa.makePublicFromComponents(ok, ok, ok, empty);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("input len is negative", expected.getMessage());
        }
    }


    // -----------------------------------------------------------------
    // getComponent
    // -----------------------------------------------------------------

    @Test
    public void DSAServiceNI_getComponent_nullSpec()
    {
        try
        {
            dsa.getComponent(0L, DSAServiceNI.COMP_P, new byte[128]);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("key spec is null", expected.getMessage());
        }
    }

    /**
     * Default branch in the {@code switch (component)} — any selector
     * outside {0..4} returns {@code JO_FAIL}, surfaced by the Java
     * default error handler as {@code IllegalStateException}.
     */
    @Test
    public void DSAServiceNI_getComponent_invalidSelector()
    {
        try
        {
            dsa.getComponent(keyRef, 999, new byte[128]);
            Assertions.fail("expected IllegalStateException for invalid selector");
        }
        catch (IllegalStateException expected)
        {
            Assertions.assertEquals("unexpected error code JO_FAIL: -1",
                    expected.getMessage());
        }
    }

    @Test
    public void DSAServiceNI_getComponent_outputTooSmall()
    {
        // Boundary probe: q for the 1024/160 parameters is exactly 20
        // bytes, so 19 is the largest size that should be rejected.
        try
        {
            dsa.getComponent(keyRef, DSAServiceNI.COMP_Q, new byte[19]);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("output too small", expected.getMessage());
        }
    }

    @Test
    public void DSAServiceNI_getComponent_privateValueAbsentOnPublicKey()
    {
        // A public-only spec has no x — OpenSSL's get_bn_param fails and
        // surfaces as a real OpenSSL error (prefix-match per the
        // Limit-test message rules; the queue detail is volatile).
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
            dsa.getComponent(pubRef, DSAServiceNI.COMP_PRIVATE_VALUE, new byte[128]);
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
    // Null native-context handle (caller passes 0L for dsa_ref).
    // -----------------------------------------------------------------

    @Test
    public void DSAServiceNI_initSign_nullSignerCtx()
    {
        try
        {
            dsa.initSign(0L, keyRef, "SHA-256", TestUtil.RNDSrc);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("signer context is null", expected.getMessage());
        }
    }

    @Test
    public void DSAServiceNI_initVerify_nullSignerCtx()
    {
        try
        {
            dsa.initVerify(0L, keyRef, "SHA-256");
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("signer context is null", expected.getMessage());
        }
    }

    @Test
    public void DSAServiceNI_update_nullSignerCtx()
    {
        try
        {
            dsa.update(0L, new byte[]{0x01}, 0, 1);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("signer context is null", expected.getMessage());
        }
    }

    @Test
    public void DSAServiceNI_sign_nullSignerCtx()
    {
        try
        {
            dsa.sign(0L, new byte[64], 0, TestUtil.RNDSrc);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("signer context is null", expected.getMessage());
        }
    }

    @Test
    public void DSAServiceNI_verify_nullSignerCtx()
    {
        try
        {
            dsa.verify(0L, new byte[64], 64, TestUtil.RNDSrc);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("signer context is null", expected.getMessage());
        }
    }


    // -----------------------------------------------------------------
    // Sign / verify session — pre-init (null spec / digest / rand)
    // -----------------------------------------------------------------

    @Test
    public void DSAServiceNI_initSign_nullKeyRef()
    {
        long ref = 0;
        try
        {
            ref = dsa.allocateSigner();
            dsa.initSign(ref, 0L, "SHA-256", TestUtil.RNDSrc);
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
                dsa.disposeSigner(ref);
            }
        }
    }

    @Test
    public void DSAServiceNI_initSign_nullDigestName()
    {
        long ref = 0;
        try
        {
            ref = dsa.allocateSigner();
            dsa.initSign(ref, keyRef, null, TestUtil.RNDSrc);
            Assertions.fail("expected NullPointerException");
        }
        catch (NullPointerException expected)
        {
            Assertions.assertEquals("name is null", expected.getMessage());
        }
        finally
        {
            if (ref != 0)
            {
                dsa.disposeSigner(ref);
            }
        }
    }

    @Test
    public void DSAServiceNI_initSign_nullRand()
    {
        long ref = 0;
        try
        {
            ref = dsa.allocateSigner();
            dsa.initSign(ref, keyRef, "SHA-256", null);
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
                dsa.disposeSigner(ref);
            }
        }
    }

    @Test
    public void DSAServiceNI_initSign_wrongKeyType()
    {
        long ref = 0;
        long ecRef = 0;
        try
        {
            ref = dsa.allocateSigner();
            ecRef = TestNISelector.getECNi().generateKeyPair("P-256", TestUtil.RNDSrc);
            dsa.initSign(ref, ecRef, "SHA-256", TestUtil.RNDSrc);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("invalid key type for DSA", expected.getMessage());
        }
        finally
        {
            if (ref != 0)
            {
                dsa.disposeSigner(ref);
            }
            if (ecRef != 0)
            {
                disposeSpec(ecRef);
            }
        }
    }

    @Test
    public void DSAServiceNI_initVerify_nullKeyRef()
    {
        long ref = 0;
        try
        {
            ref = dsa.allocateSigner();
            dsa.initVerify(ref, 0L, "SHA-256");
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
                dsa.disposeSigner(ref);
            }
        }
    }

    @Test
    public void DSAServiceNI_initVerify_nullDigestName()
    {
        long ref = 0;
        try
        {
            ref = dsa.allocateSigner();
            dsa.initVerify(ref, keyRef, null);
            Assertions.fail("expected NullPointerException");
        }
        catch (NullPointerException expected)
        {
            Assertions.assertEquals("name is null", expected.getMessage());
        }
        finally
        {
            if (ref != 0)
            {
                dsa.disposeSigner(ref);
            }
        }
    }


    // -----------------------------------------------------------------
    // dsa_ctx state-machine guards (pre-init, opp mismatch)
    // -----------------------------------------------------------------

    @Test
    public void DSAServiceNI_update_beforeInit_isNotInitialized()
    {
        long ref = 0;
        try
        {
            ref = dsa.allocateSigner();
            dsa.update(ref, new byte[]{0x01}, 0, 1);
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
                dsa.disposeSigner(ref);
            }
        }
    }

    @Test
    public void DSAServiceNI_sign_beforeInit_isNotInitialized()
    {
        long ref = 0;
        try
        {
            ref = dsa.allocateSigner();
            dsa.sign(ref, new byte[128], 0, TestUtil.RNDSrc);
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
                dsa.disposeSigner(ref);
            }
        }
    }

    @Test
    public void DSAServiceNI_verify_beforeInit_isNotInitialized()
    {
        long ref = 0;
        try
        {
            ref = dsa.allocateSigner();
            dsa.verify(ref, new byte[64], 64, TestUtil.RNDSrc);
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
                dsa.disposeSigner(ref);
            }
        }
    }

    @Test
    public void DSAServiceNI_sign_afterInitVerify_isUnexpectedState()
    {
        long ref = 0;
        try
        {
            ref = dsa.allocateSigner();
            dsa.initVerify(ref, keyRef, "SHA-256");
            dsa.update(ref, new byte[]{0x01}, 0, 1);
            dsa.sign(ref, new byte[128], 0, TestUtil.RNDSrc);
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
                dsa.disposeSigner(ref);
            }
        }
    }

    @Test
    public void DSAServiceNI_verify_afterInitSign_isUnexpectedState()
    {
        long ref = 0;
        try
        {
            ref = dsa.allocateSigner();
            dsa.initSign(ref, keyRef, "SHA-256", TestUtil.RNDSrc);
            dsa.update(ref, new byte[]{0x01}, 0, 1);
            dsa.verify(ref, new byte[64], 64, TestUtil.RNDSrc);
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
                dsa.disposeSigner(ref);
            }
        }
    }


    // -----------------------------------------------------------------
    // update — null / negative / out-of-range
    // -----------------------------------------------------------------

    @Test
    public void DSAServiceNI_update_nullInput()
    {
        long ref = 0;
        try
        {
            ref = dsa.allocateSigner();
            dsa.initSign(ref, keyRef, "SHA-256", TestUtil.RNDSrc);
            dsa.update(ref, null, 0, 0);
            Assertions.fail("expected NullPointerException");
        }
        catch (NullPointerException expected)
        {
            Assertions.assertEquals("input is null", expected.getMessage());
        }
        finally
        {
            if (ref != 0)
            {
                dsa.disposeSigner(ref);
            }
        }
    }

    @Test
    public void DSAServiceNI_update_negativeOffset()
    {
        long ref = 0;
        try
        {
            ref = dsa.allocateSigner();
            dsa.initSign(ref, keyRef, "SHA-256", TestUtil.RNDSrc);
            dsa.update(ref, new byte[16], -1, 0);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("input offset is negative", expected.getMessage());
        }
        finally
        {
            if (ref != 0)
            {
                dsa.disposeSigner(ref);
            }
        }
    }

    @Test
    public void DSAServiceNI_update_negativeLen()
    {
        long ref = 0;
        try
        {
            ref = dsa.allocateSigner();
            dsa.initSign(ref, keyRef, "SHA-256", TestUtil.RNDSrc);
            dsa.update(ref, new byte[16], 0, -1);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("input len is negative", expected.getMessage());
        }
        finally
        {
            if (ref != 0)
            {
                dsa.disposeSigner(ref);
            }
        }
    }

    @Test
    public void DSAServiceNI_update_offsetPlusLenOverflow()
    {
        long ref = 0;
        try
        {
            ref = dsa.allocateSigner();
            dsa.initSign(ref, keyRef, "SHA-256", TestUtil.RNDSrc);
            // Boundary probe: off + len = 1 + 16 = 17 > 16, the smallest
            // sum that should be rejected.
            dsa.update(ref, new byte[16], 1, 16);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("input offset + length is out of range", expected.getMessage());
        }
        finally
        {
            if (ref != 0)
            {
                dsa.disposeSigner(ref);
            }
        }
    }


    // -----------------------------------------------------------------
    // sign — null rand / negative offset / out-of-range
    // -----------------------------------------------------------------

    @Test
    public void DSAServiceNI_sign_nullRand()
    {
        long ref = 0;
        try
        {
            ref = dsa.allocateSigner();
            dsa.initSign(ref, keyRef, "SHA-256", TestUtil.RNDSrc);
            dsa.update(ref, new byte[]{0x01, 0x02, 0x03}, 0, 3);
            dsa.sign(ref, new byte[128], 0, null);
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
                dsa.disposeSigner(ref);
            }
        }
    }

    @Test
    public void DSAServiceNI_sign_negativeOffset()
    {
        long ref = 0;
        try
        {
            ref = dsa.allocateSigner();
            dsa.initSign(ref, keyRef, "SHA-256", TestUtil.RNDSrc);
            dsa.update(ref, new byte[]{0x01}, 0, 1);
            dsa.sign(ref, new byte[128], -1, TestUtil.RNDSrc);
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
                dsa.disposeSigner(ref);
            }
        }
    }

    @Test
    public void DSAServiceNI_sign_offsetPastEnd()
    {
        long ref = 0;
        try
        {
            ref = dsa.allocateSigner();
            dsa.initSign(ref, keyRef, "SHA-256", TestUtil.RNDSrc);
            dsa.update(ref, new byte[]{0x01}, 0, 1);
            // Boundary probe: out_off = 129 is the smallest value that
            // exceeds the 128-byte buffer (the bridge accepts
            // out_off == buffer.length as "write at end with zero
            // capacity").
            dsa.sign(ref, new byte[128], 129, TestUtil.RNDSrc);
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
                dsa.disposeSigner(ref);
            }
        }
    }


    // -----------------------------------------------------------------
    // verify — null sig / negative len / out-of-range
    // -----------------------------------------------------------------

    @Test
    public void DSAServiceNI_verify_nullRand()
    {
        long ref = 0;
        try
        {
            ref = dsa.allocateSigner();
            dsa.initVerify(ref, keyRef, "SHA-256");
            dsa.update(ref, new byte[]{0x01}, 0, 1);
            dsa.verify(ref, new byte[64], 64, null);
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
                dsa.disposeSigner(ref);
            }
        }
    }

    @Test
    public void DSAServiceNI_verify_nullSig()
    {
        long ref = 0;
        try
        {
            ref = dsa.allocateSigner();
            dsa.initVerify(ref, keyRef, "SHA-256");
            dsa.update(ref, new byte[]{0x01}, 0, 1);
            dsa.verify(ref, null, 0, TestUtil.RNDSrc);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("sig is null", expected.getMessage());
        }
        finally
        {
            if (ref != 0)
            {
                dsa.disposeSigner(ref);
            }
        }
    }

    @Test
    public void DSAServiceNI_verify_negativeLen()
    {
        long ref = 0;
        try
        {
            ref = dsa.allocateSigner();
            dsa.initVerify(ref, keyRef, "SHA-256");
            dsa.update(ref, new byte[]{0x01}, 0, 1);
            dsa.verify(ref, new byte[64], -1, TestUtil.RNDSrc);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("sig length is negative", expected.getMessage());
        }
        finally
        {
            if (ref != 0)
            {
                dsa.disposeSigner(ref);
            }
        }
    }

    @Test
    public void DSAServiceNI_verify_lenOutOfRange()
    {
        long ref = 0;
        try
        {
            ref = dsa.allocateSigner();
            dsa.initVerify(ref, keyRef, "SHA-256");
            dsa.update(ref, new byte[]{0x01}, 0, 1);
            // Boundary probe: sig_len = 17 is the smallest value that
            // exceeds the 16-byte buffer.
            dsa.verify(ref, new byte[16], 17, TestUtil.RNDSrc);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("sig out of range", expected.getMessage());
        }
        finally
        {
            if (ref != 0)
            {
                dsa.disposeSigner(ref);
            }
        }
    }


    /**
     * Offset-write contract for the RAW DSA path (NoneWithDSA, digest
     * name "NONE") — a distinct C function ({@code dsa_ctx_sign}'s raw
     * branch) from the digest path. 4-step structure adapted for DSA's
     * variable DER length: random fill, prefix snapshot,
     * prefix-untouched, signature window at offset verifies,
     * shifted-by-one window does NOT.
     */
    @Test
    public void DSAServiceNI_signRaw_writesAtOffsetWithoutClobberingPrefix() throws Exception
    {
        long signRef = 0;
        long verifyRef = 0;
        try
        {
            signRef = dsa.allocateSigner();
            verifyRef = dsa.allocateSigner();

            // Raw DSA ("NONE"): the caller supplies a pre-computed digest.
            byte[] digest = new byte[20];
            new SecureRandom().nextBytes(digest);

            dsa.initSign(signRef, keyRef, "NONE", TestUtil.RNDSrc);
            dsa.update(signRef, digest, 0, digest.length);
            // DSA DER length varies; the probe returns an upper bound.
            int needed = dsa.sign(signRef, null, 0, TestUtil.RNDSrc);

            int prefix = 7;
            byte[] big = new byte[needed + prefix];
            new SecureRandom().nextBytes(big);
            byte[] expectedPrefix = new byte[prefix];
            System.arraycopy(big, 0, expectedPrefix, 0, prefix);

            int written = dsa.sign(signRef, big, prefix, TestUtil.RNDSrc);
            Assertions.assertTrue(written > 0 && written <= needed,
                    "unexpected raw DSA DER length " + written);

            // (1) Prefix untouched.
            byte[] actualPrefix = new byte[prefix];
            System.arraycopy(big, 0, actualPrefix, 0, prefix);
            Assertions.assertArrayEquals(expectedPrefix, actualPrefix,
                    "raw DSA sign modified bytes preceding outOff");

            // (2) The signature window at big[prefix..prefix+written] verifies.
            byte[] sig = new byte[written];
            System.arraycopy(big, prefix, sig, 0, written);
            dsa.initVerify(verifyRef, keyRef, "NONE");
            dsa.update(verifyRef, digest, 0, digest.length);
            Assertions.assertEquals(ErrorCode.JO_SUCCESS.getCode(),
                    dsa.verify(verifyRef, sig, sig.length, TestUtil.RNDSrc),
                    "raw DSA signature at offset " + prefix + " did not verify");

            // (3) A window shifted one byte into the prefix must NOT verify.
            byte[] shifted = new byte[written];
            System.arraycopy(big, prefix - 1, shifted, 0, written);
            dsa.initVerify(verifyRef, keyRef, "NONE");
            dsa.update(verifyRef, digest, 0, digest.length);
            int shiftedResult;
            try
            {
                shiftedResult = dsa.verify(verifyRef, shifted, shifted.length, TestUtil.RNDSrc);
            }
            catch (Exception expected)
            {
                shiftedResult = ErrorCode.JO_FAIL.getCode();
            }
            Assertions.assertEquals(ErrorCode.JO_FAIL.getCode(), shiftedResult,
                    "raw DSA window shifted by 1 verified — wrote at outOff-1");
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
}
