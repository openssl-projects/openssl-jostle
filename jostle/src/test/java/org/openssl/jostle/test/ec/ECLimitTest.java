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

package org.openssl.jostle.test.ec;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.ec.ECServiceNI;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.test.crypto.TestNISelector;

import java.security.Security;

/**
 * NI-layer input-validation tests for the EC service. Calls
 * {@link ECServiceNI} default-method wrappers directly so the C bridge
 * layer's null / range / type checks surface as the same JCE-friendly
 * exceptions exercised by the higher-level SPI tests.
 *
 * <p>Each test drives a single bridge function with one bad input,
 * confirms the matching {@link IllegalArgumentException} /
 * {@link IllegalStateException} / {@link NullPointerException} is
 * thrown, and disposes any allocated native references in
 * {@code finally}.
 */
public class ECLimitTest
{
    private final ECServiceNI ec = TestNISelector.getECNi();


    @BeforeAll
    public static void beforeAll()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }


    // -----------------------------------------------------------------
    // curveSupported / generateKeyPair
    // -----------------------------------------------------------------

    @Test
    public void ECServiceNI_curveSupported_nullName()
    {
        // Returns false for null — must NOT throw.
        Assertions.assertFalse(ec.curveSupported(null));
    }

    @Test
    public void ECServiceNI_generateKeyPair_nullCurveName()
    {
        try
        {
            ec.generateKeyPair(null, TestUtil.RNDSrc);
            Assertions.fail("expected NullPointerException");
        }
        catch (NullPointerException expected)
        {
            Assertions.assertEquals("name is null", expected.getMessage());
        }
    }

    @Test
    public void ECServiceNI_generateKeyPair_nullRand()
    {
        try
        {
            ec.generateKeyPair("P-256", null);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            // JO_RAND_NO_RAND_UP_CALL → "supplied random source was null"
            Assertions.assertEquals("supplied random source was null", expected.getMessage());
        }
    }


    // -----------------------------------------------------------------
    // makePrivateFromComponents
    // -----------------------------------------------------------------

    @Test
    public void ECServiceNI_makePrivateFromComponents_nullCurveName()
    {
        try
        {
            ec.makePrivateFromComponents(null, new byte[]{0x01, 0x02}, TestUtil.RNDSrc);
            Assertions.fail("expected NullPointerException");
        }
        catch (NullPointerException expected)
        {
            Assertions.assertEquals("name is null", expected.getMessage());
        }
    }

    @Test
    public void ECServiceNI_makePrivateFromComponents_nullScalar()
    {
        try
        {
            ec.makePrivateFromComponents("P-256", null, TestUtil.RNDSrc);
            Assertions.fail("expected NullPointerException");
        }
        catch (NullPointerException expected)
        {
            Assertions.assertEquals("input is null", expected.getMessage());
        }
    }

    @Test
    public void ECServiceNI_makePrivateFromComponents_nullRand()
    {
        try
        {
            ec.makePrivateFromComponents("P-256", new byte[]{0x01, 0x02}, null);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("supplied random source was null", expected.getMessage());
        }
    }


    // -----------------------------------------------------------------
    // getComponent
    // -----------------------------------------------------------------

    @Test
    public void ECServiceNI_getComponent_nullSpec()
    {
        try
        {
            ec.getComponent(0L, ECServiceNI.COMP_PUBLIC_X, new byte[64]);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("key spec is null", expected.getMessage());
        }
    }

    /**
     * Default branch in the {@code switch (component)} — any selector
     * outside {0,1,2,3} returns {@code JO_FAIL}, surfaced by the Java
     * default error handler as {@code IllegalStateException}.
     */
    @Test
    public void ECServiceNI_getComponent_invalidSelector()
    {
        long keyRef = 0;
        try
        {
            keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
            ec.getComponent(keyRef, 999, new byte[64]);
            Assertions.fail("expected IllegalStateException for invalid selector");
        }
        catch (IllegalStateException expected) {}
        finally
        {
            if (keyRef != 0) NISelectorDispose.disposeSpec(keyRef);
        }
    }

    @Test
    public void ECServiceNI_getComponent_outputTooSmall()
    {
        // Caller-supplied buffer is shorter than the BIGNUM magnitude
        // requires — getComponent returns JO_OUTPUT_TOO_SMALL. The
        // default error handler maps this to "output too small".
        long keyRef = 0;
        try
        {
            keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
            // P-256 X is ~32 bytes; 4 bytes is guaranteed too small.
            ec.getComponent(keyRef, ECServiceNI.COMP_PUBLIC_X, new byte[4]);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("output too small", expected.getMessage());
        }
        finally
        {
            if (keyRef != 0) NISelectorDispose.disposeSpec(keyRef);
        }
    }


    // -----------------------------------------------------------------
    // Sign / verify session — pre-init (null spec / digest)
    // -----------------------------------------------------------------

    @Test
    public void ECServiceNI_initSign_nullKeyRef()
    {
        long ref = 0;
        try
        {
            ref = ec.allocateSigner();
            ec.initSign(ref, 0L, "SHA-256", TestUtil.RNDSrc);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("key spec is null", expected.getMessage());
        }
        finally
        {
            if (ref != 0) ec.disposeSigner(ref);
        }
    }

    @Test
    public void ECServiceNI_initSign_nullDigestName()
    {
        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = ec.allocateSigner();
            keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
            ec.initSign(ref, keyRef, null, TestUtil.RNDSrc);
            Assertions.fail("expected NullPointerException");
        }
        catch (NullPointerException expected)
        {
            Assertions.assertEquals("name is null", expected.getMessage());
        }
        finally
        {
            if (ref != 0) ec.disposeSigner(ref);
            if (keyRef != 0) NISelectorDispose.disposeSpec(keyRef);
        }
    }

    @Test
    public void ECServiceNI_initSign_nullRand()
    {
        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = ec.allocateSigner();
            keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
            ec.initSign(ref, keyRef, "SHA-256", null);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("supplied random source was null", expected.getMessage());
        }
        finally
        {
            if (ref != 0) ec.disposeSigner(ref);
            if (keyRef != 0) NISelectorDispose.disposeSpec(keyRef);
        }
    }

    @Test
    public void ECServiceNI_initVerify_nullKeyRef()
    {
        long ref = 0;
        try
        {
            ref = ec.allocateSigner();
            ec.initVerify(ref, 0L, "SHA-256");
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("key spec is null", expected.getMessage());
        }
        finally
        {
            if (ref != 0) ec.disposeSigner(ref);
        }
    }

    @Test
    public void ECServiceNI_initVerify_nullDigestName()
    {
        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = ec.allocateSigner();
            keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
            ec.initVerify(ref, keyRef, null);
            Assertions.fail("expected NullPointerException");
        }
        catch (NullPointerException expected)
        {
            Assertions.assertEquals("name is null", expected.getMessage());
        }
        finally
        {
            if (ref != 0) ec.disposeSigner(ref);
            if (keyRef != 0) NISelectorDispose.disposeSpec(keyRef);
        }
    }


    // -----------------------------------------------------------------
    // ec_ctx state-machine guards (pre-init, opp mismatch)
    // -----------------------------------------------------------------

    @Test
    public void ECServiceNI_update_beforeInit_isNotInitialized()
    {
        long ref = 0;
        try
        {
            ref = ec.allocateSigner();
            // No initSign / initVerify before update.
            ec.update(ref, new byte[]{0x01}, 0, 1);
            Assertions.fail("expected IllegalStateException");
        }
        catch (IllegalStateException expected)
        {
            Assertions.assertEquals("not initialized", expected.getMessage());
        }
        finally
        {
            if (ref != 0) ec.disposeSigner(ref);
        }
    }

    @Test
    public void ECServiceNI_sign_beforeInit_isNotInitialized()
    {
        long ref = 0;
        try
        {
            ref = ec.allocateSigner();
            ec.sign(ref, new byte[128], 0, TestUtil.RNDSrc);
            Assertions.fail("expected IllegalStateException");
        }
        catch (IllegalStateException expected)
        {
            Assertions.assertEquals("not initialized", expected.getMessage());
        }
        finally
        {
            if (ref != 0) ec.disposeSigner(ref);
        }
    }

    @Test
    public void ECServiceNI_verify_beforeInit_isNotInitialized()
    {
        long ref = 0;
        try
        {
            ref = ec.allocateSigner();
            ec.verify(ref, new byte[64], 64, TestUtil.RNDSrc);
            Assertions.fail("expected IllegalStateException");
        }
        catch (IllegalStateException expected)
        {
            Assertions.assertEquals("not initialized", expected.getMessage());
        }
        finally
        {
            if (ref != 0) ec.disposeSigner(ref);
        }
    }

    @Test
    public void ECServiceNI_sign_afterInitVerify_isUnexpectedState()
    {
        // Init for verify, then call sign — ec_ctx_sign rejects with
        // JO_UNEXPECTED_STATE because ctx->opp != EC_OP_SIGN.
        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = ec.allocateSigner();
            keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
            ec.initVerify(ref, keyRef, "SHA-256");
            ec.update(ref, new byte[]{0x01}, 0, 1);
            ec.sign(ref, new byte[128], 0, TestUtil.RNDSrc);
            Assertions.fail("expected IllegalStateException");
        }
        catch (IllegalStateException expected)
        {
            Assertions.assertEquals("unexpected state", expected.getMessage());
        }
        finally
        {
            if (ref != 0) ec.disposeSigner(ref);
            if (keyRef != 0) NISelectorDispose.disposeSpec(keyRef);
        }
    }

    @Test
    public void ECServiceNI_verify_afterInitSign_isUnexpectedState()
    {
        // Inverse of the above — initSign then verify.
        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = ec.allocateSigner();
            keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
            ec.initSign(ref, keyRef, "SHA-256", TestUtil.RNDSrc);
            ec.update(ref, new byte[]{0x01}, 0, 1);
            ec.verify(ref, new byte[64], 64, TestUtil.RNDSrc);
            Assertions.fail("expected IllegalStateException");
        }
        catch (IllegalStateException expected)
        {
            Assertions.assertEquals("unexpected state", expected.getMessage());
        }
        finally
        {
            if (ref != 0) ec.disposeSigner(ref);
            if (keyRef != 0) NISelectorDispose.disposeSpec(keyRef);
        }
    }


    // -----------------------------------------------------------------
    // update — null / negative / out-of-range
    // -----------------------------------------------------------------

    @Test
    public void ECServiceNI_update_nullInput()
    {
        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = ec.allocateSigner();
            keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
            ec.initSign(ref, keyRef, "SHA-256", TestUtil.RNDSrc);
            ec.update(ref, null, 0, 0);
            Assertions.fail("expected NullPointerException");
        }
        catch (NullPointerException expected)
        {
            Assertions.assertEquals("input is null", expected.getMessage());
        }
        finally
        {
            if (ref != 0) ec.disposeSigner(ref);
            if (keyRef != 0) NISelectorDispose.disposeSpec(keyRef);
        }
    }

    @Test
    public void ECServiceNI_update_negativeOffset()
    {
        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = ec.allocateSigner();
            keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
            ec.initSign(ref, keyRef, "SHA-256", TestUtil.RNDSrc);
            ec.update(ref, new byte[16], -1, 0);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("input offset is negative", expected.getMessage());
        }
        finally
        {
            if (ref != 0) ec.disposeSigner(ref);
            if (keyRef != 0) NISelectorDispose.disposeSpec(keyRef);
        }
    }

    @Test
    public void ECServiceNI_update_negativeLen()
    {
        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = ec.allocateSigner();
            keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
            ec.initSign(ref, keyRef, "SHA-256", TestUtil.RNDSrc);
            ec.update(ref, new byte[16], 0, -1);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("input len is negative", expected.getMessage());
        }
        finally
        {
            if (ref != 0) ec.disposeSigner(ref);
            if (keyRef != 0) NISelectorDispose.disposeSpec(keyRef);
        }
    }

    @Test
    public void ECServiceNI_update_offsetPlusLenOverflow()
    {
        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = ec.allocateSigner();
            keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
            ec.initSign(ref, keyRef, "SHA-256", TestUtil.RNDSrc);
            ec.update(ref, new byte[16], 10, 10);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("input offset + length is out of range", expected.getMessage());
        }
        finally
        {
            if (ref != 0) ec.disposeSigner(ref);
            if (keyRef != 0) NISelectorDispose.disposeSpec(keyRef);
        }
    }


    // -----------------------------------------------------------------
    // sign — null rand / negative offset / out-of-range
    // -----------------------------------------------------------------

    @Test
    public void ECServiceNI_sign_nullRand()
    {
        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = ec.allocateSigner();
            keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
            ec.initSign(ref, keyRef, "SHA-256", TestUtil.RNDSrc);
            ec.update(ref, new byte[]{0x01, 0x02, 0x03}, 0, 3);
            ec.sign(ref, new byte[128], 0, null);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("supplied random source was null", expected.getMessage());
        }
        finally
        {
            if (ref != 0) ec.disposeSigner(ref);
            if (keyRef != 0) NISelectorDispose.disposeSpec(keyRef);
        }
    }

    @Test
    public void ECServiceNI_sign_negativeOffset()
    {
        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = ec.allocateSigner();
            keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
            ec.initSign(ref, keyRef, "SHA-256", TestUtil.RNDSrc);
            ec.update(ref, new byte[]{0x01}, 0, 1);
            ec.sign(ref, new byte[128], -1, TestUtil.RNDSrc);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("output offset is negative", expected.getMessage());
        }
        finally
        {
            if (ref != 0) ec.disposeSigner(ref);
            if (keyRef != 0) NISelectorDispose.disposeSpec(keyRef);
        }
    }

    @Test
    public void ECServiceNI_sign_offsetPastEnd()
    {
        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = ec.allocateSigner();
            keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
            ec.initSign(ref, keyRef, "SHA-256", TestUtil.RNDSrc);
            ec.update(ref, new byte[]{0x01}, 0, 1);
            ec.sign(ref, new byte[128], 200, TestUtil.RNDSrc);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("output offset + length is out of range", expected.getMessage());
        }
        finally
        {
            if (ref != 0) ec.disposeSigner(ref);
            if (keyRef != 0) NISelectorDispose.disposeSpec(keyRef);
        }
    }


    // -----------------------------------------------------------------
    // verify — null sig / negative len / out-of-range
    // -----------------------------------------------------------------

    @Test
    public void ECServiceNI_verify_nullRand()
    {
        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = ec.allocateSigner();
            keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
            ec.initVerify(ref, keyRef, "SHA-256");
            ec.update(ref, new byte[]{0x01}, 0, 1);
            ec.verify(ref, new byte[64], 64, null);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("supplied random source was null", expected.getMessage());
        }
        finally
        {
            if (ref != 0) ec.disposeSigner(ref);
            if (keyRef != 0) NISelectorDispose.disposeSpec(keyRef);
        }
    }

    @Test
    public void ECServiceNI_verify_nullSig()
    {
        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = ec.allocateSigner();
            keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
            ec.initVerify(ref, keyRef, "SHA-256");
            ec.update(ref, new byte[]{0x01}, 0, 1);
            ec.verify(ref, null, 0, TestUtil.RNDSrc);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("sig is null", expected.getMessage());
        }
        finally
        {
            if (ref != 0) ec.disposeSigner(ref);
            if (keyRef != 0) NISelectorDispose.disposeSpec(keyRef);
        }
    }

    @Test
    public void ECServiceNI_verify_negativeLen()
    {
        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = ec.allocateSigner();
            keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
            ec.initVerify(ref, keyRef, "SHA-256");
            ec.update(ref, new byte[]{0x01}, 0, 1);
            ec.verify(ref, new byte[64], -1, TestUtil.RNDSrc);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("sig length is negative", expected.getMessage());
        }
        finally
        {
            if (ref != 0) ec.disposeSigner(ref);
            if (keyRef != 0) NISelectorDispose.disposeSpec(keyRef);
        }
    }

    @Test
    public void ECServiceNI_verify_lenOutOfRange()
    {
        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = ec.allocateSigner();
            keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
            ec.initVerify(ref, keyRef, "SHA-256");
            ec.update(ref, new byte[]{0x01}, 0, 1);
            ec.verify(ref, new byte[16], 100, TestUtil.RNDSrc);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("sig out of range", expected.getMessage());
        }
        finally
        {
            if (ref != 0) ec.disposeSigner(ref);
            if (keyRef != 0) NISelectorDispose.disposeSpec(keyRef);
        }
    }


    // -----------------------------------------------------------------
    // Key agreement (kex) — null spec / null rand
    // -----------------------------------------------------------------

    @Test
    public void ECServiceNI_kexInit_nullKeyRef()
    {
        long ref = 0;
        try
        {
            ref = ec.allocateKex();
            ec.kexInit(ref, 0L, TestUtil.RNDSrc);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("key spec is null", expected.getMessage());
        }
        finally
        {
            if (ref != 0) ec.disposeKex(ref);
        }
    }

    @Test
    public void ECServiceNI_kexInit_nullRand()
    {
        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = ec.allocateKex();
            keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
            ec.kexInit(ref, keyRef, null);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("supplied random source was null", expected.getMessage());
        }
        finally
        {
            if (ref != 0) ec.disposeKex(ref);
            if (keyRef != 0) NISelectorDispose.disposeSpec(keyRef);
        }
    }

    @Test
    public void ECServiceNI_kexSetPeer_nullPeerRef()
    {
        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = ec.allocateKex();
            keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
            ec.kexInit(ref, keyRef, TestUtil.RNDSrc);
            ec.kexSetPeer(ref, 0L);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("key spec is null", expected.getMessage());
        }
        finally
        {
            if (ref != 0) ec.disposeKex(ref);
            if (keyRef != 0) NISelectorDispose.disposeSpec(keyRef);
        }
    }

    @Test
    public void ECServiceNI_kexSetPeer_beforeInit_isNotInitialized()
    {
        long ref = 0;
        long peer = 0;
        try
        {
            ref = ec.allocateKex();
            peer = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
            // No kexInit beforehand — set_peer must surface "not initialized".
            ec.kexSetPeer(ref, peer);
            Assertions.fail("expected IllegalStateException");
        }
        catch (IllegalStateException expected)
        {
            Assertions.assertEquals("not initialized", expected.getMessage());
        }
        finally
        {
            if (ref != 0) ec.disposeKex(ref);
            if (peer != 0) NISelectorDispose.disposeSpec(peer);
        }
    }

    @Test
    public void ECServiceNI_kexDerive_nullRand()
    {
        long ref = 0;
        long keyRef = 0;
        long peerRef = 0;
        try
        {
            ref = ec.allocateKex();
            keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
            peerRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
            ec.kexInit(ref, keyRef, TestUtil.RNDSrc);
            ec.kexSetPeer(ref, peerRef);
            ec.kexDerive(ref, new byte[64], 0, null);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("supplied random source was null", expected.getMessage());
        }
        finally
        {
            if (ref != 0) ec.disposeKex(ref);
            if (keyRef != 0) NISelectorDispose.disposeSpec(keyRef);
            if (peerRef != 0) NISelectorDispose.disposeSpec(peerRef);
        }
    }

    @Test
    public void ECServiceNI_kexDerive_negativeOffset()
    {
        long ref = 0;
        long keyRef = 0;
        long peerRef = 0;
        try
        {
            ref = ec.allocateKex();
            keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
            peerRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
            ec.kexInit(ref, keyRef, TestUtil.RNDSrc);
            ec.kexSetPeer(ref, peerRef);
            ec.kexDerive(ref, new byte[64], -1, TestUtil.RNDSrc);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("output offset is negative", expected.getMessage());
        }
        finally
        {
            if (ref != 0) ec.disposeKex(ref);
            if (keyRef != 0) NISelectorDispose.disposeSpec(keyRef);
            if (peerRef != 0) NISelectorDispose.disposeSpec(peerRef);
        }
    }

    @Test
    public void ECServiceNI_kexDerive_offsetPastEnd()
    {
        long ref = 0;
        long keyRef = 0;
        long peerRef = 0;
        try
        {
            ref = ec.allocateKex();
            keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
            peerRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
            ec.kexInit(ref, keyRef, TestUtil.RNDSrc);
            ec.kexSetPeer(ref, peerRef);
            ec.kexDerive(ref, new byte[64], 100, TestUtil.RNDSrc);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("output offset + length is out of range", expected.getMessage());
        }
        finally
        {
            if (ref != 0) ec.disposeKex(ref);
            if (keyRef != 0) NISelectorDispose.disposeSpec(keyRef);
            if (peerRef != 0) NISelectorDispose.disposeSpec(peerRef);
        }
    }

    @Test
    public void ECServiceNI_kexDerive_beforeSetPeer_isUnexpectedState()
    {
        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = ec.allocateKex();
            keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
            ec.kexInit(ref, keyRef, TestUtil.RNDSrc);
            // No kexSetPeer — derive must reject as "unexpected state".
            ec.kexDerive(ref, new byte[64], 0, TestUtil.RNDSrc);
            Assertions.fail("expected IllegalStateException");
        }
        catch (IllegalStateException expected)
        {
            Assertions.assertEquals("unexpected state", expected.getMessage());
        }
        finally
        {
            if (ref != 0) ec.disposeKex(ref);
            if (keyRef != 0) NISelectorDispose.disposeSpec(keyRef);
        }
    }


    // -----------------------------------------------------------------
    // Helper — dispose key_spec via the SpecNI bridge.
    // -----------------------------------------------------------------

    private static class NISelectorDispose
    {
        static void disposeSpec(long ref)
        {
            // The PKEYKeySpec disposer handles cleanup, but for direct NI
            // calls we dispose via the SpecNI free path (which calls
            // free_key_spec on the C side).
            TestNISelector.getSpecNI().dispose(ref);
        }
    }
}
