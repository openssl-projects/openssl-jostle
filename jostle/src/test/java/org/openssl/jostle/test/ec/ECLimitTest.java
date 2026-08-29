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
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.ec.ECServiceNI;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.test.crypto.TestNISelector;

import java.security.SecureRandom;
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
        // Boolean wrapper must return false for null — must NOT throw.
        // Wrapper checks `code == 1`, so any negative ni return → false.
        Assertions.assertFalse(ec.curveSupported(null));
    }

    @Test
    public void ECServiceNI_ni_curveSupported_nullName_returnsTypedCode()
    {
        // Direct NI call surfaces the typed error code so callers
        // bypassing the boolean wrapper can distinguish the cause.
        Assertions.assertEquals(ErrorCode.JO_NAME_IS_NULL.getCode(),
                ec.ni_curveSupported(null));
    }

    @Test
    public void ECServiceNI_ni_curveSupported_unknownCurve_returnsCurveNotSupported()
    {
        // Unrecognised curve name → JO_CURVE_NOT_SUPPORTED at the NI
        // level (boolean wrapper still returns false for it).
        Assertions.assertEquals(ErrorCode.JO_CURVE_NOT_SUPPORTED.getCode(),
                ec.ni_curveSupported("definitely-not-a-real-curve"));
        Assertions.assertFalse(ec.curveSupported("definitely-not-a-real-curve"));
    }

    @Test
    public void ECServiceNI_ni_curveSupported_knownCurve_returns1()
    {
        // P-256 must be universally supported on any reasonable
        // OpenSSL build. The NI returns 1 on success.
        Assertions.assertEquals(1, ec.ni_curveSupported("P-256"));
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
     * outside {0,1,2,3} returns {@code JO_UNEXPECTED_STATE}, surfaced by the
     * Java error handler as {@code IllegalStateException}.
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
        catch (IllegalStateException expected)
        {
            // ec_get_component returns the typed JO_UNEXPECTED_STATE for
            // unknown selectors (not bare JO_FAIL, which would surface as the
            // opaque "unexpected error code" fallback).
            Assertions.assertEquals("unexpected state",
                    expected.getMessage());
        }
        finally
        {
            if (keyRef != 0)
            {
                NISelectorDispose.disposeSpec(keyRef);
            }
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
            // Boundary probe: query the actual component length, then probe at
            // exactly one byte too small. The P-256 X coordinate is at most 32
            // bytes, but a BIGNUM's minimal encoding is shorter when the top
            // byte happens to be zero (~1 key in 256), so a hardcoded 31 is
            // occasionally large enough and the test flakes. Probing relative
            // to the real length still exercises the off-by-one boundary
            // exactly, regardless of leading-zero variation in the key.
            int actualLen = ec.getComponent(keyRef, ECServiceNI.COMP_PUBLIC_X, new byte[64]);
            ec.getComponent(keyRef, ECServiceNI.COMP_PUBLIC_X, new byte[actualLen - 1]);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("output too small", expected.getMessage());
        }
        finally
        {
            if (keyRef != 0)
            {
                NISelectorDispose.disposeSpec(keyRef);
            }
        }
    }


    // -----------------------------------------------------------------
    // Null native-context handle (caller passes 0L for ec_ref / kex_ref).
    // Bridge layer must surface this as IllegalArgumentException with a
    // typed message — never abort the JVM via jo_assert.
    // -----------------------------------------------------------------

    @Test
    public void ECServiceNI_initSign_nullSignerCtx()
    {
        long keyRef = 0;
        try
        {
            keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
            ec.initSign(0L, keyRef, "SHA-256", TestUtil.RNDSrc);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("signer context is null", expected.getMessage());
        }
        finally
        {
            if (keyRef != 0)
            {
                NISelectorDispose.disposeSpec(keyRef);
            }
        }
    }

    @Test
    public void ECServiceNI_initVerify_nullSignerCtx()
    {
        long keyRef = 0;
        try
        {
            keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
            ec.initVerify(0L, keyRef, "SHA-256");
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("signer context is null", expected.getMessage());
        }
        finally
        {
            if (keyRef != 0)
            {
                NISelectorDispose.disposeSpec(keyRef);
            }
        }
    }

    @Test
    public void ECServiceNI_update_nullSignerCtx()
    {
        try
        {
            ec.update(0L, new byte[]{0x01}, 0, 1);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("signer context is null", expected.getMessage());
        }
    }

    @Test
    public void ECServiceNI_sign_nullSignerCtx()
    {
        try
        {
            ec.sign(0L, new byte[64], 0, TestUtil.RNDSrc);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("signer context is null", expected.getMessage());
        }
    }

    @Test
    public void ECServiceNI_verify_nullSignerCtx()
    {
        try
        {
            ec.verify(0L, new byte[64], 64, TestUtil.RNDSrc);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("signer context is null", expected.getMessage());
        }
    }

    @Test
    public void ECServiceNI_kexInit_nullKexCtx()
    {
        long keyRef = 0;
        try
        {
            keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
            ec.kexInit(0L, keyRef, TestUtil.RNDSrc);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("key-agreement context is null", expected.getMessage());
        }
        finally
        {
            if (keyRef != 0)
            {
                NISelectorDispose.disposeSpec(keyRef);
            }
        }
    }

    @Test
    public void ECServiceNI_kexSetPeer_nullKexCtx()
    {
        long peerRef = 0;
        try
        {
            peerRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);
            ec.kexSetPeer(0L, peerRef, TestUtil.RNDSrc);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("key-agreement context is null", expected.getMessage());
        }
        finally
        {
            if (peerRef != 0)
            {
                NISelectorDispose.disposeSpec(peerRef);
            }
        }
    }

    @Test
    public void ECServiceNI_kexDerive_nullKexCtx()
    {
        try
        {
            ec.kexDerive(0L, new byte[64], 0, TestUtil.RNDSrc);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("key-agreement context is null", expected.getMessage());
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
            if (ref != 0)
            {
                ec.disposeSigner(ref);
            }
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
            if (ref != 0)
            {
                ec.disposeSigner(ref);
            }
            if (keyRef != 0)
            {
                NISelectorDispose.disposeSpec(keyRef);
            }
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
            if (ref != 0)
            {
                ec.disposeSigner(ref);
            }
            if (keyRef != 0)
            {
                NISelectorDispose.disposeSpec(keyRef);
            }
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
            if (ref != 0)
            {
                ec.disposeSigner(ref);
            }
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
            if (ref != 0)
            {
                ec.disposeSigner(ref);
            }
            if (keyRef != 0)
            {
                NISelectorDispose.disposeSpec(keyRef);
            }
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
            if (ref != 0)
            {
                ec.disposeSigner(ref);
            }
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
            if (ref != 0)
            {
                ec.disposeSigner(ref);
            }
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
            if (ref != 0)
            {
                ec.disposeSigner(ref);
            }
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
            if (ref != 0)
            {
                ec.disposeSigner(ref);
            }
            if (keyRef != 0)
            {
                NISelectorDispose.disposeSpec(keyRef);
            }
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
            if (ref != 0)
            {
                ec.disposeSigner(ref);
            }
            if (keyRef != 0)
            {
                NISelectorDispose.disposeSpec(keyRef);
            }
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
            if (ref != 0)
            {
                ec.disposeSigner(ref);
            }
            if (keyRef != 0)
            {
                NISelectorDispose.disposeSpec(keyRef);
            }
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
            if (ref != 0)
            {
                ec.disposeSigner(ref);
            }
            if (keyRef != 0)
            {
                NISelectorDispose.disposeSpec(keyRef);
            }
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
            if (ref != 0)
            {
                ec.disposeSigner(ref);
            }
            if (keyRef != 0)
            {
                NISelectorDispose.disposeSpec(keyRef);
            }
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
            // Boundary probe: off + len = 1 + 16 = 17 > 16, the smallest
            // sum that should be rejected. A check off-by-N would let
            // arbitrary values like (10, 10) through but reject this one.
            ec.update(ref, new byte[16], 1, 16);
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
                ec.disposeSigner(ref);
            }
            if (keyRef != 0)
            {
                NISelectorDispose.disposeSpec(keyRef);
            }
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
            if (ref != 0)
            {
                ec.disposeSigner(ref);
            }
            if (keyRef != 0)
            {
                NISelectorDispose.disposeSpec(keyRef);
            }
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
            if (ref != 0)
            {
                ec.disposeSigner(ref);
            }
            if (keyRef != 0)
            {
                NISelectorDispose.disposeSpec(keyRef);
            }
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
            // Boundary probe: out_off = 129 is the smallest value that
            // exceeds the 128-byte buffer (the bridge accepts
            // out_off == buffer.length as "write at end with zero
            // capacity"). Avoids hiding an off-by-N in the bridge check.
            ec.sign(ref, new byte[128], 129, TestUtil.RNDSrc);
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
                ec.disposeSigner(ref);
            }
            if (keyRef != 0)
            {
                NISelectorDispose.disposeSpec(keyRef);
            }
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
            if (ref != 0)
            {
                ec.disposeSigner(ref);
            }
            if (keyRef != 0)
            {
                NISelectorDispose.disposeSpec(keyRef);
            }
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
            if (ref != 0)
            {
                ec.disposeSigner(ref);
            }
            if (keyRef != 0)
            {
                NISelectorDispose.disposeSpec(keyRef);
            }
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
            if (ref != 0)
            {
                ec.disposeSigner(ref);
            }
            if (keyRef != 0)
            {
                NISelectorDispose.disposeSpec(keyRef);
            }
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
            // Boundary probe: sig_len = 17 is the smallest value that
            // exceeds the 16-byte buffer. A check off-by-N would let
            // arbitrary values like 100 through but reject this one.
            ec.verify(ref, new byte[16], 17, TestUtil.RNDSrc);
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
                ec.disposeSigner(ref);
            }
            if (keyRef != 0)
            {
                NISelectorDispose.disposeSpec(keyRef);
            }
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
            if (ref != 0)
            {
                ec.disposeKex(ref);
            }
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
            if (ref != 0)
            {
                ec.disposeKex(ref);
            }
            if (keyRef != 0)
            {
                NISelectorDispose.disposeSpec(keyRef);
            }
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
            ec.kexSetPeer(ref, 0L, TestUtil.RNDSrc);
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
                ec.disposeKex(ref);
            }
            if (keyRef != 0)
            {
                NISelectorDispose.disposeSpec(keyRef);
            }
        }
    }

    @Test
    public void ECServiceNI_kexSetPeer_nullRand()
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
            ec.kexSetPeer(ref, peerRef, null);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            // RAND is required even on set_peer because binary-field
            // curves trigger an internal EVP_PKEY_public_check.
            Assertions.assertEquals("supplied random source was null", expected.getMessage());
        }
        finally
        {
            if (ref != 0)
            {
                ec.disposeKex(ref);
            }
            if (keyRef != 0)
            {
                NISelectorDispose.disposeSpec(keyRef);
            }
            if (peerRef != 0)
            {
                NISelectorDispose.disposeSpec(peerRef);
            }
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
            ec.kexSetPeer(ref, peer, TestUtil.RNDSrc);
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
                ec.disposeKex(ref);
            }
            if (peer != 0)
            {
                NISelectorDispose.disposeSpec(peer);
            }
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
            ec.kexSetPeer(ref, peerRef, TestUtil.RNDSrc);
            ec.kexDerive(ref, new byte[64], 0, null);
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
                ec.disposeKex(ref);
            }
            if (keyRef != 0)
            {
                NISelectorDispose.disposeSpec(keyRef);
            }
            if (peerRef != 0)
            {
                NISelectorDispose.disposeSpec(peerRef);
            }
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
            ec.kexSetPeer(ref, peerRef, TestUtil.RNDSrc);
            ec.kexDerive(ref, new byte[64], -1, TestUtil.RNDSrc);
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
                ec.disposeKex(ref);
            }
            if (keyRef != 0)
            {
                NISelectorDispose.disposeSpec(keyRef);
            }
            if (peerRef != 0)
            {
                NISelectorDispose.disposeSpec(peerRef);
            }
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
            ec.kexSetPeer(ref, peerRef, TestUtil.RNDSrc);
            // Boundary probe: out_off = 65 is the smallest value that
            // exceeds the 64-byte buffer. The bridge accepts
            // out_off == buffer.length but rejects anything past.
            ec.kexDerive(ref, new byte[64], 65, TestUtil.RNDSrc);
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
                ec.disposeKex(ref);
            }
            if (keyRef != 0)
            {
                NISelectorDispose.disposeSpec(keyRef);
            }
            if (peerRef != 0)
            {
                NISelectorDispose.disposeSpec(peerRef);
            }
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
            if (ref != 0)
            {
                ec.disposeKex(ref);
            }
            if (keyRef != 0)
            {
                NISelectorDispose.disposeSpec(keyRef);
            }
        }
    }


    /**
     * Offset-write contract for the RAW ECDSA path (NoneWithECDSA, digest
     * name "NONE") — a distinct C function ({@code ec_ctx_sign}'s raw branch)
     * from the digest path. 4-step structure adapted for ECDSA's variable DER
     * length: random fill, prefix snapshot, prefix-untouched, signature window
     * at offset verifies, shifted-by-one window does NOT. (Bridge-level
     * offset / length / negative-int validation is shared with the digest path
     * and covered by the ECServiceNI_sign_* / _update_* tests above.)
     */
    @Test
    public void ECServiceNI_signRaw_writesAtOffsetWithoutClobberingPrefix() throws Exception
    {
        long signRef = 0;
        long verifyRef = 0;
        long keyRef = 0;
        try
        {
            signRef = ec.allocateSigner();
            verifyRef = ec.allocateSigner();
            keyRef = ec.generateKeyPair("P-256", TestUtil.RNDSrc);

            // Raw ECDSA ("NONE"): the caller supplies a pre-computed digest.
            byte[] digest = new byte[32];
            new SecureRandom().nextBytes(digest);

            ec.initSign(signRef, keyRef, "NONE", TestUtil.RNDSrc);
            ec.update(signRef, digest, 0, digest.length);
            // ECDSA DER length varies; the probe returns an upper bound.
            int needed = ec.sign(signRef, null, 0, TestUtil.RNDSrc);

            int prefix = 7;
            byte[] big = new byte[needed + prefix];
            new SecureRandom().nextBytes(big);
            byte[] expectedPrefix = new byte[prefix];
            System.arraycopy(big, 0, expectedPrefix, 0, prefix);

            int written = ec.sign(signRef, big, prefix, TestUtil.RNDSrc);
            Assertions.assertTrue(written > 0 && written <= needed,
                    "unexpected raw ECDSA DER length " + written);

            // (1) Prefix untouched.
            byte[] actualPrefix = new byte[prefix];
            System.arraycopy(big, 0, actualPrefix, 0, prefix);
            Assertions.assertArrayEquals(expectedPrefix, actualPrefix,
                    "raw ECDSA sign modified bytes preceding outOff");

            // (2) The signature window at big[prefix..prefix+written] verifies.
            byte[] sig = new byte[written];
            System.arraycopy(big, prefix, sig, 0, written);
            ec.initVerify(verifyRef, keyRef, "NONE");
            ec.update(verifyRef, digest, 0, digest.length);
            Assertions.assertEquals(ErrorCode.JO_SUCCESS.getCode(),
                    ec.verify(verifyRef, sig, sig.length, TestUtil.RNDSrc),
                    "raw ECDSA signature at offset " + prefix + " did not verify");

            // (3) A window shifted one byte into the prefix must NOT verify.
            byte[] shifted = new byte[written];
            System.arraycopy(big, prefix - 1, shifted, 0, written);
            ec.initVerify(verifyRef, keyRef, "NONE");
            ec.update(verifyRef, digest, 0, digest.length);
            int shiftedResult;
            try
            {
                shiftedResult = ec.verify(verifyRef, shifted, shifted.length, TestUtil.RNDSrc);
            }
            catch (Exception expected)
            {
                shiftedResult = ErrorCode.JO_FAIL.getCode();
            }
            Assertions.assertEquals(ErrorCode.JO_FAIL.getCode(), shiftedResult,
                    "raw ECDSA window shifted by 1 verified — wrote at outOff-1");
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
                NISelectorDispose.disposeSpec(keyRef);
            }
        }
    }


    // -----------------------------------------------------------------
    // getCurveComponent / findCurveName (MT-21)
    //
    // Both bridges validate independently and must reject identical inputs
    // with identical codes, so every case here runs on JNI and FFI alike.
    // -----------------------------------------------------------------

    @Test
    public void ECServiceNI_getCurveComponent_nullName()
    {
        try
        {
            ec.getCurveComponent(null, ECServiceNI.CURVE_COMP_P, null);
            Assertions.fail("expected NullPointerException");
        }
        catch (NullPointerException expected)
        {
            Assertions.assertEquals("name is null", expected.getMessage());
        }
    }

    /**
     * A name OpenSSL resolves to some OTHER kind of object must not be taken
     * for a curve. {@code OBJ_txt2nid} answers for every object OpenSSL knows,
     * so the group build is what actually gates this — without it a cipher
     * name would reach the component switch.
     */
    @Test
    public void ECServiceNI_getCurveComponent_nonCurveObjectNameIsRefused()
    {
        Assertions.assertEquals(ErrorCode.JO_CURVE_NOT_SUPPORTED.getCode(),
                ec.getCurveComponent("AES-256-CBC", ECServiceNI.CURVE_COMP_P, null),
                "a non-curve object name must not resolve as a curve");
        Assertions.assertEquals(ErrorCode.JO_CURVE_NOT_SUPPORTED.getCode(),
                ec.getCurveComponent("no-such-curve", ECServiceNI.CURVE_COMP_P, null));
    }

    /** Selector outside the EC_CURVE_COMP_* set is a typed state error. */
    @Test
    public void ECServiceNI_getCurveComponent_invalidSelector()
    {
        try
        {
            ec.getCurveComponent("P-256", 999, null);
            Assertions.fail("expected IllegalStateException for invalid selector");
        }
        catch (IllegalStateException expected)
        {
            Assertions.assertEquals("unexpected state", expected.getMessage());
        }
    }

    /** One byte short of the reported length is refused, not truncated. */
    @Test
    public void ECServiceNI_getCurveComponent_outputTooSmall()
    {
        int len = ec.getCurveComponent("P-256", ECServiceNI.CURVE_COMP_P, null);
        Assertions.assertTrue(len > 0, "P-256 must report a field size");
        try
        {
            ec.getCurveComponent("P-256", ECServiceNI.CURVE_COMP_P, new byte[len - 1]);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("output too small", expected.getMessage());
        }
    }

    /**
     * A zero-length component is SUCCESS, not an error: secp256k1's a is zero
     * and {@code BN_num_bytes} reports 0 for it. Pinned by name because the
     * whole error space is negative, so a 0 here can only mean "empty".
     */
    @Test
    public void ECServiceNI_getCurveComponent_zeroLengthComponentIsSuccess()
    {
        if (!ec.curveSupported("secp256k1"))
        {
            return;
        }
        Assertions.assertEquals(0,
                ec.getCurveComponent("secp256k1", ECServiceNI.CURVE_COMP_A, null),
                "secp256k1 has a == 0, which is a zero-length component");
        Assertions.assertEquals(0,
                ec.getCurveComponent("secp256k1", ECServiceNI.CURVE_COMP_A, new byte[4]),
                "the fetch call must also report zero, not an error");
    }

    /**
     * Every one of the seven domain inputs is null-checked independently.
     * Probed one at a time so a bridge that checked six of seven is caught by
     * the position it missed rather than passing on the other six.
     */
    @Test
    public void ECServiceNI_findCurveName_everyInputIsNullChecked()
    {
        byte[] ok = new byte[]{0x01};
        for (int missing = 0; missing < 7; missing++)
        {
            byte[][] in = new byte[7][];
            for (int i = 0; i < 7; i++)
            {
                in[i] = i == missing ? null : ok;
            }
            try
            {
                ec.findCurveName(ECServiceNI.FIELD_TYPE_PRIME,
                        in[0], in[1], in[2], in[3], in[4], in[5], in[6], null);
                Assertions.fail("expected NullPointerException for null input " + missing);
            }
            catch (NullPointerException expected)
            {
                Assertions.assertEquals("input is null", expected.getMessage(),
                        "null input at position " + missing);
            }
        }
    }

    /**
     * The zero-length-input case, which is the one that slips past a range
     * check: an empty array is a legitimate zero, so the bridge must accept it
     * and let the lookup answer "no match" rather than reaching a util assert.
     */
    @Test
    public void ECServiceNI_findCurveName_allZeroLengthInputsAreNoMatch()
    {
        byte[] empty = new byte[0];
        Assertions.assertEquals(ErrorCode.JO_CURVE_NO_MATCH.getCode(),
                ec.findCurveName(ECServiceNI.FIELD_TYPE_PRIME,
                        empty, empty, empty, empty, empty, empty, empty, null),
                "all-zero domain parameters name no curve, and must not abort");
    }

    /** A field-type selector outside {1,2} is a typed state error. */
    @Test
    public void ECServiceNI_findCurveName_invalidFieldType()
    {
        byte[] ok = new byte[]{0x01};
        try
        {
            ec.findCurveName(99, ok, ok, ok, ok, ok, ok, ok, null);
            Assertions.fail("expected IllegalStateException for invalid field type");
        }
        catch (IllegalStateException expected)
        {
            Assertions.assertEquals("unexpected state", expected.getMessage());
        }
    }

    /** The output buffer is range-checked the same way as every other. */
    @Test
    public void ECServiceNI_findCurveName_outputTooSmall()
    {
        byte[][] p256 = p256Domain();
        int len = ec.findCurveName(ECServiceNI.FIELD_TYPE_PRIME,
                p256[0], p256[1], p256[2], p256[3], p256[4], p256[5], p256[6], null);
        Assertions.assertTrue(len > 0, "P-256's domain must name a curve");
        try
        {
            ec.findCurveName(ECServiceNI.FIELD_TYPE_PRIME,
                    p256[0], p256[1], p256[2], p256[3], p256[4], p256[5], p256[6],
                    new byte[len - 1]);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("output too small", expected.getMessage());
        }
    }

    /**
     * Declaring a prime curve's values to be a binary field must not match:
     * the field type is part of the domain, not a formatting hint.
     */
    @Test
    public void ECServiceNI_findCurveName_wrongFieldTypeDoesNotMatch()
    {
        byte[][] p256 = p256Domain();
        Assertions.assertEquals(ErrorCode.JO_CURVE_NO_MATCH.getCode(),
                ec.findCurveName(ECServiceNI.FIELD_TYPE_BINARY,
                        p256[0], p256[1], p256[2], p256[3], p256[4], p256[5], p256[6], null));
    }

    /** P-256's seven domain values, fetched through the forward direction. */
    private byte[][] p256Domain()
    {
        int[] components = {
                ECServiceNI.CURVE_COMP_P, ECServiceNI.CURVE_COMP_A,
                ECServiceNI.CURVE_COMP_B, ECServiceNI.CURVE_COMP_GX,
                ECServiceNI.CURVE_COMP_GY, ECServiceNI.CURVE_COMP_ORDER,
                ECServiceNI.CURVE_COMP_COFACTOR};
        byte[][] out = new byte[components.length][];
        for (int i = 0; i < components.length; i++)
        {
            int len = ec.getCurveComponent("P-256", components[i], null);
            Assertions.assertTrue(len >= 0, "component " + components[i]);
            out[i] = new byte[len];
            ec.getCurveComponent("P-256", components[i], out[i]);
        }
        return out;
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
