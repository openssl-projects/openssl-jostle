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

package org.openssl.jostle.test.rsa;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.rsa.RSAServiceNI;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.test.crypto.TestNISelector;

import java.security.SecureRandom;
import java.security.Security;

/**
 * NI-layer input-validation tests for RSA signing. Calls the {@code RSAServiceNI}
 * default-method wrappers directly so that the C bridge layer's null/range
 * checks surface as the same JCE-friendly exceptions exercised by the higher
 * layers.
 *
 * <p>Each test follows the EdDSA pattern: drive a single bridge function with
 * one bad input, confirm the matching {@link IllegalArgumentException} /
 * {@link IllegalStateException} / {@link NullPointerException} is thrown with
 * the expected message, then dispose any allocated native references in the
 * {@code finally} block.
 */

public class RSALimitTest
{
    private static final byte[] PUB_EXP_F4 = {0x01, 0x00, 0x01};

    RSAServiceNI rsaServiceNI = TestNISelector.getRSANi();
    SpecNI specNI = TestNISelector.getSpecNI();

    @BeforeAll
    public static void beforeAll()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }


    // -----------------------------------------------------------------
    // generateKeyPair
    // -----------------------------------------------------------------

    @Test
    public void RSAServiceNI_generateKeyPair_nullPubExp() throws Exception
    {
        // The null-pubExp path uses a dedicated error code so callers
        // can distinguish "missing public exponent" from a generic
        // null input — useful when wrapping the NI from higher layers.
        try
        {
            rsaServiceNI.generateKeyPair(2048, null, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (NullPointerException e)
        {
            Assertions.assertEquals("public exponent is null", e.getMessage());
        }
    }

    @Test
    public void RSAServiceNI_generateKeyPair_emptyPubExp() throws Exception
    {
        // Regression: a non-null but empty (length 0) pubexp byte array
        // used to crash via jo_assert(pubexp_len > 0) inside the util
        // layer (CLAUDE.md "Never use jo_assert for user-supplied input").
        // Now surfaces as the same JO_RSA_PUB_EXP_IS_NULL error as a null
        // array — both represent "no public exponent provided".
        try
        {
            rsaServiceNI.generateKeyPair(2048, new byte[0], TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (NullPointerException e)
        {
            Assertions.assertEquals("public exponent is null", e.getMessage());
        }
    }

    @Test
    public void RSAServiceNI_generateKeyPair_nullRand() throws Exception
    {
        try
        {
            rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, null);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("supplied random source was null", e.getMessage());
        }
    }


    // -----------------------------------------------------------------
    // decodePublicComponents
    // -----------------------------------------------------------------

    @Test
    public void RSAServiceNI_decodePublicComponents_nullSpec() throws Exception
    {
        try
        {
            rsaServiceNI.decodePublicComponents(0, new byte[]{0x01}, PUB_EXP_F4);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("key spec is null", e.getMessage());
        }
    }

    @Test
    public void RSAServiceNI_decodePublicComponents_nullN() throws Exception
    {
        long keyRef = 0;
        try
        {
            keyRef = specNI.allocate();
            Assertions.assertTrue(keyRef > 0);
            rsaServiceNI.decodePublicComponents(keyRef, null, PUB_EXP_F4);
            Assertions.fail();
        }
        catch (NullPointerException e)
        {
            Assertions.assertEquals("modulus is null", e.getMessage());
        }
        finally
        {
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSAServiceNI_decodePublicComponents_nullE() throws Exception
    {
        long keyRef = 0;
        try
        {
            keyRef = specNI.allocate();
            Assertions.assertTrue(keyRef > 0);
            rsaServiceNI.decodePublicComponents(keyRef, new byte[]{0x01}, null);
            Assertions.fail();
        }
        catch (NullPointerException e)
        {
            Assertions.assertEquals("public exponent is null", e.getMessage());
        }
        finally
        {
            specNI.dispose(keyRef);
        }
    }


    // -----------------------------------------------------------------
    // decodePrivateComponents
    // -----------------------------------------------------------------

    @Test
    public void RSAServiceNI_decodePrivateComponents_nullSpec() throws Exception
    {
        try
        {
            rsaServiceNI.decodePrivateComponents(0,
                    new byte[]{0x01}, PUB_EXP_F4, new byte[]{0x01});
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("key spec is null", e.getMessage());
        }
    }

    @Test
    public void RSAServiceNI_decodePrivateComponents_nullN() throws Exception
    {
        long keyRef = 0;
        try
        {
            keyRef = specNI.allocate();
            Assertions.assertTrue(keyRef > 0);
            rsaServiceNI.decodePrivateComponents(keyRef,
                    null, PUB_EXP_F4, new byte[]{0x01});
            Assertions.fail();
        }
        catch (NullPointerException e)
        {
            Assertions.assertEquals("modulus is null", e.getMessage());
        }
        finally
        {
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSAServiceNI_decodePrivateComponents_nullE() throws Exception
    {
        long keyRef = 0;
        try
        {
            keyRef = specNI.allocate();
            Assertions.assertTrue(keyRef > 0);
            rsaServiceNI.decodePrivateComponents(keyRef,
                    new byte[]{0x01}, null, new byte[]{0x01});
            Assertions.fail();
        }
        catch (NullPointerException e)
        {
            Assertions.assertEquals("public exponent is null", e.getMessage());
        }
        finally
        {
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSAServiceNI_decodePrivateComponents_nullD() throws Exception
    {
        long keyRef = 0;
        try
        {
            keyRef = specNI.allocate();
            Assertions.assertTrue(keyRef > 0);
            rsaServiceNI.decodePrivateComponents(keyRef,
                    new byte[]{0x01}, PUB_EXP_F4, null);
            Assertions.fail();
        }
        catch (NullPointerException e)
        {
            Assertions.assertEquals("private exponent is null", e.getMessage());
        }
        finally
        {
            specNI.dispose(keyRef);
        }
    }


    // -----------------------------------------------------------------
    // decodePrivateComponentsCrt
    // -----------------------------------------------------------------

    @Test
    public void RSAServiceNI_decodePrivateComponentsCrt_nullSpec() throws Exception
    {
        byte[] one = {0x01};
        try
        {
            rsaServiceNI.decodePrivateComponentsCrt(0,
                    one, PUB_EXP_F4, one,
                    one, one,
                    one, one, one);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("key spec is null", e.getMessage());
        }
    }

    @Test
    public void RSAServiceNI_decodePrivateComponentsCrt_anyNull() throws Exception
    {
        // Walk through each component slot, nulling exactly one at a time.
        // Each component has its own dedicated error code so callers can
        // pinpoint exactly which component was missing.
        byte[] one = {0x01};
        String[] expectedMsg = {
                "modulus is null",            // 0: n
                "public exponent is null",    // 1: e
                "private exponent is null",   // 2: d
                "prime P is null",            // 3: p
                "prime Q is null",            // 4: q
                "prime exponent P is null",   // 5: dp
                "prime exponent Q is null",   // 6: dq
                "CRT coefficient is null"     // 7: qinv
        };
        for (int nullIdx = 0; nullIdx < 8; nullIdx++)
        {
            long keyRef = 0;
            try
            {
                keyRef = specNI.allocate();
                Assertions.assertTrue(keyRef > 0);
                rsaServiceNI.decodePrivateComponentsCrt(keyRef,
                        nullIdx == 0 ? null : one,
                        nullIdx == 1 ? null : PUB_EXP_F4,
                        nullIdx == 2 ? null : one,
                        nullIdx == 3 ? null : one,
                        nullIdx == 4 ? null : one,
                        nullIdx == 5 ? null : one,
                        nullIdx == 6 ? null : one,
                        nullIdx == 7 ? null : one);
                Assertions.fail("null at index " + nullIdx + " should have rejected");
            }
            catch (NullPointerException e)
            {
                Assertions.assertEquals(expectedMsg[nullIdx], e.getMessage(),
                        "wrong message for null at index " + nullIdx);
            }
            finally
            {
                specNI.dispose(keyRef);
            }
        }
    }


    // -----------------------------------------------------------------
    // getComponent
    // -----------------------------------------------------------------

    @Test
    public void RSAServiceNI_getComponent_nullSpec() throws Exception
    {
        try
        {
            rsaServiceNI.getComponent(0, RSAServiceNI.COMP_MODULUS, null);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("key spec is null", e.getMessage());
        }
    }

    @Test
    public void RSAServiceNI_getComponent_specHasNullKey() throws Exception
    {
        long keyRef = 0;
        try
        {
            keyRef = specNI.allocate();
            Assertions.assertTrue(keyRef > 0);
            // Allocated but never populated — spec->key is NULL.
            rsaServiceNI.getComponent(keyRef, RSAServiceNI.COMP_MODULUS, null);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("key spec has null key", e.getMessage());
        }
        finally
        {
            specNI.dispose(keyRef);
        }
    }


    // -----------------------------------------------------------------
    // initSign
    // -----------------------------------------------------------------

    @Test
    public void RSAServiceNI_initSign_nullKey() throws Exception
    {
        long rsaRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            Assertions.assertTrue(rsaRef > 0);
            rsaServiceNI.initSign(rsaRef, 0, "SHA-256",
                    RSAServiceNI.PADDING_PKCS1, null, 0, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("key spec is null", e.getMessage());
        }
        finally
        {
            rsaServiceNI.disposeSigner(rsaRef);
        }
    }

    @Test
    public void RSAServiceNI_initSign_nullDigestName() throws Exception
    {
        long rsaRef = 0;
        long keyRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            Assertions.assertTrue(rsaRef > 0);
            Assertions.assertTrue(keyRef > 0);
            rsaServiceNI.initSign(rsaRef, keyRef, null,
                    RSAServiceNI.PADDING_PKCS1, null, 0, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (NullPointerException e)
        {
            Assertions.assertEquals("name is null", e.getMessage());
        }
        finally
        {
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSAServiceNI_initSign_nullRand() throws Exception
    {
        long rsaRef = 0;
        long keyRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            Assertions.assertTrue(rsaRef > 0);
            Assertions.assertTrue(keyRef > 0);
            rsaServiceNI.initSign(rsaRef, keyRef, "SHA-256",
                    RSAServiceNI.PADDING_PKCS1, null, 0, null);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("supplied random source was null", e.getMessage());
        }
        finally
        {
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }


    // -----------------------------------------------------------------
    // initVerify
    // -----------------------------------------------------------------

    @Test
    public void RSAServiceNI_initVerify_nullKey() throws Exception
    {
        long rsaRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            Assertions.assertTrue(rsaRef > 0);
            rsaServiceNI.initVerify(rsaRef, 0, "SHA-256",
                    RSAServiceNI.PADDING_PKCS1, null, 0);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("key spec is null", e.getMessage());
        }
        finally
        {
            rsaServiceNI.disposeSigner(rsaRef);
        }
    }

    @Test
    public void RSAServiceNI_initVerify_nullDigestName() throws Exception
    {
        long rsaRef = 0;
        long keyRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            Assertions.assertTrue(rsaRef > 0);
            Assertions.assertTrue(keyRef > 0);
            rsaServiceNI.initVerify(rsaRef, keyRef, null,
                    RSAServiceNI.PADDING_PKCS1, null, 0);
            Assertions.fail();
        }
        catch (NullPointerException e)
        {
            Assertions.assertEquals("name is null", e.getMessage());
        }
        finally
        {
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }


    // -----------------------------------------------------------------
    // update
    // -----------------------------------------------------------------

    @Test
    public void RSAServiceNI_update_nullInput() throws Exception
    {
        long rsaRef = 0;
        long keyRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            rsaServiceNI.initSign(rsaRef, keyRef, "SHA-256",
                    RSAServiceNI.PADDING_PKCS1, null, 0, TestUtil.RNDSrc);
            rsaServiceNI.update(rsaRef, null, 0, 0);
            Assertions.fail();
        }
        catch (NullPointerException e)
        {
            Assertions.assertEquals("input is null", e.getMessage());
        }
        finally
        {
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSAServiceNI_update_offsetNegative() throws Exception
    {
        long rsaRef = 0;
        long keyRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            rsaServiceNI.initSign(rsaRef, keyRef, "SHA-256",
                    RSAServiceNI.PADDING_PKCS1, null, 0, TestUtil.RNDSrc);
            rsaServiceNI.update(rsaRef, new byte[16], -1, 0);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset is negative", e.getMessage());
        }
        finally
        {
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSAServiceNI_update_lenNegative() throws Exception
    {
        long rsaRef = 0;
        long keyRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            rsaServiceNI.initSign(rsaRef, keyRef, "SHA-256",
                    RSAServiceNI.PADDING_PKCS1, null, 0, TestUtil.RNDSrc);
            rsaServiceNI.update(rsaRef, new byte[16], 0, -1);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input len is negative", e.getMessage());
        }
        finally
        {
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }

    /**
     * {@code Integer.MIN_VALUE} on int parameters that the NI casts to
     * {@code size_t} on the C side must be rejected at the Java boundary,
     * not propagated as a ~2^31 unsigned that would drive runaway
     * allocations or out-of-bounds reads. Per CLAUDE.md "Feed negative
     * values into every integer parameter" directive.
     */
    @Test
    public void RSAServiceNI_update_minIntValueOff() throws Exception
    {
        long rsaRef = 0;
        long keyRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            rsaServiceNI.initSign(rsaRef, keyRef, "SHA-256",
                    RSAServiceNI.PADDING_PKCS1, null, 0, TestUtil.RNDSrc);
            rsaServiceNI.update(rsaRef, new byte[16], Integer.MIN_VALUE, 0);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset is negative", e.getMessage());
        }
        finally
        {
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSAServiceNI_update_minIntValueLen() throws Exception
    {
        long rsaRef = 0;
        long keyRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            rsaServiceNI.initSign(rsaRef, keyRef, "SHA-256",
                    RSAServiceNI.PADDING_PKCS1, null, 0, TestUtil.RNDSrc);
            rsaServiceNI.update(rsaRef, new byte[16], 0, Integer.MIN_VALUE);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input len is negative", e.getMessage());
        }
        finally
        {
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSAServiceNI_sign_minIntValueOff() throws Exception
    {
        long rsaRef = 0;
        long keyRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            rsaServiceNI.initSign(rsaRef, keyRef, "SHA-256",
                    RSAServiceNI.PADDING_PKCS1, null, 0, TestUtil.RNDSrc);
            rsaServiceNI.sign(rsaRef, new byte[256], Integer.MIN_VALUE, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output offset is negative", e.getMessage());
        }
        finally
        {
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSAServiceNI_verify_minIntValueLen() throws Exception
    {
        long rsaRef = 0;
        long keyRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            rsaServiceNI.initVerify(rsaRef, keyRef, "SHA-256",
                    RSAServiceNI.PADDING_PKCS1, null, 0);
            rsaServiceNI.verify(rsaRef, new byte[1], Integer.MIN_VALUE);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("sig length is negative", e.getMessage());
        }
        finally
        {
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }

    /**
     * Combination: negative offset paired with a valid length. A check
     * written {@code off + len > buffer.length} is silently true for
     * negative {@code off} (overflow back to negative compares as &le;
     * length) — only an explicit {@code off &lt; 0} guard catches it.
     */
    @Test
    public void RSAServiceNI_update_negativeOffsetWithValidLen() throws Exception
    {
        long rsaRef = 0;
        long keyRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            rsaServiceNI.initSign(rsaRef, keyRef, "SHA-256",
                    RSAServiceNI.PADDING_PKCS1, null, 0, TestUtil.RNDSrc);
            rsaServiceNI.update(rsaRef, new byte[16], -1, 8);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset is negative", e.getMessage());
        }
        finally
        {
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSAServiceNI_update_outOfRange_offsetEdge() throws Exception
    {
        long rsaRef = 0;
        long keyRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            rsaServiceNI.initSign(rsaRef, keyRef, "SHA-256",
                    RSAServiceNI.PADDING_PKCS1, null, 0, TestUtil.RNDSrc);
            // off + len = 1 + 10 > 10 (size)
            rsaServiceNI.update(rsaRef, new byte[10], 1, 10);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset + length is out of range", e.getMessage());
        }
        finally
        {
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSAServiceNI_update_outOfRange_lenEdge() throws Exception
    {
        long rsaRef = 0;
        long keyRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            rsaServiceNI.initSign(rsaRef, keyRef, "SHA-256",
                    RSAServiceNI.PADDING_PKCS1, null, 0, TestUtil.RNDSrc);
            // off + len = 0 + 11 > 10
            rsaServiceNI.update(rsaRef, new byte[10], 0, 11);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset + length is out of range", e.getMessage());
        }
        finally
        {
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }


    // -----------------------------------------------------------------
    // sign
    // -----------------------------------------------------------------

    @Test
    public void RSAServiceNI_sign_nullRand() throws Exception
    {
        long rsaRef = 0;
        long keyRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            rsaServiceNI.initSign(rsaRef, keyRef, "SHA-256",
                    RSAServiceNI.PADDING_PKCS1, null, 0, TestUtil.RNDSrc);
            rsaServiceNI.sign(rsaRef, new byte[256], 0, null);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("supplied random source was null", e.getMessage());
        }
        finally
        {
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSAServiceNI_sign_offsetNegative() throws Exception
    {
        long rsaRef = 0;
        long keyRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            rsaServiceNI.initSign(rsaRef, keyRef, "SHA-256",
                    RSAServiceNI.PADDING_PKCS1, null, 0, TestUtil.RNDSrc);
            rsaServiceNI.sign(rsaRef, new byte[256], -1, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output offset is negative", e.getMessage());
        }
        finally
        {
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSAServiceNI_sign_offsetPastEnd() throws Exception
    {
        long rsaRef = 0;
        long keyRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            rsaServiceNI.initSign(rsaRef, keyRef, "SHA-256",
                    RSAServiceNI.PADDING_PKCS1, null, 0, TestUtil.RNDSrc);
            // offset == size+1 → past the end
            rsaServiceNI.sign(rsaRef, new byte[10], 11, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output offset + length is out of range", e.getMessage());
        }
        finally
        {
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSAServiceNI_sign_outputTooSmall() throws Exception
    {
        long rsaRef = 0;
        long keyRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            rsaServiceNI.initSign(rsaRef, keyRef, "SHA-256",
                    RSAServiceNI.PADDING_PKCS1, null, 0, TestUtil.RNDSrc);
            int needed = rsaServiceNI.sign(rsaRef, null, 0, TestUtil.RNDSrc);
            Assertions.assertTrue(needed > 0);
            // One byte short.
            rsaServiceNI.sign(rsaRef, new byte[needed - 1], 0, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output too small", e.getMessage());
        }
        finally
        {
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSAServiceNI_sign_notInitialized() throws Exception
    {
        long rsaRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            Assertions.assertTrue(rsaRef > 0);
            // Never called init.
            rsaServiceNI.sign(rsaRef, new byte[256], 0, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IllegalStateException e)
        {
            Assertions.assertEquals("not initialized", e.getMessage());
        }
        finally
        {
            rsaServiceNI.disposeSigner(rsaRef);
        }
    }

    @Test
    public void RSAServiceNI_sign_initForVerify() throws Exception
    {
        long rsaRef = 0;
        long keyRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            rsaServiceNI.initVerify(rsaRef, keyRef, "SHA-256",
                    RSAServiceNI.PADDING_PKCS1, null, 0);
            rsaServiceNI.sign(rsaRef, new byte[256], 0, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IllegalStateException e)
        {
            Assertions.assertEquals("unexpected state", e.getMessage());
        }
        finally
        {
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }


    // -----------------------------------------------------------------
    // verify
    // -----------------------------------------------------------------

    @Test
    public void RSAServiceNI_verify_nullSig() throws Exception
    {
        long rsaRef = 0;
        long keyRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            rsaServiceNI.initVerify(rsaRef, keyRef, "SHA-256",
                    RSAServiceNI.PADDING_PKCS1, null, 0);
            rsaServiceNI.verify(rsaRef, null, 0);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("sig is null", e.getMessage());
        }
        finally
        {
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSAServiceNI_verify_sigLenNegative() throws Exception
    {
        long rsaRef = 0;
        long keyRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            rsaServiceNI.initVerify(rsaRef, keyRef, "SHA-256",
                    RSAServiceNI.PADDING_PKCS1, null, 0);
            rsaServiceNI.verify(rsaRef, new byte[1], -1);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("sig length is negative", e.getMessage());
        }
        finally
        {
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSAServiceNI_verify_sigLenZero() throws Exception
    {
        // sigLen=0 against a 1-byte buffer is not a structural error;
        // it's a legitimate "doesn't verify" — confirm the path returns
        // JO_FAIL rather than throwing.
        long rsaRef = 0;
        long keyRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            rsaServiceNI.initVerify(rsaRef, keyRef, "SHA-256",
                    RSAServiceNI.PADDING_PKCS1, null, 0);
            int code = rsaServiceNI.verify(rsaRef, new byte[1], 0);
            Assertions.assertEquals(ErrorCode.JO_FAIL.getCode(), code);
        }
        finally
        {
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSAServiceNI_verify_sigOutOfRange_offsetEdge() throws Exception
    {
        long rsaRef = 0;
        long keyRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            rsaServiceNI.initVerify(rsaRef, keyRef, "SHA-256",
                    RSAServiceNI.PADDING_PKCS1, null, 0);
            rsaServiceNI.verify(rsaRef, new byte[10], 11);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("sig out of range", e.getMessage());
        }
        finally
        {
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSAServiceNI_verify_sigOutOfRange_emptyBuf() throws Exception
    {
        long rsaRef = 0;
        long keyRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            rsaServiceNI.initVerify(rsaRef, keyRef, "SHA-256",
                    RSAServiceNI.PADDING_PKCS1, null, 0);
            rsaServiceNI.verify(rsaRef, new byte[0], 1);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("sig out of range", e.getMessage());
        }
        finally
        {
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSAServiceNI_verify_notInitialized() throws Exception
    {
        long rsaRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            Assertions.assertTrue(rsaRef > 0);
            rsaServiceNI.verify(rsaRef, new byte[1], 1);
            Assertions.fail();
        }
        catch (IllegalStateException e)
        {
            Assertions.assertEquals("not initialized", e.getMessage());
        }
        finally
        {
            rsaServiceNI.disposeSigner(rsaRef);
        }
    }

    // -----------------------------------------------------------------
    // NI-direct happy-path coverage for the non-JCE entry points
    // -----------------------------------------------------------------

    /**
     * Round-trip the no-CRT private decode path. The JCE layer rejects
     * bare {@code RSAPrivateKeySpec} (OpenSSL needs the public exponent
     * to construct an {@code EVP_PKEY}); this NI-direct test passes
     * {@code n, e, d} explicitly and asserts the resulting key is
     * usable for signing. This locks in the non-CRT decode contract
     * for NI-only callers and exercises the rsa.c branch the JCE never
     * reaches.
     */
    @Test
    public void RSAServiceNI_decodePrivateComponents_roundTrip() throws Exception
    {
        long src = 0;
        long noCrt = 0;
        long signer = 0;
        try
        {
            // 1. Generate a CRT keypair to harvest n, e, d.
            src = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            Assertions.assertTrue(src > 0);

            byte[] n = fetchComponent(src, RSAServiceNI.COMP_MODULUS);
            byte[] e = fetchComponent(src, RSAServiceNI.COMP_PUBLIC_EXPONENT);
            byte[] d = fetchComponent(src, RSAServiceNI.COMP_PRIVATE_EXPONENT);

            // 2. Reconstruct as a non-CRT private key.
            noCrt = specNI.allocate();
            Assertions.assertTrue(noCrt > 0);
            int rc = rsaServiceNI.decodePrivateComponents(noCrt, n, e, d);
            Assertions.assertEquals(0, rc, "non-CRT decode should succeed");

            // 3. Sign with the reconstructed key.
            signer = rsaServiceNI.allocateSigner();
            rsaServiceNI.initSign(signer, noCrt, "SHA-256",
                    RSAServiceNI.PADDING_PKCS1, null, 0, TestUtil.RNDSrc);
            rsaServiceNI.update(signer, new byte[]{1, 2, 3}, 0, 3);
            int needed = rsaServiceNI.sign(signer, null, 0, TestUtil.RNDSrc);
            byte[] sig = new byte[needed];
            int written = rsaServiceNI.sign(signer, sig, 0, TestUtil.RNDSrc);
            Assertions.assertEquals(needed, written);
        }
        finally
        {
            rsaServiceNI.disposeSigner(signer);
            specNI.dispose(noCrt);
            specNI.dispose(src);
        }
    }

    /**
     * NI-direct fetch of a component into a too-small buffer must return
     * {@code JO_OUTPUT_TOO_SMALL}, surfaced as IllegalArgumentException
     * by the default-method error handler. Locks the rsa.c output-size
     * branch the JCE never trips (RSAComponents always sizes correctly).
     */
    @Test
    public void RSAServiceNI_getComponent_outputTooSmall() throws Exception
    {
        long keyRef = 0;
        try
        {
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            Assertions.assertTrue(keyRef > 0);
            int needed = rsaServiceNI.getComponent(keyRef, RSAServiceNI.COMP_MODULUS, null);
            Assertions.assertTrue(needed > 0);
            // One byte short.
            rsaServiceNI.getComponent(keyRef, RSAServiceNI.COMP_MODULUS, new byte[needed - 1]);
            Assertions.fail();
        }
        catch (IllegalArgumentException ex)
        {
            Assertions.assertEquals("output too small", ex.getMessage());
        }
        finally
        {
            specNI.dispose(keyRef);
        }
    }

    /**
     * Regression test for an FFI-only bug where {@code ni_sign}'s
     * post-call output copy-back was {@code outSeg.asByteBuffer().get(sig)},
     * which clobbered any caller-provided bytes preceding {@code outOff}
     * with zeros. Confirms the signature lands at {@code outOff} and the
     * leading bytes are untouched. The JNI path is unaffected (writes
     * directly into the Java byte[] without copy-back) but the test
     * runs on both bridges to lock the contract.
     */
    @Test
    public void RSAServiceNI_sign_writesAtOffsetWithoutClobberingPrefix() throws Exception
    {
        long signRef = 0;
        long verifyRef = 0;
        long keyRef = 0;
        try
        {
            signRef = rsaServiceNI.allocateSigner();
            verifyRef = rsaServiceNI.allocateSigner();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);

            byte[] msg = new byte[]{1, 2, 3};

            rsaServiceNI.initSign(signRef, keyRef, "SHA-256",
                    RSAServiceNI.PADDING_PKCS1, null, 0, TestUtil.RNDSrc);
            rsaServiceNI.update(signRef, msg, 0, msg.length);

            int needed = rsaServiceNI.sign(signRef, null, 0, TestUtil.RNDSrc);
            Assertions.assertEquals(256, needed);

            // Fill the WHOLE buffer with random bytes; save aside a copy
            // of the prefix so the post-sign comparison is against an
            // arbitrary value rather than a fixed sentinel.
            int prefix = 7;
            byte[] big = new byte[needed + prefix];
            new SecureRandom().nextBytes(big);
            byte[] expectedPrefix = new byte[prefix];
            System.arraycopy(big, 0, expectedPrefix, 0, prefix);

            int written = rsaServiceNI.sign(signRef, big, prefix, TestUtil.RNDSrc);
            Assertions.assertEquals(needed, written);

            // (1) Bridge contract: bytes preceding outOff must be untouched.
            byte[] actualPrefix = new byte[prefix];
            System.arraycopy(big, 0, actualPrefix, 0, prefix);
            Assertions.assertArrayEquals(expectedPrefix, actualPrefix,
                    "prefix bytes were modified by the sign call");

            // (2) Positive functional check: the signature at
            //     big[prefix..prefix+needed] verifies against the
            //     original message.
            byte[] sig = new byte[needed];
            System.arraycopy(big, prefix, sig, 0, needed);

            rsaServiceNI.initVerify(verifyRef, keyRef, "SHA-256",
                    RSAServiceNI.PADDING_PKCS1, null, 0);
            rsaServiceNI.update(verifyRef, msg, 0, msg.length);
            int verifyResult = rsaServiceNI.verify(verifyRef, sig, sig.length);
            Assertions.assertEquals(ErrorCode.JO_SUCCESS.getCode(), verifyResult,
                    "signature at offset " + prefix + " did not verify against "
                            + "the original message");

            // (3) Negative functional check: a 256-byte window starting
            //     ONE BYTE EARLIER (one byte INTO the random prefix) must
            //     NOT verify. The probability that a window of 256 random
            //     bytes is a valid PKCS#1 v1.5 signature for the given
            //     message is ~2^-2048 — verification must return JO_FAIL.
            //     If it returned SUCCESS the sign call had written at
            //     outOff-1 instead of outOff.
            byte[] shiftedSig = new byte[needed];
            System.arraycopy(big, prefix - 1, shiftedSig, 0, needed);

            rsaServiceNI.initVerify(verifyRef, keyRef, "SHA-256",
                    RSAServiceNI.PADDING_PKCS1, null, 0);
            rsaServiceNI.update(verifyRef, msg, 0, msg.length);
            int shiftedResult;
            try
            {
                shiftedResult = rsaServiceNI.verify(verifyRef, shiftedSig, shiftedSig.length);
            }
            catch (Exception expected)
            {
                // EVP_DigestVerifyFinal can return a structural error (-1)
                // for malformed signatures; the wrapper translates that
                // to OpenSSLException. That's also a correct rejection.
                shiftedResult = ErrorCode.JO_FAIL.getCode();
            }
            Assertions.assertEquals(ErrorCode.JO_FAIL.getCode(), shiftedResult,
                    "signature window shifted by 1 byte INTO the prefix "
                            + "verified successfully — sign wrote at outOff-1 "
                            + "instead of at outOff=" + prefix);
        }
        finally
        {
            rsaServiceNI.disposeSigner(signRef);
            rsaServiceNI.disposeSigner(verifyRef);
            specNI.dispose(keyRef);
        }
    }

    private byte[] fetchComponent(long keyRef, int component)
    {
        int len = rsaServiceNI.getComponent(keyRef, component, null);
        byte[] out = new byte[len];
        int written = rsaServiceNI.getComponent(keyRef, component, out);
        Assertions.assertEquals(len, written);
        return out;
    }

    @Test
    public void RSAServiceNI_verify_initForSign() throws Exception
    {
        long rsaRef = 0;
        long keyRef = 0;
        try
        {
            rsaRef = rsaServiceNI.allocateSigner();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            rsaServiceNI.initSign(rsaRef, keyRef, "SHA-256",
                    RSAServiceNI.PADDING_PKCS1, null, 0, TestUtil.RNDSrc);
            rsaServiceNI.verify(rsaRef, new byte[1], 1);
            Assertions.fail();
        }
        catch (IllegalStateException e)
        {
            Assertions.assertEquals("unexpected state", e.getMessage());
        }
        finally
        {
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }
}
