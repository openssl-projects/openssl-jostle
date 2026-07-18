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

package org.openssl.jostle.test.slhdsa;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.slhdsa.SLHDSAServiceNI;
import org.openssl.jostle.jcajce.provider.slhdsa.SLHDSASignatureSpi;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.test.crypto.TestNISelector;

import java.security.Security;

public class SLHDSALimitTest
{


    SLHDSAServiceNI slhdsaServiceNI = TestNISelector.getSLHDSANI();
    SpecNI specNI = TestNISelector.getSpecNI();

    @BeforeAll
    public static void beforeAll()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    @Test
    public void slhdsa_nullSignerCtx_rejectedTyped() throws Exception
    {
        // A 0/null ctx handle at any SLH-DSA session entry point must surface the
        // typed JO_SIGNER_CTX_IS_NULL -> IllegalArgumentException("signer context
        // is null"), NOT abort the JVM via jo_assert. The ctx null-check is the
        // first thing each bridge does, so the remaining args are never reached.
        // Regression lock for the ctx null-check bridge fix (slhdsa_ni_jni.c /
        // slhdsa_ni_ffi.c); runs on both JNI and FFI via TestNISelector.
        byte[] context = new byte[0];
        byte[] sig = new byte[256];
        Assertions.assertEquals("signer context is null", Assertions.assertThrows(IllegalArgumentException.class,
                () -> slhdsaServiceNI.initSign(0, 0, context, 0, 0, 0, TestUtil.RNDSrc)).getMessage());
        Assertions.assertEquals("signer context is null", Assertions.assertThrows(IllegalArgumentException.class,
                () -> slhdsaServiceNI.initVerify(0, 0, context, 0, 0, 0)).getMessage());
        Assertions.assertEquals("signer context is null", Assertions.assertThrows(IllegalArgumentException.class,
                () -> slhdsaServiceNI.update(0, new byte[8], 0, 8)).getMessage());
        Assertions.assertEquals("signer context is null", Assertions.assertThrows(IllegalArgumentException.class,
                () -> slhdsaServiceNI.sign(0, sig, 0, TestUtil.RNDSrc)).getMessage());
        Assertions.assertEquals("signer context is null", Assertions.assertThrows(IllegalArgumentException.class,
                () -> slhdsaServiceNI.verify(0, sig, sig.length)).getMessage());
    }

    @Test
    public void SLHDSAServiceNI_sign_writesAtOffsetWithoutClobbering() throws Exception
    {
        // Regression for the FFI whole-array copy-back clobber (finding 4):
        // SLHDSAServiceFFI.ni_sign allocated a zero-filled arena for the whole
        // output array and copied ALL of it back, zeroing caller bytes outside
        // [offset, offset+written). Sign at a non-zero offset into an oversized
        // random-filled buffer; the bytes outside the written window must be
        // preserved and the signature at the offset must verify. Runs on JNI
        // and FFI via TestNISelector; only the FFI path exhibited the clobber.
        // SLH_DSA_SHA2_128f is the fast-signing 128-bit variant (keeps the
        // sequential limit-test cost down).
        java.security.SecureRandom rnd = new java.security.SecureRandom();
        long keyRef = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType(), TestUtil.RNDSrc);
        long signer = slhdsaServiceNI.allocateSigner();
        long verifier = slhdsaServiceNI.allocateSigner();
        try
        {
            byte[] msg = new byte[64];
            rnd.nextBytes(msg);

            slhdsaServiceNI.initSign(signer, keyRef, new byte[0], 0, 0, 0, TestUtil.RNDSrc);
            slhdsaServiceNI.update(signer, msg, 0, msg.length);
            int sigLen = (int) slhdsaServiceNI.sign(signer, null, 0, TestUtil.RNDSrc);
            Assertions.assertTrue(sigLen > 0);

            int prefix = 5;
            int suffix = 7;
            byte[] big = new byte[prefix + sigLen + suffix];
            rnd.nextBytes(big);
            byte[] snapshot = big.clone();

            int written = (int) slhdsaServiceNI.sign(signer, big, prefix, TestUtil.RNDSrc);
            Assertions.assertEquals(sigLen, written);

            Assertions.assertArrayEquals(java.util.Arrays.copyOfRange(snapshot, 0, prefix),
                    java.util.Arrays.copyOfRange(big, 0, prefix), "bytes before outOff were clobbered");
            Assertions.assertArrayEquals(java.util.Arrays.copyOfRange(snapshot, prefix + written, big.length),
                    java.util.Arrays.copyOfRange(big, prefix + written, big.length), "bytes after the signature were clobbered");

            byte[] sig = java.util.Arrays.copyOfRange(big, prefix, prefix + written);
            slhdsaServiceNI.initVerify(verifier, keyRef, new byte[0], 0, 0, 0);
            slhdsaServiceNI.update(verifier, msg, 0, msg.length);
            Assertions.assertEquals(ErrorCode.JO_SUCCESS.getCode(), slhdsaServiceNI.verify(verifier, sig, sig.length));
        }
        finally
        {
            slhdsaServiceNI.disposeSigner(signer);
            slhdsaServiceNI.disposeSigner(verifier);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void testSLHDSAGenerateKeyPair_keyGenWrongType() throws Exception
    {
        for (int type : new int[]{-1, 0, 4, 17})
        {
            try
            {
                slhdsaServiceNI.generateKeyPair(type, TestUtil.RNDSrc);
                Assertions.fail();
            }
            catch (IllegalArgumentException e)
            {
                Assertions.assertEquals("invalid key type for SLH-DSA", e.getMessage());
            }

        }
    }


    @Test
    public void SLHDSAServiceJNI_generateKeyPair_nullRand() throws Exception
    {
        byte[] seed = new byte[64];
        int seedLen = 64;

        try
        {

            slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_192s.getKsType(), seed, seedLen, null);

            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("supplied random source was null", e.getMessage());
        }
    }

    @Test
    public void SLHDSAServiceJNI_generateKeyPair_seedIsNull() throws Exception
    {
        byte[] seed = null;
        int seedLen = 0;

        try
        {

            slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_192s.getKsType(), seed, seedLen, TestUtil.RNDSrc);

            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("seed is null", e.getMessage());
        }
    }

    @Test
    public void SLHDSAServiceJNI_generateKeyPair_seedLenNegative() throws Exception
    {
        byte[] seed = new byte[32];
        int seedLen = -1;

        try
        {

            slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_192f.getKsType(), seed, seedLen, TestUtil.RNDSrc);

            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("seed len is negative", e.getMessage());
        }
    }

    @Test
    public void SLHDSAServiceJNI_generateKeyPair_seedLenPastEndOfArray() throws Exception
    {
        byte[] seed = new byte[16];
        int seedLen = 17;

        try
        {

            slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType(), seed, seedLen, TestUtil.RNDSrc);

            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("seed length is out of range", e.getMessage());
        }
    }

    @Test
    public void SLHDSAServiceJNI_generateKeyPair_invalidSeedLength_128() throws Exception
    {
        byte[] seed = new byte[16 * 3];
        int seedLen = seed.length - 1;

        try
        {

            slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType(), seed, seedLen, TestUtil.RNDSrc);

            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("invalid seed length", e.getMessage());
        }
    }


    @Test
    public void SLHDSAServiceJNI_generateKeyPair_invalidSeedLength_192() throws Exception
    {
        byte[] seed = new byte[24 * 3];
        int seedLen = seed.length - 1;

        try
        {

            slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_192f.getKsType(), seed, seedLen, TestUtil.RNDSrc);

            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("invalid seed length", e.getMessage());
        }
    }

    @Test
    public void SLHDSAServiceJNI_generateKeyPair_invalidSeedLength_256() throws Exception
    {
        byte[] seed = new byte[24 * 3];
        int seedLen = seed.length - 1;

        try
        {

            slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_256f.getKsType(), seed, seedLen, TestUtil.RNDSrc);

            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("invalid seed length", e.getMessage());
        }

    }


    @Test
    public void SLHDSAServiceJNI_generateKeyPair_noSeedButLength() throws Exception
    {
        byte[] seed = null;
        int seedLen = 48;

        try
        {

            slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType(), seed, seedLen, TestUtil.RNDSrc);

            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("seed is null", e.getMessage());
        }
    }

    @Test
    public void SLHDSAServiceJNI_generateKeyPair_seedWrongKeyType() throws Exception
    {
        byte[] seed = new byte[48];
        int seedLen = 48;

        try
        {

            slhdsaServiceNI.generateKeyPair(Integer.MAX_VALUE, seed, seedLen, TestUtil.RNDSrc);

            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("invalid key type for SLH-DSA", e.getMessage());
        }
    }


    @Test
    public void SLHDSAServiceJNI_generateKeyPair_incorrectSeedLen() throws Exception
    {
        for (OSSLKeyType keyType : new OSSLKeyType[]{
                OSSLKeyType.SLH_DSA_SHA2_128f,
                OSSLKeyType.SLH_DSA_SHA2_128s,
                OSSLKeyType.SLH_DSA_SHA2_192f,
                OSSLKeyType.SLH_DSA_SHA2_192s,
                OSSLKeyType.SLH_DSA_SHA2_256f,
                OSSLKeyType.SLH_DSA_SHA2_256s,
                OSSLKeyType.SLH_DSA_SHAKE_128f,
                OSSLKeyType.SLH_DSA_SHAKE_128s,
                OSSLKeyType.SLH_DSA_SHAKE_192f,
                OSSLKeyType.SLH_DSA_SHAKE_192s,
                OSSLKeyType.SLH_DSA_SHAKE_256f,
                OSSLKeyType.SLH_DSA_SHAKE_256s
        })
        {
            int base = 0;
            if (keyType.name().contains("128"))
            {
                base = 16;
            }
            else
            {
                if (keyType.name().contains("192"))
                {
                    base = 24;
                }
                else
                {
                    if (keyType.name().contains("256"))
                    {
                        base = 32;
                    }
                    else
                    {
                        Assertions.fail();
                    }
                }
            }

            byte[] seed = new byte[base * 3];
            int seedLen = seed.length - 1;

            try
            {
               
               slhdsaServiceNI.generateKeyPair(keyType.ordinal(), seed, seedLen, TestUtil.RNDSrc);
               
                Assertions.fail();
            }
            catch (IllegalArgumentException e)
            {
                Assertions.assertEquals("invalid seed length", e.getMessage());
            }
        }
    }


    @Test
    public void SLHDSAServiceJNI_getPublicKey_nullKeyRef() throws Exception
    {

        long ref = 0;
        try
        {
            slhdsaServiceNI.getPublicKey(0, new byte[0]);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("key spec is null", e.getMessage());
        }
        finally
        {
            specNI.dispose(ref);
        }

    }

    @Test
    public void SLHDSAServiceJNI_getPublicKey_keyRefNullKey() throws Exception
    {
        long ref = TestNISelector.SpecNI.allocate();
        try
        {
            slhdsaServiceNI.getPublicKey(ref, new byte[0]);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("key spec has null key", e.getMessage());
        }
        finally
        {
            specNI.dispose(ref);
        }

    }

    @Test
    public void SLHDSAServiceJNI_getPublicKey_outLen() throws Exception
    {
        long ref = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_256f.getKsType(), TestUtil.RNDSrc);
        try
        {
            slhdsaServiceNI.getPublicKey(ref, new byte[10]);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output too small", e.getMessage());
        }
        finally
        {
            specNI.dispose(ref);
        }
    }

    @Test
    public void SLHDSAServiceJNI_getPrivateKey_nullKeyRef() throws Exception
    {

        long ref = 0;
        try
        {
            slhdsaServiceNI.getPrivateKey(0, new byte[0]);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("key spec is null", e.getMessage());
        }
        finally
        {
            specNI.dispose(ref);
        }

    }

    @Test
    public void SLHDSAServiceJNI_getPrivateKey_keyRefNullKey() throws Exception
    {
        long ref = TestNISelector.SpecNI.allocate();
        try
        {
            slhdsaServiceNI.getPrivateKey(ref, new byte[0]);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("key spec has null key", e.getMessage());
        }
        finally
        {
            specNI.dispose(ref);
        }
    }


    @Test
    public void SLHDSAServiceJNI_getPrivateKey_outLen() throws Exception
    {
        long ref = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), TestUtil.RNDSrc);
        try
        {
            slhdsaServiceNI.getPrivateKey(ref, new byte[10]);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output too small", e.getMessage());
        }
        finally
        {
            specNI.dispose(ref);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_decode_1publicKey_nullKeySpec() throws Exception
    {

        long keyRef = 0;
        try
        {
            slhdsaServiceNI.decode_publicKey(keyRef, OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), new byte[1024], 0, 1024);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("key spec is null", e.getMessage());
        }
        finally
        {
        }
    }

    @Test()
    public void SLHDSAServiceJNI_decode_1publicKey_inputNull() throws Exception
    {

        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);

            slhdsaServiceNI.decode_publicKey(keyRef, OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), null, 0, 0);
            Assertions.fail();
        }
        catch (NullPointerException e)
        {
            Assertions.assertEquals("input is null", e.getMessage());
        }
        finally
        {
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_decode_1publicKey_inputOffsetNegative() throws Exception
    {

        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);

            slhdsaServiceNI.decode_publicKey(keyRef, OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), new byte[0], -1, 0);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset is negative", e.getMessage());
        }
        finally
        {
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_decode_1publicKey_inputLenNegative() throws Exception
    {

        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);

            slhdsaServiceNI.decode_publicKey(keyRef, OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), new byte[0], 0, -1);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input len is negative", e.getMessage());
        }
        finally
        {
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_decode_1publicKey_inputOutOfRange_1() throws Exception
    {

        // offset + len > size
        // 1 + 10 > 10
        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.decode_publicKey(keyRef, OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), new byte[10], 1, 10);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset + length is out of range", e.getMessage());
        }
        finally
        {
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_decode_1publicKey_inputOutOfRange_2() throws Exception
    {

        // offset + len > size
        // 0 + 11 > 10

        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);
           slhdsaServiceNI.decode_publicKey(keyRef, OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), new byte[10], 0, 11);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset + length is out of range", e.getMessage());
        }
        finally
        {
            specNI.dispose(keyRef);
        }
    }

    //TODO  @Test()
    public void SLHDSAServiceJNI_decode_1publicKey_keyLength() throws Exception
    {
        // Either side of each valid key len
        for (int len : new int[]{1311, 1313, 1951, 1953, 2951, 2953})
        {
            long keyRef = 0;
            try
            {
                keyRef = TestNISelector.getSpecNI().allocate();
                Assertions.assertTrue(keyRef > 0);
                slhdsaServiceNI.decode_publicKey(keyRef, OSSLKeyType.NONE.getKsType(), new byte[len], 0, len);
                Assertions.fail();
            }
            catch (IllegalArgumentException e)
            {
                Assertions.assertEquals("unknown key length", e.getMessage());
            }
            finally
            {
                specNI.dispose(keyRef);
            }
        }
    }

    @Test()
    public void SLHDSAServiceJNI_decode_1publicKey_keyType() throws Exception
    {
        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.decode_publicKey(keyRef, 99, new byte[10], 0, 10);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("invalid key type for SLH-DSA", e.getMessage());
        }
        finally
        {
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_decode_1publicKey_inputWrongSize4KeyType() throws Exception
    {
        long keyRef = 0;


        for (OSSLKeyType keyType : new OSSLKeyType[]{
                OSSLKeyType.SLH_DSA_SHA2_128f,
                OSSLKeyType.SLH_DSA_SHA2_128s,
                OSSLKeyType.SLH_DSA_SHA2_192f,
                OSSLKeyType.SLH_DSA_SHA2_192s,
                OSSLKeyType.SLH_DSA_SHA2_256f,
                OSSLKeyType.SLH_DSA_SHA2_256s,
                OSSLKeyType.SLH_DSA_SHAKE_128f,
                OSSLKeyType.SLH_DSA_SHAKE_128s,
                OSSLKeyType.SLH_DSA_SHAKE_192f,
                OSSLKeyType.SLH_DSA_SHAKE_192s,
                OSSLKeyType.SLH_DSA_SHAKE_256f,
                OSSLKeyType.SLH_DSA_SHAKE_256s
        })
        {
            int base = 0;
            if (keyType.name().contains("128"))
            {
                base = 16;
            }
            else
            {
                if (keyType.name().contains("192"))
                {
                    base = 24;
                }
                else
                {
                    if (keyType.name().contains("256"))
                    {
                        base = 32;
                    }
                    else
                    {
                        Assertions.fail();
                    }
                }
            }


            { // too short
                byte[] key = (byte[]) new byte[(base * 2) - 1];

                try
                {
                    keyRef = TestNISelector.getSpecNI().allocate();
                    Assertions.assertTrue(keyRef > 0);
                    slhdsaServiceNI.decode_publicKey(keyRef, keyType.ordinal(), key, 0, key.length);
                    Assertions.fail();
                }
                catch (IllegalArgumentException e)
                {
                    Assertions.assertEquals("incorrect public key length", e.getMessage());
                }
                finally
                {
                    specNI.dispose(keyRef);
                }
            }


            { // ok
                byte[] key = (byte[]) new byte[(base * 2)];

                try
                {
                    keyRef = TestNISelector.getSpecNI().allocate();
                    Assertions.assertTrue(keyRef > 0);
                    slhdsaServiceNI.decode_publicKey(keyRef, keyType.ordinal(), key, 0, key.length);
                }
                finally
                {
                    specNI.dispose(keyRef);
                }
            }


            { // too long
                byte[] key = (byte[]) new byte[(base * 2) + 1];

                try
                {
                    keyRef = TestNISelector.getSpecNI().allocate();
                    Assertions.assertTrue(keyRef > 0);
                    slhdsaServiceNI.decode_publicKey(keyRef, keyType.ordinal(), key, 0, key.length);
                    Assertions.fail();
                }
                catch (IllegalArgumentException e)
                {
                    Assertions.assertEquals("incorrect public key length", e.getMessage());
                }
                finally
                {
                    specNI.dispose(keyRef);
                }
            }

        }

    }

    // Boken input for public key is an OpsTest see SLHDSAOpsTest class


    @Test()
    public void SLHDSAServiceJNI_decode_1privateKey_inputNull() throws Exception
    {

        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);

           slhdsaServiceNI.decode_privateKey(keyRef, OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), null, 0, 0);
            Assertions.fail();
        }
        catch (NullPointerException e)
        {
            Assertions.assertEquals("input is null", e.getMessage());
        }
        finally
        {
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_decode_1privateKey_inputOffsetNegative() throws Exception
    {

        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);

            slhdsaServiceNI.decode_privateKey(keyRef, OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), new byte[0], -1, 0);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset is negative", e.getMessage());
        }
        finally
        {
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_decode_1privateKey_inputLenNegative() throws Exception
    {

        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);

            slhdsaServiceNI.decode_privateKey(keyRef, OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), new byte[0], 0, -1);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input len is negative", e.getMessage());
        }
        finally
        {
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_decode_1privateKey_inputOutOfRange_1() throws Exception
    {

        // offset + len > size
        // 1 + 10 > 10
        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.decode_privateKey(keyRef, OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), new byte[10], 1, 10);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset + length is out of range", e.getMessage());
        }
        finally
        {
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_decode_1privateKey_inputOutOfRange_2() throws Exception
    {

        // offset + len > size
        // 0 + 11 > 10

        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.decode_privateKey(keyRef, OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), new byte[10], 0, 11);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset + length is out of range", e.getMessage());
        }
        finally
        {
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_decode_1privateKey_keyLength() throws Exception
    {
        long keyRef = 0;


        for (OSSLKeyType keyType : new OSSLKeyType[]{
                OSSLKeyType.SLH_DSA_SHA2_128f,
                OSSLKeyType.SLH_DSA_SHA2_128s,
                OSSLKeyType.SLH_DSA_SHA2_192f,
                OSSLKeyType.SLH_DSA_SHA2_192s,
                OSSLKeyType.SLH_DSA_SHA2_256f,
                OSSLKeyType.SLH_DSA_SHA2_256s,
                OSSLKeyType.SLH_DSA_SHAKE_128f,
                OSSLKeyType.SLH_DSA_SHAKE_128s,
                OSSLKeyType.SLH_DSA_SHAKE_192f,
                OSSLKeyType.SLH_DSA_SHAKE_192s,
                OSSLKeyType.SLH_DSA_SHAKE_256f,
                OSSLKeyType.SLH_DSA_SHAKE_256s
        })
        {
            int base = 0;
            if (keyType.name().contains("128"))
            {
                base = 16;
            }
            else
            {
                if (keyType.name().contains("192"))
                {
                    base = 24;
                }
                else
                {
                    if (keyType.name().contains("256"))
                    {
                        base = 32;
                    }
                    else
                    {
                        Assertions.fail();
                    }
                }
            }


            { // too short
                byte[] key = (byte[]) new byte[(base * 4) - 1];

                try
                {
                    keyRef = TestNISelector.getSpecNI().allocate();
                    Assertions.assertTrue(keyRef > 0);
                    slhdsaServiceNI.decode_privateKey(keyRef, keyType.ordinal(), key, 0, key.length);
                    Assertions.fail();
                }
                catch (IllegalArgumentException e)
                {
                    Assertions.assertEquals("incorrect private key length", e.getMessage());
                }
                finally
                {
                    specNI.dispose(keyRef);
                }
            }


            { // ok
                byte[] key = (byte[]) new byte[(base * 4)];

                try
                {
                    keyRef = TestNISelector.getSpecNI().allocate();
                    Assertions.assertTrue(keyRef > 0);
                    slhdsaServiceNI.decode_privateKey(keyRef, keyType.ordinal(), key, 0, key.length);
                }
                finally
                {
                    specNI.dispose(keyRef);
                }
            }


            { // too long
                byte[] key = (byte[]) new byte[(base * 4) + 1];

                try
                {
                    keyRef = TestNISelector.getSpecNI().allocate();
                    Assertions.assertTrue(keyRef > 0);
                    slhdsaServiceNI.decode_privateKey(keyRef, keyType.ordinal(), key, 0, key.length);
                    Assertions.fail();
                }
                catch (IllegalArgumentException e)
                {
                    Assertions.assertEquals("incorrect private key length", e.getMessage());
                }
                finally
                {
                    specNI.dispose(keyRef);
                }
            }

        }
    }

    @Test()
    public void SLHDSAServiceJNI_decode_1privateKey_keyType() throws Exception
    {
        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);
           slhdsaServiceNI.decode_privateKey(keyRef, 99, new byte[10], 0, 10);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("invalid key type for SLH-DSA", e.getMessage());
        }
        finally
        {
            specNI.dispose(keyRef);
        }
    }


    // init Verifier

    @Test()
    public void SLHDSAServiceJNI_initVerify_nullContextArray() throws Exception
    {
        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = TestNISelector.getSLHDSANI().generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.initVerify(slhdsaRef, keyRef, null, 0, 0, 0);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("context array is null", e.getMessage());
        }
        finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }

    // negative context len is a valid input so no limit test on negative len


    @Test()
    public void SLHDSAServiceJNI_initVerify_ctxLenPastEndOfContext_1() throws Exception
    {


        // Zero length array but declared len of 1

        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = TestNISelector.getSLHDSANI().generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.initVerify(slhdsaRef, keyRef, new byte[0], 1, 0, 0);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("context length is past end of context", e.getMessage());
        }
        finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_initVerify_ctxLenPastEndOfContext_2() throws Exception
    {

        // array length of 1  but declared len of 2

        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = TestNISelector.getSLHDSANI().generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.initVerify(slhdsaRef, keyRef, new byte[1], 2, 0, 0);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("context length is past end of context", e.getMessage());
        }
        finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_initVerify_ctxTooLong() throws Exception
    {

        // array length of 1  but declared len of 2

        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = TestNISelector.getSLHDSANI().generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.initVerify(slhdsaRef, keyRef, new byte[256], 256, 0, 0);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("context length is too long", e.getMessage());
        }
        finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_initVerify_nullKey() throws Exception
    {

        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            slhdsaServiceNI.initVerify(slhdsaRef, keyRef, new byte[1], 1, 0, 0);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("key spec is null", e.getMessage());
        }
        finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_initVerify_keySpecNullKey() throws Exception
    {

        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = specNI.allocate();

            Assertions.assertTrue(keyRef > 0);
           slhdsaServiceNI.initVerify(slhdsaRef, keyRef, new byte[1], 1, 0, 0);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("key spec has null key", e.getMessage());
        }
        finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_initVerify_unknownMessageEncodingParam() throws Exception
    {
        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.initVerify(slhdsaRef, keyRef, new byte[1], 1, 3, 0);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("invalid message encoding param", e.getMessage());
        }
        finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_initVerify_unknownDetParam() throws Exception
    {
        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.initVerify(slhdsaRef, keyRef, new byte[1], 1, 0, 3);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("invalid deterministic param", e.getMessage());
        }
        finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }


    // init Signer


    @Test()
    public void SLHDSAServiceJNI_initSign_nullRand_1() throws Exception
    {

        // array length of 1  but declared len of 2

        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            TestNISelector.getSLHDSANI().generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), null);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("supplied random source was null", e.getMessage());
        }
        finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            if (keyRef != 0)
            {
                specNI.dispose(keyRef);
            }
        }
    }

    @Test()
    public void SLHDSAServiceJNI_sign_nullRand() throws Exception
    {

        // array length of 1  but declared len of 2

        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = TestNISelector.getSLHDSANI().generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.initSign(slhdsaRef, keyRef, new byte[256], 256, 0, 0, null);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("supplied random source was null", e.getMessage());
        }
        finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            if (keyRef != 0)
            {
                specNI.dispose(keyRef);
            }
        }
    }


    @Test()
    public void SLHDSAServiceJNI_initSign_nullContextArray() throws Exception
    {

        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = TestNISelector.getSLHDSANI().generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.initVerify(slhdsaRef, keyRef, null, 0, 0, 0);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("context array is null", e.getMessage());
        }
        finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }

    // negative context len is a valid input so no limit test on negative len


    @Test()
    public void SLHDSAServiceJNI_initSign_ctxLenPastEndOfContext_1() throws Exception
    {

        // Zero length array but declared len of 1

        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = TestNISelector.getSLHDSANI().generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.initSign(slhdsaRef, keyRef, new byte[0], 1, 0, 0, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("context length is past end of context", e.getMessage());
        }
        finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_initSign_ctxLenPastEndOfContext_2() throws Exception
    {

        // array length of 1  but declared len of 2

        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = TestNISelector.getSLHDSANI().generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.initSign(slhdsaRef, keyRef, new byte[1], 2, 0, 0, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("context length is past end of context", e.getMessage());
        }
        finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_initSign_ctxTooLong() throws Exception
    {

        // array length of 1  but declared len of 2

        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = TestNISelector.getSLHDSANI().generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.initSign(slhdsaRef, keyRef, new byte[256], 256, 0, 0, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("context length is too long", e.getMessage());
        }
        finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void SLHDSAServiceJNI_initSign_nullKey() throws Exception
    {

        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
           slhdsaServiceNI.initSign(slhdsaRef, keyRef, new byte[1], 1, 0, 0, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("key spec is null", e.getMessage());
        }
        finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_initSign_keySpecNullKey() throws Exception
    {

        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = specNI.allocate();

            Assertions.assertTrue(keyRef > 0);
           slhdsaServiceNI.initSign(slhdsaRef, keyRef, new byte[1], 1, 0, 0, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("key spec has null key", e.getMessage());
        }
        finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_initSign_unknownMessageEncoding() throws Exception
    {

        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
           slhdsaServiceNI.initSign(slhdsaRef, keyRef, new byte[1], 1, 3, 0, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("invalid message encoding param", e.getMessage());
        }
        finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void SLHDSAServiceJNI_initSign_unknownDeterminisiticParam() throws Exception
    {
        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
           slhdsaServiceNI.initSign(slhdsaRef, keyRef, new byte[1], 1, 0, 3, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("invalid deterministic param", e.getMessage());
        }
        finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void SLHDSAServiceJNI_slhdsa_update_notInitialised() throws Exception
    {
        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            // slhdsaServiceNI.initSign(slhdsaRef, keyRef, new byte[1], 1, 3));

           slhdsaServiceNI.update(slhdsaRef, new byte[0], 0, 0);

            Assertions.fail();
        }
        catch (IllegalStateException e)
        {
            Assertions.assertEquals("not initialized", e.getMessage());
        }
        finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void SLHDSAServiceJNI_slhdsa_update_nullInput() throws Exception
    {
        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
           slhdsaServiceNI.initSign(slhdsaRef, keyRef, new byte[0], 0, 0, 0, TestUtil.RNDSrc);

           slhdsaServiceNI.update(slhdsaRef, null, 0, 0);

            Assertions.fail();
        }
        catch (NullPointerException e)
        {
            Assertions.assertEquals("input is null", e.getMessage());
        }
        finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void SLHDSAServiceJNI_slhdsa_update_inputOffsetNegative() throws Exception
    {
        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
           slhdsaServiceNI.initSign(slhdsaRef, keyRef, new byte[0], 0, 0, 0, TestUtil.RNDSrc);

           slhdsaServiceNI.update(slhdsaRef, new byte[0], -1, 0);

            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset is negative", e.getMessage());
        }
        finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_slhdsa_update_inputLenNegative() throws Exception
    {
        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
           slhdsaServiceNI.initSign(slhdsaRef, keyRef, new byte[0], 0, 0, 0, TestUtil.RNDSrc);

           slhdsaServiceNI.update(slhdsaRef, new byte[0], 0, -1);

            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input len is negative", e.getMessage());
        }
        finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void SLHDSAServiceJNI_slhdsa_update_inputOutOfRange_1() throws Exception
    {

        // 10 byte input
        // 0 offset
        // 11 byte len

        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
           slhdsaServiceNI.initSign(slhdsaRef, keyRef, new byte[0], 0, 0, 0, TestUtil.RNDSrc);

           slhdsaServiceNI.update(slhdsaRef, new byte[10], 0, 11);

            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset + length is out of range", e.getMessage());
        }
        finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void SLHDSAServiceJNI_slhdsa_update_inputOutOfRange_2() throws Exception
    {

        // 10 byte input
        // 1 offset
        // 10 byte len

        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
           slhdsaServiceNI.initSign(slhdsaRef, keyRef, new byte[0], 0, 0, 0, TestUtil.RNDSrc);

           slhdsaServiceNI.update(slhdsaRef, new byte[10], 1, 10);

            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset + length is out of range", e.getMessage());
        }
        finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }


    // NB Sign accepts null input, returns length of signature so null input is valid

    @Test()
    public void SLHDSAServiceJNI_slhdsa_sign_outOffsetNegative() throws Exception
    {

        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
           slhdsaServiceNI.initSign(slhdsaRef, keyRef, new byte[0], 0, 0, 0, TestUtil.RNDSrc);

           slhdsaServiceNI.sign(slhdsaRef, new byte[0], -1, TestUtil.RNDSrc);

            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output offset is negative", e.getMessage());
        }
        finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_slhdsa_sign_outputRange() throws Exception
    {

        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
           slhdsaServiceNI.initSign(slhdsaRef, keyRef, new byte[0], 0, 0, 0, TestUtil.RNDSrc);

           slhdsaServiceNI.sign(slhdsaRef, new byte[0], 1, TestUtil.RNDSrc);

            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output offset + length is out of range", e.getMessage());
        }
        finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_slhdsa_sign_notInitialized() throws Exception
    {

        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            //slhdsaServiceNI.initSign(slhdsaRef, keyRef, new byte[0], 0, 0));

           slhdsaServiceNI.sign(slhdsaRef, new byte[0], 0, TestUtil.RNDSrc);

            Assertions.fail();
        }
        catch (IllegalStateException e)
        {
            Assertions.assertEquals("not initialized", e.getMessage());
        }
        finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void SLHDSAServiceJNI_slhdsa_sign_initVerify() throws Exception
    {

        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
           slhdsaServiceNI.initVerify(slhdsaRef, keyRef, new byte[0], 0, 0, 0);

           slhdsaServiceNI.sign(slhdsaRef, new byte[0], 0, TestUtil.RNDSrc);

            Assertions.fail();
        }
        catch (IllegalStateException e)
        {
            Assertions.assertEquals("unexpected state", e.getMessage());
        }
        finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void SLHDSAServiceJNI_slhdsa_sign_outputTooSmall_1() throws Exception
    {

        //
        // offset is zero
        //

        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
           slhdsaServiceNI.initSign(slhdsaRef, keyRef, new byte[0], 0, 0, 0, TestUtil.RNDSrc);

            long len =slhdsaServiceNI.sign(slhdsaRef, null, 0, TestUtil.RNDSrc);

            byte[] sig = new byte[(int) len - 1];

           slhdsaServiceNI.sign(slhdsaRef, sig, 0, TestUtil.RNDSrc);

            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output too small", e.getMessage());
        }
        finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void SLHDSAServiceJNI_slhdsa_sign_outputTooSmall_2() throws Exception
    {

        //
        // offset is 1
        //

        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
           slhdsaServiceNI.initSign(slhdsaRef, keyRef, new byte[0], 0, 0, 0, TestUtil.RNDSrc);

            long len =slhdsaServiceNI.sign(slhdsaRef, null, 0, TestUtil.RNDSrc);

            byte[] sig = new byte[(int) len];

           slhdsaServiceNI.sign(slhdsaRef, sig, 1, TestUtil.RNDSrc);

            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output too small", e.getMessage());
        }
        finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void SLHDSAServiceJNI_slhdsa_verify_nullSig() throws Exception
    {


        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
           slhdsaServiceNI.initVerify(slhdsaRef, keyRef, new byte[0], 0, SLHDSASignatureSpi.MessageEncoding.PURE.ordinal(), SLHDSASignatureSpi.Deterministic.DETERMINISTIC.ordinal());

           slhdsaServiceNI.verify(slhdsaRef, null, 0);

            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("sig is null", e.getMessage());
        }
        finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void SLHDSAServiceJNI_slhdsa_verify_sigLenZero() throws Exception
    {
        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
           slhdsaServiceNI.initVerify(slhdsaRef, keyRef, new byte[0], 0, SLHDSASignatureSpi.MessageEncoding.PURE.ordinal(), SLHDSASignatureSpi.Deterministic.DETERMINISTIC.ordinal());

            long code =slhdsaServiceNI.verify(slhdsaRef, new byte[1], 0);
            Assertions.assertEquals(ErrorCode.JO_FAIL.getCode(), code);

        }
        finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_slhdsa_verify_sigLenNegative() throws Exception
    {
        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
           slhdsaServiceNI.initVerify(slhdsaRef, keyRef, new byte[0], 0, SLHDSASignatureSpi.MessageEncoding.PURE.ordinal(), SLHDSASignatureSpi.Deterministic.DETERMINISTIC.ordinal());

           slhdsaServiceNI.verify(slhdsaRef, new byte[1], -1);

            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("sig length is negative", e.getMessage());
        }
        finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void SLHDSAServiceJNI_slhdsa_verify_sigLenOutOfRange_1() throws Exception
    {
        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
           slhdsaServiceNI.initVerify(slhdsaRef, keyRef, new byte[0], 0, SLHDSASignatureSpi.MessageEncoding.PURE.ordinal(), SLHDSASignatureSpi.Deterministic.DETERMINISTIC.ordinal());

           slhdsaServiceNI.verify(slhdsaRef, new byte[10], 11);

            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("sig out of range", e.getMessage());
        }
        finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_slhdsa_verify_sigLenOutOfRange_2() throws Exception
    {
        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
           slhdsaServiceNI.initVerify(slhdsaRef, keyRef, new byte[0], 0, SLHDSASignatureSpi.MessageEncoding.PURE.ordinal(), SLHDSASignatureSpi.Deterministic.DETERMINISTIC.ordinal());

           slhdsaServiceNI.verify(slhdsaRef, new byte[0], 1);

            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("sig out of range", e.getMessage());
        }
        finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_slhdsa_verify_initForSigning() throws Exception
    {
        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
           slhdsaServiceNI.initSign(slhdsaRef, keyRef, new byte[0], 0, SLHDSASignatureSpi.MessageEncoding.PURE.ordinal(), SLHDSASignatureSpi.Deterministic.DETERMINISTIC.ordinal(), TestUtil.RNDSrc);

           slhdsaServiceNI.verify(slhdsaRef, new byte[1], 1);

            Assertions.fail();
        }
        catch (IllegalStateException e)
        {
            Assertions.assertEquals("unexpected state", e.getMessage());
        }
        finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }


    // -------------------------------------------------------------------------
    // The encoded getters reject non-SLH-DSA keys with JO_INCORRECT_KEY_TYPE
    // (Wave 4). Generate a non-SLH-DSA key (Ed25519) via the EDEC service and
    // pass its spec ref to each getter.
    // -------------------------------------------------------------------------

    @Test
    public void SLHDSAServiceJNI_getPublicKey_wrongKeyType() throws Exception
    {
        long keyRef = TestNISelector.getEdNi().generateKeyPair(
                OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);
        try
        {
            Assertions.assertTrue(keyRef > 0);
            long code = slhdsaServiceNI.ni_getPublicKey(keyRef, new byte[2048]);
            Assertions.assertEquals(ErrorCode.JO_INCORRECT_KEY_TYPE.getCode(), code);
        }
        finally
        {
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void SLHDSAServiceJNI_getPrivateKey_wrongKeyType() throws Exception
    {
        long keyRef = TestNISelector.getEdNi().generateKeyPair(
                OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);
        try
        {
            Assertions.assertTrue(keyRef > 0);
            long code = slhdsaServiceNI.ni_getPrivateKey(keyRef, new byte[4096]);
            Assertions.assertEquals(ErrorCode.JO_INCORRECT_KEY_TYPE.getCode(), code);
        }
        finally
        {
            specNI.dispose(keyRef);
        }
    }

    // -------------------------------------------------------------------------
    // Integer.MIN_VALUE probes for every int offset/length parameter — catches
    // a check written `len > 0` (which accepts MIN_VALUE) or any Math.abs/-len
    // that stays negative for MIN_VALUE, before the value reaches a size_t cast
    // on the native side. Runs on JNI and FFI via TestNISelector.
    // -------------------------------------------------------------------------

    @Test
    public void SLHDSAServiceNI_update_minValueOffsetAndLen_rejectedTyped() throws Exception
    {
        final long signer = slhdsaServiceNI.allocateSigner();
        final long keyRef = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), TestUtil.RNDSrc);
        try
        {
            slhdsaServiceNI.initSign(signer, keyRef, new byte[0], 0, 0, 0, TestUtil.RNDSrc);

            Assertions.assertEquals("input offset is negative", Assertions.assertThrows(
                    IllegalArgumentException.class,
                    () -> slhdsaServiceNI.update(signer, new byte[8], Integer.MIN_VALUE, 0)).getMessage());

            Assertions.assertEquals("input len is negative", Assertions.assertThrows(
                    IllegalArgumentException.class,
                    () -> slhdsaServiceNI.update(signer, new byte[8], 0, Integer.MIN_VALUE)).getMessage());
        }
        finally
        {
            slhdsaServiceNI.disposeSigner(signer);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void SLHDSAServiceNI_sign_minValueOffset_rejectedTyped() throws Exception
    {
        final long signer = slhdsaServiceNI.allocateSigner();
        final long keyRef = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), TestUtil.RNDSrc);
        try
        {
            slhdsaServiceNI.initSign(signer, keyRef, new byte[0], 0, 0, 0, TestUtil.RNDSrc);
            slhdsaServiceNI.update(signer, new byte[]{1, 2, 3}, 0, 3);

            Assertions.assertEquals("output offset is negative", Assertions.assertThrows(
                    IllegalArgumentException.class,
                    () -> slhdsaServiceNI.sign(signer, new byte[64], Integer.MIN_VALUE, TestUtil.RNDSrc)).getMessage());
        }
        finally
        {
            slhdsaServiceNI.disposeSigner(signer);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void SLHDSAServiceNI_verify_minValueSigLen_rejectedTyped() throws Exception
    {
        final long verifier = slhdsaServiceNI.allocateSigner();
        final long keyRef = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), TestUtil.RNDSrc);
        try
        {
            slhdsaServiceNI.initVerify(verifier, keyRef, new byte[0], 0, 0, 0);
            slhdsaServiceNI.update(verifier, new byte[]{1, 2, 3}, 0, 3);

            Assertions.assertEquals("sig length is negative", Assertions.assertThrows(
                    IllegalArgumentException.class,
                    () -> slhdsaServiceNI.verify(verifier, new byte[64], Integer.MIN_VALUE)).getMessage());
        }
        finally
        {
            slhdsaServiceNI.disposeSigner(verifier);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void SLHDSAServiceNI_decode_minValueOffsetAndLen_rejectedTyped() throws Exception
    {
        final long spec = TestNISelector.SpecNI.allocate();
        try
        {
            Assertions.assertEquals("input offset is negative", Assertions.assertThrows(
                    IllegalArgumentException.class,
                    () -> slhdsaServiceNI.decode_privateKey(spec, OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), new byte[8], Integer.MIN_VALUE, 0)).getMessage());

            Assertions.assertEquals("input len is negative", Assertions.assertThrows(
                    IllegalArgumentException.class,
                    () -> slhdsaServiceNI.decode_publicKey(spec, OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), new byte[8], 0, Integer.MIN_VALUE)).getMessage());
        }
        finally
        {
            specNI.dispose(spec);
        }
    }

    @Test
    public void SLHDSAServiceNI_sign_nullOutput_lengthQueryIgnoresOffset() throws Exception
    {
        // A length query (null output) must return the signature length on BOTH
        // JNI and FFI, ignoring the offset argument entirely — even a negative
        // one. Before the parity fix the FFI bridge validated the offset first
        // and diverged (JO_OUTPUT_OFFSET_IS_NEGATIVE / JO_OUTPUT_OUT_OF_RANGE)
        // while JNI returned the length. Runs on both bridges via TestNISelector.
        final long signer = slhdsaServiceNI.allocateSigner();
        final long keyRef = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType(), TestUtil.RNDSrc);
        try
        {
            slhdsaServiceNI.initSign(signer, keyRef, new byte[0], 0, 0, 0, TestUtil.RNDSrc);
            slhdsaServiceNI.update(signer, new byte[]{1, 2, 3}, 0, 3);

            long lenAtZero = slhdsaServiceNI.sign(signer, null, 0, TestUtil.RNDSrc);
            long lenAtPositive = slhdsaServiceNI.sign(signer, null, 5, TestUtil.RNDSrc);
            long lenAtNegative = slhdsaServiceNI.sign(signer, null, -1, TestUtil.RNDSrc);

            Assertions.assertTrue(lenAtZero > 0);
            Assertions.assertEquals(lenAtZero, lenAtPositive);
            Assertions.assertEquals(lenAtZero, lenAtNegative);
        }
        finally
        {
            slhdsaServiceNI.disposeSigner(signer);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void SLHDSAServiceNI_sign_aliasedUpdateInputAndOutputBuffer() throws Exception
    {
        // Aliasing case: the same array feeds update() as the message and then
        // receives the signature from sign(). update() copies the message into
        // the ctx's message BIO immediately (it does not retain the caller
        // pointer), so reusing that array as the sign output must produce a
        // valid signature and must not corrupt bytes outside the written
        // window. Runs on JNI and FFI via TestNISelector.
        java.security.SecureRandom rnd = new java.security.SecureRandom();
        final long keyRef = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType(), TestUtil.RNDSrc);
        final long signer = slhdsaServiceNI.allocateSigner();
        final long verifier = slhdsaServiceNI.allocateSigner();
        try
        {
            byte[] msg = new byte[64];
            rnd.nextBytes(msg);

            // Determine the signature length up front.
            slhdsaServiceNI.initSign(signer, keyRef, new byte[0], 0, 0, 0, TestUtil.RNDSrc);
            slhdsaServiceNI.update(signer, msg, 0, msg.length);
            int sigLen = (int) slhdsaServiceNI.sign(signer, null, 0, TestUtil.RNDSrc);
            Assertions.assertTrue(sigLen > 0);

            // Oversized buffer holding the message at offset 0; the signature is
            // written at offset 0 too, so the write overlaps the just-consumed
            // message region.
            int suffix = 7;
            byte[] big = new byte[sigLen + suffix];
            rnd.nextBytes(big);
            System.arraycopy(msg, 0, big, 0, msg.length);
            byte[] snapshot = big.clone();

            slhdsaServiceNI.initSign(signer, keyRef, new byte[0], 0, 0, 0, TestUtil.RNDSrc);
            slhdsaServiceNI.update(signer, big, 0, msg.length);
            int written = (int) slhdsaServiceNI.sign(signer, big, 0, TestUtil.RNDSrc);
            Assertions.assertEquals(sigLen, written);

            // Bytes after the signature window must be untouched.
            Assertions.assertArrayEquals(
                    java.util.Arrays.copyOfRange(snapshot, written, big.length),
                    java.util.Arrays.copyOfRange(big, written, big.length),
                    "bytes after the signature were clobbered");

            // The signature must verify against the original message.
            byte[] sig = java.util.Arrays.copyOfRange(big, 0, written);
            slhdsaServiceNI.initVerify(verifier, keyRef, new byte[0], 0, 0, 0);
            slhdsaServiceNI.update(verifier, msg, 0, msg.length);
            Assertions.assertEquals(ErrorCode.JO_SUCCESS.getCode(), slhdsaServiceNI.verify(verifier, sig, sig.length));
        }
        finally
        {
            slhdsaServiceNI.disposeSigner(signer);
            slhdsaServiceNI.disposeSigner(verifier);
            specNI.dispose(keyRef);
        }
    }

}
