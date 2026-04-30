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

package org.openssl.jostle.test.mlkem;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.mlkem.MLKEMServiceNI;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.test.crypto.TestNISelector;

import java.security.Security;

public class MLKEMLimitTest
{

    @BeforeAll
    public static void beforeAll()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    MLKEMServiceNI mlkemServiceNI = TestNISelector.getMLKEMNI();
    SpecNI specNI = TestNISelector.getSpecNI();

    @Test
    public void testMLKEMGenerateKeyPair_keyGenWrongType() throws Exception
    {

        for (int type : new int[]{-1, 0, 7})
        {

            try
            {
                mlkemServiceNI.generateKeyPair(type, TestUtil.RNDSrc);
                Assertions.fail();
            }
            catch (IllegalArgumentException e)
            {
                Assertions.assertEquals("invalid key type for ML-KEM", e.getMessage());
            }

        }
    }


    @Test
    public void testMLKEMGenerateKeyPair_noRand() throws Exception
    {


        try
        {
            mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), null);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("supplied random source was null", e.getMessage());
        }


    }

    @Test
    public void MLKEMServiceJNI_generateKeyPairSeed_noRand() throws Exception
    {
        byte[] seed = new byte[32];
        int seedLen = 32;

        try
        {

            mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), seed, seedLen, null);

            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("supplied random source was null", e.getMessage());
        }
    }


    @Test
    public void MLKEMServiceJNI_generateKeyPair_seedIsNull() throws Exception
    {
        byte[] seed = null;
        int seedLen = 0;

        try
        {
            mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), seed, seedLen, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("seed is null", e.getMessage());
        }
    }

    @Test
    public void MLKEMServiceJNI_generateKeyPair_seedLenNegative() throws Exception
    {
        byte[] seed = new byte[64];
        int seedLen = -1;

        try
        {
            mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_1024.getKsType(), seed, seedLen, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("seed len is negative", e.getMessage());
        }
    }

    @Test
    public void MLKEMServiceJNI_generateKeyPair_seedLenPastEndOfArray() throws Exception
    {
        byte[] seed = new byte[64];
        int seedLen = 65;

        try
        {
            mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), seed, seedLen, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("seed length is out of range", e.getMessage());
        }
    }


    @Test
    public void MLKEMServiceJNI_generateKeyPair_invalidSeedLength() throws Exception
    {
        byte[] seed = new byte[64];
        int seedLen = 63;

        try
        {
            mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), seed, seedLen, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("invalid seed length", e.getMessage());
        }
    }


    @Test
    public void MLKEMServiceJNI_generateKeyPair_noSeedButLength() throws Exception
    {
        byte[] seed = null;
        int seedLen = 64;

        try
        {
            mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), seed, seedLen, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("seed is null", e.getMessage());
        }
    }


    @Test
    public void MLKEMServiceJNI_generateKeyPair_seedWrongKeyType() throws Exception
    {
        byte[] seed = new byte[64];
        int seedLen = 64;

        try
        {
            mlkemServiceNI.generateKeyPair(Integer.MAX_VALUE, seed, seedLen, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("invalid key type for ML-KEM", e.getMessage());
        }
    }


    @Test
    public void MLKEMServiceJNI_getPublicKey_nullKeyRef() throws Exception
    {

        long ref = 0;
        try
        {
            mlkemServiceNI.getPublicKey(0, new byte[0]);
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
    public void MLKEMServiceJNI_getPublicKey_keyRefNullKey() throws Exception
    {
        long ref = TestNISelector.SpecNI.allocate();
        try
        {
            mlkemServiceNI.getPublicKey(ref, new byte[0]);
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
    public void MLKEMServiceJNI_getPublicKey_outLen() throws Exception
    {
        long ref = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
        try
        {
            mlkemServiceNI.getPublicKey(ref, new byte[10]);
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
    public void MLKEMServiceJNI_getPrivateKey_nullKeyRef() throws Exception
    {

        long ref = 0;
        try
        {
            mlkemServiceNI.getPrivateKey(0, new byte[0]);
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
    public void MLKEMServiceJNI_getPrivateKey_keyRefNullKey() throws Exception
    {
        long ref = TestNISelector.SpecNI.allocate();
        try
        {
            mlkemServiceNI.getPrivateKey(ref, new byte[0]);
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
    public void MLKEMServiceJNI_getPrivateKey_outLen() throws Exception
    {
        long ref = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
        try
        {
            mlkemServiceNI.getPrivateKey(ref, new byte[10]);
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
    public void MLKEMServiceJNI_getSeed_nullKeyRef() throws Exception
    {

        long ref = 0;
        try
        {
            mlkemServiceNI.getSeed(0, new byte[0]);
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
    public void MLKEMServiceJNI_getSeed_keyRefNullKey() throws Exception
    {
        long ref = TestNISelector.SpecNI.allocate();
        try
        {
            mlkemServiceNI.getSeed(ref, new byte[0]);
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
    public void MLKEMServiceJNI_getSeed_outLen() throws Exception
    {
        long ref = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
        try
        {
            mlkemServiceNI.getSeed(ref, new byte[10]);
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
    public void MLKEMServiceJNI_decode_1publicKey_nullKeySpec() throws Exception
    {

        long keyRef = 0;
        try
        {
            mlkemServiceNI.decode_publicKey(keyRef, OSSLKeyType.ML_KEM_512.getKsType(), new byte[1024], 0, 1024, TestUtil.RNDSrc);
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
    public void MLKEMServiceJNI_decode_1publicKey_inputNull() throws Exception
    {

        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);

           mlkemServiceNI.decode_publicKey(keyRef, OSSLKeyType.ML_KEM_768.getKsType(), null, 0, 0, TestUtil.RNDSrc);
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
    public void MLKEMServiceJNI_decode_1publicKey_inputOffsetNegative() throws Exception
    {

        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);

            mlkemServiceNI.decode_publicKey(keyRef, OSSLKeyType.ML_KEM_512.getKsType(), new byte[0], -1, 0, TestUtil.RNDSrc);
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
    public void MLKEMServiceJNI_decode_1publicKey_inputLenNegative() throws Exception
    {

        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);

           mlkemServiceNI.decode_publicKey(keyRef, OSSLKeyType.ML_KEM_512.getKsType(), new byte[0], 0, -1, TestUtil.RNDSrc);
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
    public void MLKEMServiceJNI_decode_1publicKey_inputOutOfRange_1() throws Exception
    {

        // offset + len > size
        // 1 + 10 > 10
        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);
            mlkemServiceNI.decode_publicKey(keyRef, OSSLKeyType.ML_KEM_512.getKsType(), new byte[10], 1, 10, TestUtil.RNDSrc);
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
    public void MLKEMServiceJNI_decode_1publicKey_inputOutOfRange_2() throws Exception
    {

        // offset + len > size
        // 0 + 11 > 10

        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);
            mlkemServiceNI.decode_publicKey(keyRef, OSSLKeyType.ML_KEM_512.getKsType(), new byte[10], 0, 11, TestUtil.RNDSrc);
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
    public void MLKEMServiceJNI_decode_1publicKey_keyType() throws Exception
    {
        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);
            mlkemServiceNI.decode_publicKey(keyRef, 99, new byte[10], 0, 10, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("invalid key type for ML-KEM", e.getMessage());
        }
        finally
        {
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void MLKEMServiceJNI_decode_1publicKey_inputWrongSize4KeyType() throws Exception
    {
        // public-key decode is strict-equality on min_len per variant
        final Object[][] tuples = new Object[][]{
                {OSSLKeyType.ML_KEM_512.getKsType(), 799},
                {OSSLKeyType.ML_KEM_512.getKsType(), 801},
                {OSSLKeyType.ML_KEM_768.getKsType(), 1183},
                {OSSLKeyType.ML_KEM_768.getKsType(), 1185},
                {OSSLKeyType.ML_KEM_1024.getKsType(), 1567},
                {OSSLKeyType.ML_KEM_1024.getKsType(), 1569},
        };

        for (Object[] tuple : tuples)
        {
            int keyType = (Integer) tuple[0];
            int len = (Integer) tuple[1];

            long keyRef = 0;
            try
            {
                keyRef = TestNISelector.getSpecNI().allocate();
                Assertions.assertTrue(keyRef > 0);
                mlkemServiceNI.decode_publicKey(keyRef, keyType, new byte[len], 0, len, TestUtil.RNDSrc);
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

    @Test()
    public void MLKEMServiceJNI_decode_1privateKey_nullKeySpec() throws Exception
    {

        long keyRef = 0;
        try
        {
            mlkemServiceNI.decode_privateKey(keyRef, OSSLKeyType.ML_KEM_512.getKsType(), new byte[1024], 0, 1024, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("key spec is null", e.getMessage());
        }
    }

    @Test()
    public void MLKEMServiceJNI_decode_1privateKey_inputNull() throws Exception
    {

        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);

            mlkemServiceNI.decode_privateKey(keyRef, OSSLKeyType.ML_KEM_768.getKsType(), null, 0, 0, TestUtil.RNDSrc);
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
    public void MLKEMServiceJNI_decode_1privateKey_inputOffsetNegative() throws Exception
    {

        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);

            mlkemServiceNI.decode_privateKey(keyRef, OSSLKeyType.ML_KEM_512.getKsType(), new byte[0], -1, 0, TestUtil.RNDSrc);
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
    public void MLKEMServiceJNI_decode_1privateKey_inputLenNegative() throws Exception
    {

        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);

            mlkemServiceNI.decode_privateKey(keyRef, OSSLKeyType.ML_KEM_512.getKsType(), new byte[0], 0, -1, TestUtil.RNDSrc);
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
    public void MLKEMServiceJNI_decode_1privateKey_inputOutOfRange_1() throws Exception
    {
        // offset + len > size: 1 + 10 > 10
        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);
            mlkemServiceNI.decode_privateKey(keyRef, OSSLKeyType.ML_KEM_512.getKsType(), new byte[10], 1, 10, TestUtil.RNDSrc);
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
    public void MLKEMServiceJNI_decode_1privateKey_inputOutOfRange_2() throws Exception
    {
        // offset + len > size: 0 + 11 > 10
        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);
            mlkemServiceNI.decode_privateKey(keyRef, OSSLKeyType.ML_KEM_512.getKsType(), new byte[10], 0, 11, TestUtil.RNDSrc);
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
    public void MLKEMServiceJNI_decode_1privateKey_keyType() throws Exception
    {
        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);
            mlkemServiceNI.decode_privateKey(keyRef, 99, new byte[10], 0, 10, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("invalid key type for ML-KEM", e.getMessage());
        }
        finally
        {
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void MLKEMServiceJNI_decode_1privateKey_inputWrongSize4KeyType() throws Exception
    {
        // private-key decode is < min_len per variant
        final Object[][] tuples = new Object[][]{
                {OSSLKeyType.ML_KEM_512.getKsType(), 1631},
                {OSSLKeyType.ML_KEM_768.getKsType(), 2399},
                {OSSLKeyType.ML_KEM_1024.getKsType(), 3167},
        };

        for (Object[] tuple : tuples)
        {
            int keyType = (Integer) tuple[0];
            int len = (Integer) tuple[1];

            long keyRef = 0;
            try
            {
                keyRef = TestNISelector.getSpecNI().allocate();
                Assertions.assertTrue(keyRef > 0);
                mlkemServiceNI.decode_privateKey(keyRef, keyType, new byte[len], 0, len, TestUtil.RNDSrc);
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

    @Test
    public void MLKEMServiceJNI_getPublicKey_wrongKeyType() throws Exception
    {
        long keyRef = TestNISelector.getEdNi().generateKeyPair(
                OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);
        try
        {
            Assertions.assertTrue(keyRef > 0);
            long code = mlkemServiceNI.ni_getPublicKey(keyRef, new byte[2048]);
            Assertions.assertEquals(ErrorCode.JO_INCORRECT_KEY_TYPE.getCode(), code);
        }
        finally
        {
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void MLKEMServiceJNI_getPrivateKey_wrongKeyType() throws Exception
    {
        long keyRef = TestNISelector.getEdNi().generateKeyPair(
                OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);
        try
        {
            Assertions.assertTrue(keyRef > 0);
            long code = mlkemServiceNI.ni_getPrivateKey(keyRef, new byte[4096]);
            Assertions.assertEquals(ErrorCode.JO_INCORRECT_KEY_TYPE.getCode(), code);
        }
        finally
        {
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void MLKEMServiceJNI_getSeed_wrongKeyType() throws Exception
    {
        long keyRef = TestNISelector.getEdNi().generateKeyPair(
                OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);
        try
        {
            Assertions.assertTrue(keyRef > 0);
            long code = mlkemServiceNI.ni_getSeed(keyRef, new byte[2048]);
            Assertions.assertEquals(ErrorCode.JO_INCORRECT_KEY_TYPE.getCode(), code);
        }
        finally
        {
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void MLKEMServiceJNI_decode_1publicKey_noRand() throws Exception
    {
        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);
            mlkemServiceNI.decode_publicKey(keyRef, OSSLKeyType.ML_KEM_512.getKsType(),
                    new byte[800], 0, 800, null);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("supplied random source was null", e.getMessage());
        }
        finally
        {
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void MLKEMServiceJNI_decode_1privateKey_noRand() throws Exception
    {
        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);
            mlkemServiceNI.decode_privateKey(keyRef, OSSLKeyType.ML_KEM_512.getKsType(),
                    new byte[1632], 0, 1632, null);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("supplied random source was null", e.getMessage());
        }
        finally
        {
            specNI.dispose(keyRef);
        }
    }

}

