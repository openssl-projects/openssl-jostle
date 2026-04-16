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

package org.openssl.jostle.test.eddsa;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.ed.EDServiceNI;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.test.crypto.TestNISelector;

import java.security.Security;

public class EdDSALimitTest
{
    EDServiceNI edServiceNI = TestNISelector.getEdNi();
    SpecNI specNI = TestNISelector.getSpecNI();

    @BeforeAll
    public static void beforeAll()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    @Test()
    public void EdDSAServiceJNI_decode_1publicKey_nullKeySpec() throws Exception
    {

        long keyRef = 0;
        try
        {
            edServiceNI.decode_publicKey(keyRef, OSSLKeyType.ED25519.getKsType(), new byte[1024], 0, 1024);
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
    public void EdDSAServiceJNI_decode_1publicKey_inputNull() throws Exception
    {

        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);

            edServiceNI.decode_publicKey(keyRef, OSSLKeyType.ED25519.getKsType(), null, 0, 0);
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
    public void EdDSAServiceJNI_decode_1publicKey_inputOffsetNegative() throws Exception
    {

        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);

            edServiceNI.decode_publicKey(keyRef, OSSLKeyType.ED25519.getKsType(), new byte[0], -1, 0);
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
    public void EdDSAServiceJNI_decode_1publicKey_inputLenNegative() throws Exception
    {

        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);

            edServiceNI.decode_publicKey(keyRef, OSSLKeyType.ED25519.getKsType(), new byte[0], 0, -1);
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
    public void EdDSAServiceJNI_decode_1publicKey_inputOutOfRange_1() throws Exception
    {

        // offset + len > size
        // 1 + 10 > 10
        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);
            edServiceNI.decode_publicKey(keyRef, OSSLKeyType.ED25519.getKsType(), new byte[10], 1, 10);
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
    public void EdDSAServiceJNI_decode_1publicKey_inputOutOfRange_2() throws Exception
    {

        // offset + len > size
        // 0 + 11 > 10

        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);
            edServiceNI.decode_publicKey(keyRef, OSSLKeyType.ED25519.getKsType(), new byte[10], 0, 11);
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
    public void EdDSAServiceJNI_decode_1publicKey_keyLength() throws Exception
    {
        // Either side of each valid key len
        for (int len : new int[]{1311, 1313, 1951, 1953, 2951, 2953})
        {
            long keyRef = 0;
            try
            {
                keyRef = TestNISelector.getSpecNI().allocate();
                Assertions.assertTrue(keyRef > 0);
                edServiceNI.decode_publicKey(keyRef, OSSLKeyType.NONE.getKsType(), new byte[len], 0, len);
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
    public void EdDSAServiceJNI_decode_1publicKey_keyType() throws Exception
    {
        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);
            edServiceNI.decode_publicKey(keyRef, 99, new byte[10], 0, 10);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("invalid key type for EDDSA", e.getMessage());
        }
        finally
        {
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void EdDSAServiceJNI_decode_1publicKey_inputWrongSize4KeyType() throws Exception
    {
        long keyRef = 0;

        final Object[][] tuples = new Object[][]{
                {
                        OSSLKeyType.ED25519.getKsType(),
                        new byte[1311]
                },
                {
                        OSSLKeyType.ED25519.getKsType(),
                        new byte[1313]
                },


        };

        for (Object[] tuple : tuples)
        {

            int keyType = (Integer) tuple[0];
            byte[] key = (byte[]) tuple[1];

            try
            {
                keyRef = TestNISelector.getSpecNI().allocate();
                Assertions.assertTrue(keyRef > 0);
                edServiceNI.decode_publicKey(keyRef, keyType, key, 0, key.length);
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

    // Boken input for public key is an OpsTest see EdDSAOpsTest class


    @Test()
    public void EdDSAServiceJNI_decode_1privateKey_inputNull() throws Exception
    {

        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);

            edServiceNI.decode_privateKey(keyRef, OSSLKeyType.ED25519.getKsType(), null, 0, 0);
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
    public void EdDSAServiceJNI_decode_1privateKey_inputOffsetNegative() throws Exception
    {

        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);

            edServiceNI.decode_privateKey(keyRef, OSSLKeyType.ED25519.getKsType(), new byte[0], -1, 0);
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
    public void EdDSAServiceJNI_decode_1privateKey_inputLenNegative() throws Exception
    {

        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);

            edServiceNI.decode_privateKey(keyRef, OSSLKeyType.ED25519.getKsType(), new byte[0], 0, -1);
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
    public void EdDSAServiceJNI_decode_1privateKey_inputOutOfRange_1() throws Exception
    {

        // offset + len > size
        // 1 + 10 > 10
        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);
            edServiceNI.decode_privateKey(keyRef, OSSLKeyType.ED25519.getKsType(), new byte[10], 1, 10);
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
    public void EdDSAServiceJNI_decode_1privateKey_inputOutOfRange_2() throws Exception
    {

        // offset + len > size
        // 0 + 11 > 10

        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);
            edServiceNI.decode_privateKey(keyRef, OSSLKeyType.ED25519.getKsType(), new byte[10], 0, 11);
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
    public void EdDSAServiceJNI_decode_1privateKey_keyLength() throws Exception
    {
        // Either side of each valid key len
        for (int len : new int[]{2559, 2561, 4031, 4033, 4895, 4897})
        {
            long keyRef = 0;
            try
            {
                keyRef = TestNISelector.getSpecNI().allocate();
                Assertions.assertTrue(keyRef > 0);
                edServiceNI.decode_privateKey(keyRef, OSSLKeyType.NONE.getKsType(), new byte[len], 0, len);
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
    public void EdDSAServiceJNI_decode_1privateKey_keyType() throws Exception
    {
        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);
            edServiceNI.decode_privateKey(keyRef, 99, new byte[10], 0, 10);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("invalid key type for EDDSA", e.getMessage());
        }
        finally
        {
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void EdDSAServiceJNI_decode_1privateKey_inputWrongSize4KeyType() throws Exception
    {
        long keyRef = 0;

        final Object[][] tuples = new Object[][]{
                {
                        OSSLKeyType.ED25519.getKsType(),
                        new byte[31]
                },
                {
                        OSSLKeyType.ED25519.getKsType(),
                        new byte[33]
                },
                {
                        OSSLKeyType.ED448.getKsType(),
                        new byte[56]
                },
                {
                        OSSLKeyType.ED448.getKsType(),
                        new byte[58]
                },
        };

        for (Object[] tuple : tuples)
        {

            int keyType = (Integer) tuple[0];
            byte[] key = (byte[]) tuple[1];

            try
            {
                keyRef = TestNISelector.getSpecNI().allocate();
                Assertions.assertTrue(keyRef > 0);
                edServiceNI.decode_privateKey(keyRef, keyType, key, 0, key.length);
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
    public void testEDDSAGenerateKeyPair_keyGenWrongType() throws Exception
    {

        for (int type : new int[]{19, 0, 22})
        {

            try
            {
                edServiceNI.generateKeyPair(type, TestUtil.RNDSrc);
                Assertions.fail();
            }
            catch (IllegalArgumentException e)
            {
                Assertions.assertEquals("invalid key type for EDDSA", e.getMessage());
            }

        }

    }





    @Test()
    public void EDDSAServiceJNI_initVerify_ctxLenPastEndOfContext_1() throws Exception
    {

        // Zero length array but declared len of 1

        long ref = 0;
        long keyRef = 0;

        try
        {
            ref = edServiceNI.allocateSigner();
            Assertions.assertTrue(ref > 0);
            keyRef = edServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            edServiceNI.initVerify(ref, keyRef, "ED25519ctx", new byte[0], 1);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("context length is past end of context", e.getMessage());
        }
        finally
        {
            edServiceNI.disposeSigner(ref);
            specNI.dispose(keyRef);

        }
    }

    @Test()
    public void edServiceJNI_initVerify_ctxLenPastEndOfContext_2() throws Exception
    {

        // array length of 1  but declared len of 2

        long EDDSARef = 0;
        long keyRef = 0;

        try
        {
            EDDSARef = edServiceNI.allocateSigner();
            Assertions.assertTrue(EDDSARef > 0);
            keyRef = edServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            edServiceNI.initVerify(EDDSARef, keyRef, "ED25519ctx", new byte[1], 2);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("context length is past end of context", e.getMessage());
        }
        finally
        {
            edServiceNI.disposeSigner(EDDSARef);
            specNI.dispose(keyRef);

        }
    }

    @Test()
    public void EDDSAServiceJNI_initVerify_ctxTooLong() throws Exception
    {

        // array length of 1  but declared len of 2

        long EDDSARef = 0;
        long keyRef = 0;

        try
        {
            EDDSARef = edServiceNI.allocateSigner();
            Assertions.assertTrue(EDDSARef > 0);
            keyRef = edServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            edServiceNI.initVerify(EDDSARef, keyRef, "ED25519ctx", new byte[64], 65);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("context length is past end of context", e.getMessage());
        }
        finally
        {
            edServiceNI.disposeSigner(EDDSARef);
            specNI.dispose(keyRef);

        }
    }

    @Test()
    public void EDDSAServiceJNI_initVerify_nullKey() throws Exception
    {

        long eddsaRef = 0;
        long keyRef = 0;
        try
        {
            eddsaRef = edServiceNI.allocateSigner();
            Assertions.assertTrue(eddsaRef > 0);
            edServiceNI.initVerify(eddsaRef, keyRef, "ED25519ctx", new byte[64], 64);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("key spec is null", e.getMessage());
        }
        finally
        {
            edServiceNI.disposeSigner(eddsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void EDDSAServiceJNI_initVerify_keySpecNullKey() throws Exception
    {

        long eddsaRef = 0;
        long keyRef = 0;
        try
        {
            eddsaRef = edServiceNI.allocateSigner();
            Assertions.assertTrue(eddsaRef > 0);
            keyRef = specNI.allocate();

            Assertions.assertTrue(keyRef > 0);
            edServiceNI.initVerify(eddsaRef, keyRef, "ED25519ctx", new byte[1], 1);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("key spec has null key", e.getMessage());
        }
        finally
        {
            edServiceNI.disposeSigner(eddsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void EDDSAServiceJNI_eddsa_update_notInitialised() throws Exception
    {
        long eddsaRef = 0;
        long keyRef = 0;

        try
        {
            eddsaRef = edServiceNI.allocateSigner();
            Assertions.assertTrue(eddsaRef > 0);
            keyRef = edServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            // (eddsaServiceNI.initSign(eddsaRef, keyRef, new byte[1], 1, 3));

            edServiceNI.update(eddsaRef, new byte[0], 0, 0);

            Assertions.fail();
        }
        catch (IllegalStateException e)
        {
            Assertions.assertEquals("not initialized", e.getMessage());
        }
        finally
        {
            edServiceNI.disposeSigner(eddsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void EDDSAServiceJNI_eddsa_update_nullInput() throws Exception
    {
        long eddsaRef = 0;
        long keyRef = 0;

        try
        {
            eddsaRef = edServiceNI.allocateSigner();
            Assertions.assertTrue(eddsaRef > 0);
            keyRef = edServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            edServiceNI.initSign(eddsaRef, keyRef, "ED25519ctx", new byte[0], 0, TestUtil.RNDSrc);

            edServiceNI.update(eddsaRef, null, 0, 0);

            Assertions.fail();
        }
        catch (NullPointerException e)
        {
            Assertions.assertEquals("input is null", e.getMessage());
        }
        finally
        {
            edServiceNI.disposeSigner(eddsaRef);
            specNI.dispose(keyRef);

        }
    }

    @Test()
    public void EDDSAServiceJNI_eddsa_update_inputOffsetNegative() throws Exception
    {
        long eddsaRef = 0;
        long keyRef = 0;

        try
        {
            eddsaRef = edServiceNI.allocateSigner();
            Assertions.assertTrue(eddsaRef > 0);
            keyRef = edServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            edServiceNI.initSign(eddsaRef, keyRef, "ED25519ctx", new byte[0], 0, TestUtil.RNDSrc);

            edServiceNI.update(eddsaRef, new byte[0], -1, 0);

            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset is negative", e.getMessage());
        }
        finally
        {
            edServiceNI.disposeSigner(eddsaRef);
            specNI.dispose(keyRef);

        }
    }

    @Test()
    public void EDDSAServiceJNI_eddsa_update_inputLenNegative() throws Exception
    {
        long eddsaRef = 0;
        long keyRef = 0;

        try
        {
            eddsaRef = edServiceNI.allocateSigner();
            Assertions.assertTrue(eddsaRef > 0);
            keyRef = edServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            edServiceNI.initSign(eddsaRef, keyRef, "ED25519ctx", new byte[0], 0, TestUtil.RNDSrc);

            edServiceNI.update(eddsaRef, new byte[0], 0, -1);

            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input len is negative", e.getMessage());
        }
        finally
        {
            edServiceNI.disposeSigner(eddsaRef);
            specNI.dispose(keyRef);

        }
    }


    @Test()
    public void EDDSAServiceJNI_eddsa_update_inputOutOfRange_1() throws Exception
    {

        // 10 byte input
        // 0 offset
        // 11 byte len

        long eddsaRef = 0;
        long keyRef = 0;

        try
        {
            eddsaRef = edServiceNI.allocateSigner();
            Assertions.assertTrue(eddsaRef > 0);
            keyRef = edServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            edServiceNI.initSign(eddsaRef, keyRef, "ED25519ctx", new byte[0], 0, TestUtil.RNDSrc);

            edServiceNI.update(eddsaRef, new byte[10], 0, 11);

            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset + length is out of range", e.getMessage());
        }
        finally
        {
            edServiceNI.disposeSigner(eddsaRef);
            specNI.dispose(keyRef);

        }
    }


    @Test()
    public void EDDSAServiceJNI_eddsa_update_inputOutOfRange_2() throws Exception
    {

        // 10 byte input
        // 1 offset
        // 10 byte len

        long eddsaRef = 0;
        long keyRef = 0;

        try
        {
            eddsaRef = edServiceNI.allocateSigner();
            Assertions.assertTrue(eddsaRef > 0);
            keyRef = edServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            edServiceNI.initSign(eddsaRef, keyRef, "ED25519ctx", new byte[0], 0, TestUtil.RNDSrc);

            edServiceNI.update(eddsaRef, new byte[10], 1, 10);

            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset + length is out of range", e.getMessage());
        }
        finally
        {
            edServiceNI.disposeSigner(eddsaRef);
            specNI.dispose(keyRef);

        }
    }


    @Test()
    public void EDDSAServiceJNI_mldsa_sign_outOffsetNegative() throws Exception
    {

        long mldsaRef = 0;
        long keyRef = 0;

        try
        {
            mldsaRef = edServiceNI.allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = edServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            edServiceNI.initSign(mldsaRef, keyRef, "ED25519ctx", new byte[0], 0, TestUtil.RNDSrc);

            edServiceNI.sign(mldsaRef, new byte[0], -1, TestUtil.RNDSrc);

            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output offset is negative", e.getMessage());
        }
        finally
        {
            edServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);

        }
    }

    @Test()
    public void EDDSAServiceJNI_mldsa_sign_outputRange() throws Exception
    {

        long mldsaRef = 0;
        long keyRef = 0;

        try
        {
            mldsaRef = edServiceNI.allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = edServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            edServiceNI.initSign(mldsaRef, keyRef, "ED25519ctx", new byte[0], 0, TestUtil.RNDSrc);

            edServiceNI.sign(mldsaRef, new byte[0], 1, TestUtil.RNDSrc);

            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output offset + length is out of range", e.getMessage());
        }
        finally
        {
            edServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);

        }
    }

    @Test()
    public void EDDSAServiceJNI_mldsa_sign_notInitialized() throws Exception
    {

        long mldsaRef = 0;
        long keyRef = 0;

        try
        {
            mldsaRef = edServiceNI.allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = edServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            //(edServiceNI.initSign(mldsaRef, keyRef, new byte[0], 0, 0));

            edServiceNI.sign(mldsaRef, new byte[0], 0, TestUtil.RNDSrc);

            Assertions.fail();
        }
        catch (IllegalStateException e)
        {
            Assertions.assertEquals("not initialized", e.getMessage());
        }
        finally
        {
            edServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);

        }
    }


    @Test()
    public void EDDSAServiceJNI_mldsa_sign_initVerify() throws Exception
    {

        long mldsaRef = 0;
        long keyRef = 0;

        try
        {
            mldsaRef = edServiceNI.allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = edServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            edServiceNI.initVerify(mldsaRef, keyRef, "ED25519ctx", new byte[0], 0);

            edServiceNI.sign(mldsaRef, new byte[0], 0, TestUtil.RNDSrc);

            Assertions.fail();
        }
        catch (IllegalStateException e)
        {
            Assertions.assertEquals("unexpected state", e.getMessage());
        }
        finally
        {
            edServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);

        }
    }


    @Test()
    public void EDDSAServiceJNI_mldsa_sign_nullRand_1() throws Exception
    {

        //
        // offset is zero
        //

        long mldsaRef = 0;
        long keyRef = 0;

        try
        {
            mldsaRef = edServiceNI.allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = edServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            edServiceNI.initSign(mldsaRef, keyRef, "ED25519ctx", new byte[0], 0, null);
            Assertions.fail();

        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("supplied random source was null", e.getMessage());
        }
        finally
        {
            edServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);

        }
    }


    @Test()
    public void EDDSAServiceJNI_mldsa_sign_nullRand_2() throws Exception
    {

        //
        // offset is zero
        //

        long mldsaRef = 0;
        long keyRef = 0;

        try
        {
            mldsaRef = edServiceNI.allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = edServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            edServiceNI.initSign(mldsaRef, keyRef, "ED25519ctx", new byte[0], 0, TestUtil.RNDSrc);

            edServiceNI.sign(mldsaRef, new byte[1024], 0, null);
            Assertions.fail();

        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("supplied random source was null", e.getMessage());
        }
        finally
        {
            edServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);

        }
    }

    @Test()
    public void EDDSAServiceJNI_mldsa_sign_outputTooSmall_1() throws Exception
    {

        //
        // offset is zero
        //

        long mldsaRef = 0;
        long keyRef = 0;

        try
        {
            mldsaRef = edServiceNI.allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = edServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            edServiceNI.initSign(mldsaRef, keyRef, "ED25519ctx", new byte[0], 0, TestUtil.RNDSrc);

            long len = (edServiceNI.sign(mldsaRef, null, 0, TestUtil.RNDSrc));

            byte[] sig = new byte[(int) len - 1];

            edServiceNI.sign(mldsaRef, sig, 0, TestUtil.RNDSrc);

            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output too small", e.getMessage());
        }
        finally
        {
            edServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);

        }
    }


    @Test()
    public void EDDSAServiceJNI_mldsa_sign_outputTooSmall_2() throws Exception
    {

        //
        // offset is 1
        //

        long mldsaRef = 0;
        long keyRef = 0;

        try
        {
            mldsaRef = edServiceNI.allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = edServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            edServiceNI.initSign(mldsaRef, keyRef, "ED25519ctx", new byte[0], 0, TestUtil.RNDSrc);

            long len = (edServiceNI.sign(mldsaRef, null, 0, TestUtil.RNDSrc));

            byte[] sig = new byte[(int) len];

            edServiceNI.sign(mldsaRef, sig, 1, TestUtil.RNDSrc);

            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output too small", e.getMessage());
        }
        finally
        {
            edServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);

        }
    }

    @Test()
    public void EDDSAServiceJNI_mldsa_verify_nullSig() throws Exception
    {


        long mldsaRef = 0;
        long keyRef = 0;

        try
        {
            mldsaRef = edServiceNI.allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = edServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            edServiceNI.initVerify(mldsaRef, keyRef, "ED25519ctx", new byte[0], 0);

            edServiceNI.verify(mldsaRef, null, 0);

            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("sig is null", e.getMessage());
        }
        finally
        {
            edServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);

        }
    }


    @Test()
    public void EDDSAServiceJNI_mldsa_verify_sigLenZero() throws Exception
    {
        long mldsaRef = 0;
        long keyRef = 0;

        try
        {
            mldsaRef = edServiceNI.allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = edServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            edServiceNI.initVerify(mldsaRef, keyRef, "ED25519ctx", new byte[0], 0);

            long code = (edServiceNI.verify(mldsaRef, new byte[1], 0));
            Assertions.assertEquals(ErrorCode.JO_FAIL.getCode(), code);

        }
        finally
        {
            edServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);

        }
    }

    @Test()
    public void EDDSAServiceJNI_mldsa_verify_sigLenNegative() throws Exception
    {
        long mldsaRef = 0;
        long keyRef = 0;

        try
        {
            mldsaRef = edServiceNI.allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = edServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            edServiceNI.initVerify(mldsaRef, keyRef, "ED25519ctx", new byte[0], 0);

            edServiceNI.verify(mldsaRef, new byte[1], -1);

            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("sig length is negative", e.getMessage());
        }
        finally
        {
            edServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);

        }
    }


    @Test()
    public void EDDSAServiceJNI_mldsa_verify_sigLenOutOfRange_1() throws Exception
    {
        long mldsaRef = 0;
        long keyRef = 0;

        try
        {
            mldsaRef = edServiceNI.allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = edServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            edServiceNI.initVerify(mldsaRef, keyRef, "ED25519ctx", new byte[0], 0);

            edServiceNI.verify(mldsaRef, new byte[10], 11);

            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("sig out of range", e.getMessage());
        }
        finally
        {
            edServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);

        }
    }

    @Test()
    public void EDDSAServiceJNI_mldsa_verify_sigLenOutOfRange_2() throws Exception
    {
        long mldsaRef = 0;
        long keyRef = 0;

        try
        {
            mldsaRef = edServiceNI.allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = edServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            edServiceNI.initVerify(mldsaRef, keyRef, "ED25519ctx", new byte[0], 0);

            edServiceNI.verify(mldsaRef, new byte[0], 1);

            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("sig out of range", e.getMessage());
        }
        finally
        {
            edServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);

        }
    }


    @Test()
    public void EDDSAServiceJNI_mldsa_verify_initForSigning() throws Exception
    {
        long mldsaRef = 0;
        long keyRef = 0;

        try
        {
            mldsaRef = edServiceNI.allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = edServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            edServiceNI.initSign(mldsaRef, keyRef, "ED25519ctx", new byte[0], 0, TestUtil.RNDSrc);

            edServiceNI.verify(mldsaRef, new byte[1], 1);

            Assertions.fail();
        }
        catch (IllegalStateException e)
        {
            Assertions.assertEquals("unexpected state", e.getMessage());
        }
        finally
        {
            edServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);

        }
    }


}
