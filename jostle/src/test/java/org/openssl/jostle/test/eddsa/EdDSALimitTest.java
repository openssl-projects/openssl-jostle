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
    public void EDDSAServiceJNI_initVerify_nullContextArray() throws Exception
    {

        long ref = 0;
        long keyRef = 0;

        try
        {
            ref = TestNISelector.getEdNi().allocateSigner();
            Assertions.assertTrue(ref > 0);
            keyRef = TestNISelector.getEdNi().generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            edServiceNI.initVerify(ref, keyRef,"ED25519ctx" , null, 0);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("context array is null", e.getMessage());
        }
        finally
        {
            edServiceNI.disposeSigner(ref);
            specNI.dispose(keyRef);
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
            edServiceNI.initVerify(EDDSARef, keyRef,"ED25519ctx" , new byte[1], 2);
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
            edServiceNI.initVerify(eddsaRef, keyRef,"ED25519ctx" , new byte[64], 64);
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
            edServiceNI.initVerify(eddsaRef, keyRef,"ED25519ctx" , new byte[1], 1);
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
            edServiceNI.initSign(eddsaRef, keyRef,"ED25519ctx" , new byte[0], 0,  TestUtil.RNDSrc );

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
            edServiceNI.initSign(eddsaRef, keyRef,"ED25519ctx" , new byte[0], 0,  TestUtil.RNDSrc );

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
            edServiceNI.initSign(eddsaRef, keyRef, "ED25519ctx", new byte[0], 0,  TestUtil.RNDSrc );

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
            edServiceNI.initSign(eddsaRef, keyRef,"ED25519ctx" , new byte[0], 0,  TestUtil.RNDSrc );

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
            edServiceNI.initSign(eddsaRef, keyRef,"ED25519ctx" , new byte[0], 0, TestUtil.RNDSrc );

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
            edServiceNI.initSign(mldsaRef, keyRef,"ED25519ctx" , new byte[0], 0,  TestUtil.RNDSrc );

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
            edServiceNI.initSign(mldsaRef, keyRef,"ED25519ctx" , new byte[0], 0,  TestUtil.RNDSrc );

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
            edServiceNI.initVerify(mldsaRef, keyRef,"ED25519ctx" , new byte[0], 0);

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
            edServiceNI.initSign(mldsaRef, keyRef,"ED25519ctx" , new byte[0], 0,  null );
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
            edServiceNI.initSign(mldsaRef, keyRef,"ED25519ctx" , new byte[0], 0,  TestUtil.RNDSrc );

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
            edServiceNI.initSign(mldsaRef, keyRef,"ED25519ctx" , new byte[0], 0,  TestUtil.RNDSrc );

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
            edServiceNI.initSign(mldsaRef, keyRef,"ED25519ctx" , new byte[0], 0,  TestUtil.RNDSrc );

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
            edServiceNI.initVerify(mldsaRef, keyRef,"ED25519ctx" , new byte[0], 0);

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
            edServiceNI.initVerify(mldsaRef, keyRef,"ED25519ctx" , new byte[0], 0);

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
            edServiceNI.initVerify(mldsaRef, keyRef,"ED25519ctx" , new byte[0], 0);

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
            edServiceNI.initVerify(mldsaRef, keyRef,"ED25519ctx" , new byte[0], 0);

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
            edServiceNI.initSign(mldsaRef, keyRef,"ED25519ctx" , new byte[0], 0, TestUtil.RNDSrc );

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
