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

import org.junit.jupiter.api.*;
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.AccessException;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.OpenSSL;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.ed.EDServiceNI;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.test.crypto.TestNISelector;
import org.openssl.jostle.util.ops.OperationsTestNI;

import java.security.Security;

public class EdDSAOpsTest
{
    EDServiceNI edDSAServiceNI = TestNISelector.getEdNi();
    SpecNI specNI = TestNISelector.getSpecNI();
    OperationsTestNI operationsTestNI = TestNISelector.getOperationsTestNI();

    @BeforeAll
    public static void beforeAll()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }


    @BeforeEach
    public void beforeEach()
    {
        if (operationsTestNI.opsTestAvailable())
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void testEDDSAGenerateKeyPair_openSSLError() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = 0;
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);

            edDSAServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);

            Assertions.fail();
        }
        catch (OpenSSLException e)
        {
            //
            // Asserting the code path would actually return if there was an error.
            // There isn't an error so the msg is null
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);

        }
    }

    @Test()
    public void EDDSAServiceJNI__initSign_accessContextArray() throws Exception
    {

        Assumptions.assumeFalse(Loader.isFFI());
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long eddsaRef = 0;
        long keyRef = 0;

        try
        {
            eddsaRef = edDSAServiceNI.allocateSigner();
            Assertions.assertTrue(eddsaRef > 0);
            keyRef = edDSAServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);

            edDSAServiceNI.initSign(eddsaRef, keyRef,"ED25519ctx" , new byte[1024], 0,  TestUtil.RNDSrc );
            Assertions.fail();
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access context array", e.getMessage());

        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
            edDSAServiceNI.disposeSigner(eddsaRef);

        }
    }

    @Test()
    public void EDDSAServiceJNI__initSign_createDigestCTX() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long eddsaRef = 0;
        long keyRef = 0;

        try
        {
            eddsaRef = edDSAServiceNI.allocateSigner();
            Assertions.assertTrue(eddsaRef > 0);
            keyRef = edDSAServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);


            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            long code = edDSAServiceNI.ni_initSign(eddsaRef, keyRef,"ED25519ctx" , new byte[1024], 0, TestUtil.RNDSrc);
            Assertions.assertEquals(-1002, code); // OpenSSL error with offset
        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
            edDSAServiceNI.disposeSigner(eddsaRef);

        }
    }

    @Test()
    public void EDDSAServiceJNI__initSign_EVP_PKEY_sign_message_init() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long eddsaRef = 0;
        long keyRef = 0;

        try
        {
            eddsaRef = edDSAServiceNI.allocateSigner();
            Assertions.assertTrue(eddsaRef > 0);
            keyRef = edDSAServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);


            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            long code = edDSAServiceNI.ni_initSign(eddsaRef, keyRef, "ED25519ctx", new byte[1024], 0, TestUtil.RNDSrc);
            Assertions.assertEquals(-1003, code); // OpenSSL error with offset
        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
            edDSAServiceNI.disposeSigner(eddsaRef);

        }
    }


    @Test()
    public void EDDSAServiceJNI__initVerify_accessContextArray() throws Exception
    {

        Assumptions.assumeFalse(Loader.isFFI());
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long eddsaRef = 0;
        long keyRef = 0;

        try
        {
            eddsaRef = edDSAServiceNI.allocateSigner();
            Assertions.assertTrue(eddsaRef > 0);
            keyRef = edDSAServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);

            edDSAServiceNI.initVerify(eddsaRef, keyRef,"ED25519ctx" , new byte[1024], 1024);
            Assertions.fail();
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access context array", e.getMessage());

        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
            edDSAServiceNI.disposeSigner(eddsaRef);

        }
    }

    @Test()
    public void EDDSAServiceJNI__initVerify_createDigestCTX() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long eddsaRef = 0;
        long keyRef = 0;

        try
        {
            eddsaRef = edDSAServiceNI.allocateSigner();
            Assertions.assertTrue(eddsaRef > 0);
            keyRef = edDSAServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);


            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            long code = edDSAServiceNI.ni_initVerify(eddsaRef, keyRef, "ED25519ctx", new byte[1024],  0);
            Assertions.assertEquals(-1005, code); // OpenSSL error with offset
        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
            edDSAServiceNI.disposeSigner(eddsaRef);

        }
    }

    @Test()
    public void EDDSAServiceJNI__initVerify_EVP_PKEY_message_init() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long eddsaRef = 0;
        long keyRef = 0;

        try
        {
            eddsaRef = edDSAServiceNI.allocateSigner();
            Assertions.assertTrue(eddsaRef > 0);
            keyRef = edDSAServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);


            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            long code = edDSAServiceNI.ni_initVerify(eddsaRef, keyRef, "ED25519ctx", new byte[1024],  0);
            Assertions.assertEquals(-1006, code); // OpenSSL error with offset
        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
            edDSAServiceNI.disposeSigner(eddsaRef);

        }
    }


    @Test()
    public void EDDSAServiceJNI_eddsa_sign_outputRange() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());

        long eddsaRef = 0;
        long keyRef = 0;

        try
        {
            eddsaRef = edDSAServiceNI.allocateSigner();
            Assertions.assertTrue(eddsaRef > 0);
            keyRef = edDSAServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            edDSAServiceNI.initSign(eddsaRef, keyRef,"ED25519ctx" , new byte[0], 0,  TestUtil.RNDSrc );

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            edDSAServiceNI.sign(eddsaRef, new byte[1], 0, TestUtil.RNDSrc);

            Assertions.fail();
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access output array", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
            edDSAServiceNI.disposeSigner(eddsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void EDDSAServiceJNI_eddsa_sign_osslErrorGettingLen() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long eddsaRef = 0;
        long keyRef = 0;

        try
        {
            eddsaRef = edDSAServiceNI.allocateSigner();
            Assertions.assertTrue(eddsaRef > 0);
            keyRef = edDSAServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            edDSAServiceNI.initSign(eddsaRef, keyRef,"ED25519ctx" , new byte[0], 0,  TestUtil.RNDSrc );

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            OpenSSL.getOpenSSLErrors(); // Purge any errors
            long len = edDSAServiceNI.sign(eddsaRef, null, 0, TestUtil.RNDSrc);

            Assertions.fail();
        }
        catch (OpenSSLException e)
        {
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        }
        finally
        {
            edDSAServiceNI.disposeSigner(eddsaRef);
            specNI.dispose(keyRef);

        }
    }

    @Test()
    public void EDDSAServiceJNI_eddsa_sign_osslErrorCalculatingSig() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long eddsaRef = 0;
        long keyRef = 0;

        try
        {
            eddsaRef = edDSAServiceNI.allocateSigner();
            Assertions.assertTrue(eddsaRef > 0);
            keyRef = edDSAServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            edDSAServiceNI.initSign(eddsaRef, keyRef,"ED25519ctx" , new byte[0], 0,  TestUtil.RNDSrc );


            long len = edDSAServiceNI.sign(eddsaRef, null, 0, TestUtil.RNDSrc);

            byte[] sig = new byte[(int) len];

            OpenSSL.getOpenSSLErrors(); // Purge any errors
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            edDSAServiceNI.sign(eddsaRef, sig, 0, TestUtil.RNDSrc);


            Assertions.fail();
        }
        catch (OpenSSLException e)
        {
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        }
        finally
        {
            edDSAServiceNI.disposeSigner(eddsaRef);
            specNI.dispose(keyRef);

        }
    }

    @Test()
    public void EDDSAServiceJNI_eddsa_sign_unexpectedSigLenChange() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long eddsaRef = 0;
        long keyRef = 0;

        try
        {
            eddsaRef = edDSAServiceNI.allocateSigner();
            Assertions.assertTrue(eddsaRef > 0);
            keyRef = edDSAServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            edDSAServiceNI.initSign(eddsaRef, keyRef,"ED25519ctx" , new byte[0], 0,  TestUtil.RNDSrc );

            long len = edDSAServiceNI.sign(eddsaRef, null, 0, TestUtil.RNDSrc);

            byte[] sig = new byte[(int) len];

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_LEN_CHANGE_1);
            edDSAServiceNI.sign(eddsaRef, sig, 0, TestUtil.RNDSrc);

            Assertions.fail();
        }
        catch (IllegalStateException e)
        {
            Assertions.assertEquals("unexpected sig length change", e.getMessage());
        }
        finally
        {
            edDSAServiceNI.disposeSigner(eddsaRef);
            specNI.dispose(keyRef);

        }
    }

    @Test()
    public void EDDSAServiceJNI_eddsa_verify_accessSigBytes() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());

        long eddsaRef = 0;
        long keyRef = 0;

        try
        {
            eddsaRef = edDSAServiceNI.allocateSigner();
            Assertions.assertTrue(eddsaRef > 0);
            keyRef = edDSAServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            edDSAServiceNI.initVerify(eddsaRef, keyRef,"ED25519ctx" , new byte[0], 0);

            OpenSSL.getOpenSSLErrors(); // Purge any errors
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            edDSAServiceNI.verify(eddsaRef, new byte[1], 1);

            Assertions.fail();
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access signature array", e.getMessage());
        }
        finally
        {
            edDSAServiceNI.disposeSigner(eddsaRef);
            specNI.dispose(keyRef);

        }
    }


    @Test()
    public void EDDSAServiceJNI_eddsa_verify_osslError() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long eddsaRef = 0;
        long keyRef = 0;

        try
        {
            eddsaRef = edDSAServiceNI.allocateSigner();
            Assertions.assertTrue(eddsaRef > 0);
            keyRef = edDSAServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            edDSAServiceNI.initVerify(eddsaRef, keyRef,"ED25519ctx" , new byte[0], 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            edDSAServiceNI.verify(eddsaRef, new byte[1], 1);

            Assertions.fail();
        }
        catch (OpenSSLException e)
        {
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        }
        finally
        {
            edDSAServiceNI.disposeSigner(eddsaRef);
            specNI.dispose(keyRef);

        }
    }
    
}
