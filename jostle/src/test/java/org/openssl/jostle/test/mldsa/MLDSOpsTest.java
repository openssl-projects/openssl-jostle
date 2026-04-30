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

package org.openssl.jostle.test.mldsa;

import org.junit.jupiter.api.*;
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.*;
import org.openssl.jostle.jcajce.provider.mldsa.MLDSAServiceNI;
import org.openssl.jostle.jcajce.provider.mldsa.MLDSASignatureSpi;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.test.crypto.TestNISelector;
import org.openssl.jostle.util.ops.OperationsTestNI;

import java.security.Security;

public class MLDSOpsTest
{


    MLDSAServiceNI mldsaServiceNI = TestNISelector.getMLDSANI();
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
    public void testMLDSAGenerateKeyPair_openSSLError() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = 0;
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);

            mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType(), TestUtil.RNDSrc);

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

    @Test
    public void MLDSAServiceJNI_generateKeyPair_seedLenNegative() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());

        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);

            mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.ordinal(), new byte[32], 32, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access seed array", e.getMessage());
        }
    }


    @Test()
    public void MLDSAServiceJNI_getPublicKey_accessByteArray() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());

        long keyRef = 0;

        try
        {
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType(), TestUtil.RNDSrc);
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);

            mldsaServiceNI.getPublicKey(keyRef, new byte[2048]);
            Assertions.fail();
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access output array", e.getMessage());

        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);

        }
    }


    @Test()
    public void MLDSAServiceJNI_getPrivateKey_accessByteArray() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());

        long keyRef = 0;
        try
        {
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType(), TestUtil.RNDSrc);
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);

            mldsaServiceNI.getPrivateKey(keyRef, new byte[4096]);
            Assertions.fail();
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access output array", e.getMessage());

        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);

        }
    }


    @Test()
    public void MLDSAService_getPrivateKey_OpenSSLError_1() throws Exception
    {
        //
        // Where min_len is determined
        //

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = 0;
        try
        {
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType(), TestUtil.RNDSrc);
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);

            mldsaServiceNI.getPrivateKey(keyRef, new byte[4096]);
            Assertions.fail();
        }
        catch (OpenSSLException e)
        {
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);

        }
    }

    @Test()
    public void MLDSAService_getPrivateKey_OpenSSLError_2() throws Exception
    {
        //
        // Where encoding operation occurs, uses offset to the error code during ops testing.
        //

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = 0;
        try
        {
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType(), TestUtil.RNDSrc);
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);

            long code = mldsaServiceNI.ni_getPrivateKey(keyRef, new byte[4096]);
            Assertions.assertEquals(-1002, code);

        }
        catch (OpenSSLException e)
        {
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);

        }
    }

    @Test()
    public void MLDSAService_getPrivateKey_OutputInt32Overflow() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = 0;
        try
        {
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType(), TestUtil.RNDSrc);
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);

            mldsaServiceNI.getPrivateKey(keyRef, new byte[4096]);
            Assertions.fail();
        }
        catch (OverflowException e)
        {
            Assertions.assertEquals("output too long int32", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);

        }
    }


    @Test()
    public void MLDSAService_getPublicKey_OpenSSLError_1() throws Exception
    {
        //
        // Where min_len is determined
        //

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = 0;
        try
        {
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType(), TestUtil.RNDSrc);
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);

            mldsaServiceNI.getPublicKey(keyRef, new byte[2048]);
            Assertions.fail();
        }
        catch (OpenSSLException e)
        {
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);

        }
    }


    @Test()
    public void MLDSAService_getPublicKey_OpenSSLError_2() throws Exception
    {
        //
        // Where encoding operation occurs, uses offset to the error code during ops testing.
        //

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = 0;
        try
        {
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType(), TestUtil.RNDSrc);
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);

            long code = mldsaServiceNI.ni_getPublicKey(keyRef, new byte[2048]);
            Assertions.assertEquals(-1002, code);

        }
        catch (OpenSSLException e)
        {
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);

        }
    }

    @Test()
    public void MLDSAService_getPublicKey_OutputInt32Overflow() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = 0;
        try
        {
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType(), TestUtil.RNDSrc);
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);

            mldsaServiceNI.getPublicKey(keyRef, new byte[2048]);
            Assertions.fail();
        }
        catch (OverflowException e)
        {
            Assertions.assertEquals("output too long int32", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);

        }
    }


    @Test()
    public void MLDSAServiceJNI_getSeed_accessByteArray() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());
        long keyRef = 0;

        try
        {
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType(), TestUtil.RNDSrc);
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);

            mldsaServiceNI.getSeed(keyRef, new byte[2048]);
            Assertions.fail();
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access output array", e.getMessage());

        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);

        }
    }


    @Test()
    public void MLDSAServiceJNI_getSeed_OpenSSLError() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = 0;

        try
        {
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType(), TestUtil.RNDSrc);
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);

            mldsaServiceNI.getSeed(keyRef, new byte[2048]);
            Assertions.fail();
        }
        catch (OpenSSLException e)
        {
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);

        }
    }

    @Test()
    public void MLDSAServiceJNI_getSeed_OutputInt32Overflow() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = 0;

        try
        {
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType(), TestUtil.RNDSrc);
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);

            mldsaServiceNI.getSeed(keyRef, new byte[2048]);
            Assertions.fail();
        }
        catch (OverflowException e)
        {
            Assertions.assertEquals("output too long int32", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);

        }
    }


    @Test()
    public void MLDSAServiceJNI_decode_1publicKey_accessByteArray() throws Exception
    {
        Assumptions.assumeFalse(Loader.isFFI());
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());


        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);

            mldsaServiceNI.decode_publicKey(keyRef, OSSLKeyType.ML_DSA_44.getKsType(), new byte[1024], 0, 1024);
            Assertions.fail();
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access input array", e.getMessage());

        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);

        }
    }


    @Test()
    public void MLDSAServiceJNI_decode_1publicKey_openSSLErrorDecoding() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long keyRef = 0;

        final Object[][] tuples = new Object[][]{
                {
                        OSSLKeyType.ML_DSA_44.getKsType(),
                        new byte[1312]
                },
                {
                        OSSLKeyType.ML_DSA_65.getKsType(),
                        new byte[1952]
                },
                {
                        OSSLKeyType.ML_DSA_87.getKsType(),
                        new byte[2592]
                }
        };

        for (Object[] tuple : tuples)
        {

            int keyType = (Integer) tuple[0];
            byte[] key = (byte[]) tuple[1];

            try
            {
                keyRef = TestNISelector.getSpecNI().allocate();
                Assertions.assertTrue(keyRef > 0);
                operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
                mldsaServiceNI.decode_publicKey(keyRef, keyType, key, 0, key.length);
                Assertions.fail();
            }
            catch (OpenSSLException e)
            {
                Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
            }
            finally
            {
                operationsTestNI.resetFlags();
                specNI.dispose(keyRef);
            }
        }
    }


    @Test()
    public void MLDSAServiceJNI_decode_1privateKey_accessByteArray() throws Exception
    {

        Assumptions.assumeFalse(Loader.isFFI());
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);

            mldsaServiceNI.decode_privateKey(keyRef, OSSLKeyType.ML_DSA_44.getKsType(), new byte[1024], 0, 1024);
            Assertions.fail();
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access input array", e.getMessage());

        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void MLDSAServiceJNI_decode_1privateKey_openSSLErrorDecoding() throws Exception
    {
        // Use a freshly-generated, validly-encoded private key so the
        // EVP_PKEY_new_raw_private_key_ex call would succeed on its own.
        // This isolates JO_OPENSSL_ERROR to the OPS cookie that forces the
        // resulting EVP_PKEY back to NULL.

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        final OSSLKeyType[] keyTypes = new OSSLKeyType[]{
                OSSLKeyType.ML_DSA_44,
                OSSLKeyType.ML_DSA_65,
                OSSLKeyType.ML_DSA_87
        };

        for (OSSLKeyType keyType : keyTypes)
        {
            long generatedRef = 0;
            long decodeRef = 0;
            try
            {
                generatedRef = mldsaServiceNI.generateKeyPair(keyType.getKsType(), TestUtil.RNDSrc);
                Assertions.assertTrue(generatedRef > 0);
                int len = mldsaServiceNI.getPrivateKey(generatedRef, null);
                Assertions.assertTrue(len > 0);
                byte[] privateKey = new byte[len];
                Assertions.assertEquals(len, mldsaServiceNI.getPrivateKey(generatedRef, privateKey));

                decodeRef = TestNISelector.getSpecNI().allocate();
                Assertions.assertTrue(decodeRef > 0);
                operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
                mldsaServiceNI.decode_privateKey(decodeRef, keyType.getKsType(), privateKey, 0, privateKey.length);
                Assertions.fail();
            }
            catch (OpenSSLException e)
            {
                Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
            }
            finally
            {
                operationsTestNI.resetFlags();
                specNI.dispose(decodeRef);
                specNI.dispose(generatedRef);
            }
        }
    }


    @Test()
    public void MLDSAServiceJNI__initSign_accessContextArray() throws Exception
    {

        Assumptions.assumeFalse(Loader.isFFI());
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long mldsaRef = 0;
        long keyRef = 0;

        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = TestNISelector.getMLDSANI().generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);

            mldsaServiceNI.initSign(mldsaRef, keyRef, new byte[1024], 0, 0, TestUtil.RNDSrc);
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
            mldsaServiceNI.disposeSigner(mldsaRef);

        }
    }

    @Test()
    public void MLDSAServiceJNI__initSign_createPKEYCTX() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long mldsaRef = 0;
        long keyRef = 0;

        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = TestNISelector.getMLDSANI().generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);


            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            long code = mldsaServiceNI.ni_initSign(mldsaRef, keyRef, new byte[1024], 0, 0, TestUtil.RNDSrc);
            Assertions.assertEquals(-1002, code); // OpenSSL error with offset
        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
            mldsaServiceNI.disposeSigner(mldsaRef);

        }
    }

    @Test()
    public void MLDSAServiceJNI__initSign_EVP_PKEY_sign_message_init() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long mldsaRef = 0;
        long keyRef = 0;

        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = TestNISelector.getMLDSANI().generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);


            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            long code = mldsaServiceNI.ni_initSign(mldsaRef, keyRef, new byte[1024], 0, 0, TestUtil.RNDSrc);
            Assertions.assertEquals(-1003, code); // OpenSSL error with offset
        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
            mldsaServiceNI.disposeSigner(mldsaRef);

        }
    }


    @Test()
    public void MLDSAServiceJNI__initSign_signatureFetchNull() throws Exception
    {
        // Forces the EVP_SIGNATURE_fetch NULL short-circuit so the diagnostic
        // surfaces immediately, not after extract_tr / pctx setup masks it.

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long mldsaRef = 0;
        long keyRef = 0;

        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType(), TestUtil.RNDSrc);
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_CREATE_1);
            mldsaServiceNI.initSign(mldsaRef, keyRef, new byte[0], 0, 0, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (OpenSSLException e)
        {
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void MLDSAServiceJNI__initVerify_signatureFetchNull() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long mldsaRef = 0;
        long keyRef = 0;

        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType(), TestUtil.RNDSrc);
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_CREATE_1);
            mldsaServiceNI.initVerify(mldsaRef, keyRef, new byte[0], 0, 0);
            Assertions.fail();
        }
        catch (OpenSSLException e)
        {
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void MLDSAServiceJNI__initSign_failureLeavesNotInitialised() throws Exception
    {
        // Regression: a failed init must roll back partial state so the next
        // update/sign reports JO_NOT_INITIALIZED rather than allowing the
        // half-configured ctx to surface a confusing OpenSSL error.

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long mldsaRef = 0;
        long keyRef = 0;

        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType(), TestUtil.RNDSrc);
            Assertions.assertTrue(keyRef > 0);

            // Trigger init failure at EVP_PKEY_sign_message_init — leaves
            // sig + pctx + hash all live without the rollback fix.
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            long code = mldsaServiceNI.ni_initSign(mldsaRef, keyRef, new byte[0], 0,
                    MLDSASignatureSpi.MuHandling.INTERNAL.ordinal(), TestUtil.RNDSrc);
            Assertions.assertEquals(-1003, code);

            operationsTestNI.resetFlags();

            try
            {
                mldsaServiceNI.update(mldsaRef, new byte[1], 0, 1);
                Assertions.fail();
            }
            catch (IllegalStateException e)
            {
                Assertions.assertEquals("not initialized", e.getMessage());
            }
        }
        finally
        {
            operationsTestNI.resetFlags();
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void MLDSAServiceJNI__initVerify_failureLeavesNotInitialised() throws Exception
    {
        // Regression: verify-side analog of the rollback regression.

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long mldsaRef = 0;
        long keyRef = 0;

        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType(), TestUtil.RNDSrc);
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            long code = mldsaServiceNI.ni_initVerify(mldsaRef, keyRef, new byte[0], 0,
                    MLDSASignatureSpi.MuHandling.INTERNAL.ordinal());
            Assertions.assertEquals(-1006, code);

            operationsTestNI.resetFlags();

            try
            {
                mldsaServiceNI.verify(mldsaRef, new byte[1], 1);
                Assertions.fail();
            }
            catch (IllegalStateException e)
            {
                Assertions.assertEquals("not initialized", e.getMessage());
            }
        }
        finally
        {
            operationsTestNI.resetFlags();
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void MLDSAServiceJNI__initVerify_accessContextArray() throws Exception
    {

        Assumptions.assumeFalse(Loader.isFFI());
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long mldsaRef = 0;
        long keyRef = 0;

        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = TestNISelector.getMLDSANI().generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);

            mldsaServiceNI.initVerify(mldsaRef, keyRef, new byte[1024], 0, 1024);
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
            mldsaServiceNI.disposeSigner(mldsaRef);

        }
    }

    @Test()
    public void MLDSAServiceJNI__initVerify_createPKEYCTX() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long mldsaRef = 0;
        long keyRef = 0;

        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = TestNISelector.getMLDSANI().generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);


            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            long code = mldsaServiceNI.ni_initVerify(mldsaRef, keyRef, new byte[1024], 0, 0);
            Assertions.assertEquals(-1005, code); // OpenSSL error with offset
        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
            mldsaServiceNI.disposeSigner(mldsaRef);

        }
    }

    @Test()
    public void MLDSAServiceJNI__initVerify_EVP_PKEY_init() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long mldsaRef = 0;
        long keyRef = 0;

        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = TestNISelector.getMLDSANI().generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);


            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            long code = mldsaServiceNI.ni_initVerify(mldsaRef, keyRef, new byte[1024], 0, 0);
            Assertions.assertEquals(-1006, code); // OpenSSL error with offset
        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
            mldsaServiceNI.disposeSigner(mldsaRef);

        }
    }

    @Test()
    public void MLDSAServiceJNI_mldsa_update_accessInputArray() throws Exception
    {

        Assumptions.assumeFalse(Loader.isFFI());
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long mldsaRef = 0;
        long keyRef = 0;

        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.initSign(mldsaRef, keyRef, new byte[0], 0, 0, TestUtil.RNDSrc);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            mldsaServiceNI.update(mldsaRef, new byte[10], 0, 10);

            Assertions.fail();
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access input array", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);

        }
    }


    @Test()
    public void MLDSAServiceJNI_mldsa_update_osslError_extMu() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long mldsaRef = 0;
        long keyRef = 0;

        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.initSign(mldsaRef, keyRef, new byte[0], 0, MLDSASignatureSpi.MuHandling.EXTERNAL_MU.ordinal(), TestUtil.RNDSrc);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            mldsaServiceNI.update(mldsaRef, new byte[10], 0, 10);

            Assertions.fail();
        }
        catch (OpenSSLException e)
        {
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);

        }
    }


    @Test()
    public void MLDSAServiceJNI_mldsa_update_osslError_internalMu() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long mldsaRef = 0;
        long keyRef = 0;

        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.initSign(mldsaRef, keyRef, new byte[0], 0, MLDSASignatureSpi.MuHandling.INTERNAL.ordinal(), TestUtil.RNDSrc);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            mldsaServiceNI.update(mldsaRef, new byte[10], 0, 10);

            Assertions.fail();
        }
        catch (OpenSSLException e)
        {
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);

        }
    }

    @Test()
    public void MLDSAServiceJNI_mldsa_sign_outputRange() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());

        long mldsaRef = 0;
        long keyRef = 0;

        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.initSign(mldsaRef, keyRef, new byte[0], 0, 0, TestUtil.RNDSrc);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            mldsaServiceNI.sign(mldsaRef, new byte[1], 0, TestUtil.RNDSrc);

            Assertions.fail();
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access output array", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);

        }
    }


    @Test()
    public void MLDSAServiceJNI_mldsa_sign_osslErrorGettingLen() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long mldsaRef = 0;
        long keyRef = 0;

        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.initSign(mldsaRef, keyRef, new byte[0], 0, MLDSASignatureSpi.MuHandling.INTERNAL.ordinal(), TestUtil.RNDSrc);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            OpenSSL.getOpenSSLErrors(); // Purge any errors
            long len = mldsaServiceNI.sign(mldsaRef, null, 0, TestUtil.RNDSrc);

            Assertions.fail();
        }
        catch (OpenSSLException e)
        {
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        }
        finally
        {
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);

        }
    }

    @Test()
    public void MLDSAServiceJNI_mldsa_sign_osslErrorCalculatingSig() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long mldsaRef = 0;
        long keyRef = 0;

        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.initSign(mldsaRef, keyRef, new byte[0], 0, MLDSASignatureSpi.MuHandling.INTERNAL.ordinal(), TestUtil.RNDSrc);


            long len = mldsaServiceNI.sign(mldsaRef, null, 0, TestUtil.RNDSrc);

            byte[] sig = new byte[(int) len];

            OpenSSL.getOpenSSLErrors(); // Purge any errors
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            mldsaServiceNI.sign(mldsaRef, sig, 0, TestUtil.RNDSrc);


            Assertions.fail();
        }
        catch (OpenSSLException e)
        {
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        }
        finally
        {
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);

        }
    }

    @Test()
    public void MLDSAServiceJNI_mldsa_sign_outputInt32Overflow() throws Exception
    {
        // Validates the sig_len > INT32_MAX guard in mldsa_ctx_sign — fires
        // immediately after the EVP_PKEY_sign size query returns, before the
        // signature is actually produced.

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long mldsaRef = 0;
        long keyRef = 0;

        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.initSign(mldsaRef, keyRef, new byte[0], 0, MLDSASignatureSpi.MuHandling.INTERNAL.ordinal(), TestUtil.RNDSrc);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);
            mldsaServiceNI.sign(mldsaRef, null, 0, TestUtil.RNDSrc);

            Assertions.fail();
        }
        catch (OverflowException e)
        {
            Assertions.assertEquals("output too long int32", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);

        }
    }


    @Test()
    public void MLDSAServiceJNI_mldsa_sign_unexpectedSigLenChange() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long mldsaRef = 0;
        long keyRef = 0;

        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.initSign(mldsaRef, keyRef, new byte[0], 0, MLDSASignatureSpi.MuHandling.INTERNAL.ordinal(), TestUtil.RNDSrc);

            long len = mldsaServiceNI.sign(mldsaRef, null, 0, TestUtil.RNDSrc);

            byte[] sig = new byte[(int) len];

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_LEN_CHANGE_1);
            mldsaServiceNI.sign(mldsaRef, sig, 0, TestUtil.RNDSrc);

            Assertions.fail();
        }
        catch (IllegalStateException e)
        {
            Assertions.assertEquals("unexpected sig length change", e.getMessage());
        }
        finally
        {
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);

        }
    }


    @Test()
    public void MLDSAServiceJNI_mldsa_verify_accessSigBytes() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());

        long mldsaRef = 0;
        long keyRef = 0;

        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.initVerify(mldsaRef, keyRef, new byte[0], 0, MLDSASignatureSpi.MuHandling.INTERNAL.ordinal());

            OpenSSL.getOpenSSLErrors(); // Purge any errors
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            mldsaServiceNI.verify(mldsaRef, new byte[1], 1);

            Assertions.fail();
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access signature array", e.getMessage());
        }
        finally
        {
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);

        }
    }


    @Test()
    public void MLDSAServiceJNI_mldsa_verify_osslError() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long mldsaRef = 0;
        long keyRef = 0;

        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.initVerify(mldsaRef, keyRef, new byte[0], 0, MLDSASignatureSpi.MuHandling.INTERNAL.ordinal());

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            mldsaServiceNI.verify(mldsaRef, new byte[1], 1);

            Assertions.fail();
        }
        catch (OpenSSLException e)
        {
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        }
        finally
        {
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);

        }
    }


    // -------------------------------------------------------------------------
    // Helper-function fault injection: extract_tr / setup_hash /
    // setup_hash_with_tr_and_context. All three run under init_sign with
    // INTERNAL mu_mode. Each path is wrapped with a distinct OPS cookie AND
    // a distinct OPS_OFFSET so the raw return code uniquely identifies which
    // branch fired.
    // -------------------------------------------------------------------------

    private void assertInitSignReturns(OperationsTestNI.OpsTestFlag flag, long expectedCode) throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType(), TestUtil.RNDSrc);
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(flag);
            long code = mldsaServiceNI.ni_initSign(mldsaRef, keyRef, new byte[0], 0,
                    MLDSASignatureSpi.MuHandling.INTERNAL.ordinal(), TestUtil.RNDSrc);
            Assertions.assertEquals(expectedCode, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }

    private static final long JO_OPENSSL_ERROR              = ErrorCode.JO_OPENSSL_ERROR.getCode();
    private static final long JO_EXTRACTED_KEY_UNEXPECTED_LEN = ErrorCode.JO_EXTRACTED_KEY_UNEXPECTED_LEN.getCode();

    @Test()
    public void MLDSA_extract_tr_getOctetFail() throws Exception
    {
        assertInitSignReturns(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3, JO_OPENSSL_ERROR - 2000);
    }

    @Test()
    public void MLDSA_extract_tr_unexpectedKeyLen() throws Exception
    {
        assertInitSignReturns(OperationsTestNI.OpsTestFlag.OPS_SHORT_SIZE_1, JO_EXTRACTED_KEY_UNEXPECTED_LEN - 2001);
    }

    @Test()
    public void MLDSA_extract_tr_shakeCtxNew() throws Exception
    {
        assertInitSignReturns(OperationsTestNI.OpsTestFlag.OPS_FAILED_CREATE_2, JO_OPENSSL_ERROR - 2002);
    }

    @Test()
    public void MLDSA_extract_tr_shakeInit() throws Exception
    {
        assertInitSignReturns(OperationsTestNI.OpsTestFlag.OPS_FAILED_INIT_1, JO_OPENSSL_ERROR - 2003);
    }

    @Test()
    public void MLDSA_extract_tr_shakeUpdate() throws Exception
    {
        assertInitSignReturns(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_4, JO_OPENSSL_ERROR - 2004);
    }

    @Test()
    public void MLDSA_extract_tr_shakeFinalXOF() throws Exception
    {
        assertInitSignReturns(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_5, JO_OPENSSL_ERROR - 2005);
    }

    @Test()
    public void MLDSA_setup_hash_evpMdCtxNew() throws Exception
    {
        assertInitSignReturns(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_7, JO_OPENSSL_ERROR - 2010);
    }

    @Test()
    public void MLDSA_setup_hash_digestInit() throws Exception
    {
        assertInitSignReturns(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_8, JO_OPENSSL_ERROR - 2011);
    }

    @Test()
    public void MLDSA_setup_hash_with_tr_and_context_trUpdate() throws Exception
    {
        assertInitSignReturns(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_9, JO_OPENSSL_ERROR - 2020);
    }

    @Test()
    public void MLDSA_setup_hash_with_tr_and_context_preHashByte() throws Exception
    {
        assertInitSignReturns(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_10, JO_OPENSSL_ERROR - 2021);
    }

    @Test()
    public void MLDSA_setup_hash_with_tr_and_context_lenByte() throws Exception
    {
        assertInitSignReturns(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_11, JO_OPENSSL_ERROR - 2022);
    }

    @Test()
    public void MLDSA_setup_hash_with_tr_and_context_ctxBytes() throws Exception
    {
        assertInitSignReturns(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_12, JO_OPENSSL_ERROR - 2023);
    }
}

