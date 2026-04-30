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

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.junit.jupiter.api.*;

import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.interfaces.SLHDSAPublicKey;
import org.openssl.jostle.jcajce.provider.*;
import org.openssl.jostle.jcajce.provider.slhdsa.SLHDSAServiceNI;
import org.openssl.jostle.jcajce.provider.slhdsa.SLHDSASignatureSpi;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.SLHDSAParameterSpec;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.test.crypto.TestNISelector;
import org.openssl.jostle.util.ops.OperationsTestNI;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

public class SLHDSAOpsTest
{


    SLHDSAServiceNI slhDSAServiceNI = TestNISelector.getSLHDSANI();
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
    public void testSLHDSAGenerateKeyPair_openSSLError() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = 0;
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
           slhDSAServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType(), TestUtil.RNDSrc);

            Assertions.fail();
        } catch (OpenSSLException e)
        {
            //
            // Asserting the code path would actually return if there was an error.
            // There isn't an error so the msg is null
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void SLHDSAServiceJNI_generateKeyPair_seedLenNegative() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
           
                    slhDSAServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.ordinal(), new byte[32], 32, TestUtil.RNDSrc
            );
            Assertions.fail();
        } catch (AccessException e)
        {
            Assertions.assertEquals("unable to access seed array", e.getMessage());
        }
    }

    //--
    @Test()
    public void SLHDSAServiceJNI_getPrivateKey_accessByteArray() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());

        long keyRef = 0;
        try
        {
            keyRef = slhDSAServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType(), TestUtil.RNDSrc);
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);

           slhDSAServiceNI.getPrivateKey(keyRef, new byte[4096]);
            Assertions.fail();
        } catch (AccessException e)
        {
            Assertions.assertEquals("unable to access output array", e.getMessage());

        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void SLHDSAServiceJNI_getPrivateKey_OpenSSLError_1() throws Exception
    {

        // Where min_len is determined

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = 0;
        try
        {
            keyRef = slhDSAServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType(), TestUtil.RNDSrc);
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);

           slhDSAServiceNI.getPrivateKey(keyRef, new byte[4096]);
            Assertions.fail();
        } catch (OpenSSLException e)
        {
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void SLHDSAServiceJNI_getPrivateKey_OpenSSLError_2() throws Exception
    {

        // Where encoding takes place

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = 0;
        try
        {
            keyRef = slhDSAServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType(), TestUtil.RNDSrc);
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);

            long code = slhDSAServiceNI.ni_getPrivateKey(keyRef, new byte[4096]);
            Assertions.assertEquals(-1002, code);
        } catch (OpenSSLException e)
        {
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void SLHDSAServiceJNI_getPrivateKey_OutputInt32Overflow() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = 0;
        try
        {
            keyRef = slhDSAServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType(), TestUtil.RNDSrc);
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);

           slhDSAServiceNI.getPrivateKey(keyRef, new byte[4096]);
            Assertions.fail();
        } catch (OverflowException e)
        {
            Assertions.assertEquals("output too long int32", e.getMessage());
        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }

    //--

    @Test()
    public void SLHDSAServiceJNI_getPublicKey_accessByteArray() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());

        long keyRef = 0;
        try
        {
            keyRef = slhDSAServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType(), TestUtil.RNDSrc);
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);

           slhDSAServiceNI.getPublicKey(keyRef, new byte[2048]);
            Assertions.fail();
        } catch (AccessException e)
        {
            Assertions.assertEquals("unable to access output array", e.getMessage());

        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void SLHDSAServiceJNI_getPublicKey_OpenSSLError() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = 0;
        try
        {
            keyRef = slhDSAServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType(), TestUtil.RNDSrc);
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);

           slhDSAServiceNI.getPublicKey(keyRef, new byte[2048]);
            Assertions.fail();
        } catch (OpenSSLException e)
        {
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_getPublicKey_OutputInt32Overflow() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = 0;
        try
        {
            keyRef = slhDSAServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType(), TestUtil.RNDSrc);
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);

           slhDSAServiceNI.getPublicKey(keyRef, new byte[2048]);
            Assertions.fail();
        } catch (OverflowException e)
        {
            Assertions.assertEquals("output too long int32", e.getMessage());
        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void SLHDSAServiceJNI_decode_1publicKey_accessByteArray() throws Exception
    {
        Assumptions.assumeFalse(Loader.isFFI());
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);

           slhDSAServiceNI.decode_publicKey(keyRef, OSSLKeyType.SLH_DSA_SHA2_128f.getKsType(), new byte[1024], 0, 1024);
            Assertions.fail();
        } catch (AccessException e)
        {
            Assertions.assertEquals("unable to access input array", e.getMessage());

        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void SLHDSAServiceJNI_decode_1publicKey_openSSLErrorDecoding() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long keyRef = 0;

        List<Object[]> tuples = new ArrayList<Object[]>();


        for (SLHDSAParameterSpec parameterSpec : SLHDSAParameterSpec.getParameterSpecs())
        {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("SLHDSA", JostleProvider.PROVIDER_NAME);
            keyPairGenerator.initialize(parameterSpec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            tuples.add(new Object[]{parameterSpec.getKeyType().getKsType(), ((SLHDSAPublicKey) keyPair.getPublic()).getPublicData()});

        }


        for (Object[] tuple : tuples)
        {

            int keyType = (Integer) tuple[0];
            byte[] key = (byte[]) tuple[1];

            try
            {
                keyRef = TestNISelector.getSpecNI().allocate();
                Assertions.assertTrue(keyRef > 0);
                operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
               slhDSAServiceNI.decode_publicKey(keyRef, keyType, key, 0, key.length);
                Assertions.fail();
            } catch (OpenSSLException e)
            {
                Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
            } finally
            {
                operationsTestNI.resetFlags();
                specNI.dispose(keyRef);
            }
        }
    }


    @Test()
    public void SLHDSAServiceJNI_decode_1privateKey_accessByteArray() throws Exception
    {

        Assumptions.assumeFalse(Loader.isFFI());
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);

           slhDSAServiceNI.decode_privateKey(keyRef, OSSLKeyType.SLH_DSA_SHA2_128f.getKsType(), new byte[1024], 0, 1024);
            Assertions.fail();
        } catch (AccessException e)
        {
            Assertions.assertEquals("unable to access input array", e.getMessage());

        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void SLHDSAServiceJNI_decode_1privateKey_openSSLErrorDecoding() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long keyRef = 0;

        List<Object[]> tuples = new ArrayList<Object[]>();


        for (SLHDSAParameterSpec parameterSpec : SLHDSAParameterSpec.getParameterSpecs())
        {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("SLHDSA", JostleProvider.PROVIDER_NAME);
            keyPairGenerator.initialize(parameterSpec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            byte[] b = PrivateKeyInfo.getInstance(keyPair.getPrivate().getEncoded()).getPrivateKey().getOctets();
            tuples.add(new Object[]{parameterSpec.getKeyType().getKsType(), b});

        }


        for (Object[] tuple : tuples)
        {

            int keyType = (Integer) tuple[0];
            byte[] key = (byte[]) tuple[1];

            try
            {
                keyRef = TestNISelector.getSpecNI().allocate();
                Assertions.assertTrue(keyRef > 0);
                operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
               slhDSAServiceNI.decode_privateKey(keyRef, keyType, key, 0, key.length);
                Assertions.fail();
            } catch (OpenSSLException e)
            {
                Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
            } finally
            {
                operationsTestNI.resetFlags();
                specNI.dispose(keyRef);
            }
        }
    }


    @Test()
    public void SLHDSAServiceJNI__initSign_accessContextArray() throws Exception
    {

        Assumptions.assumeFalse(Loader.isFFI());
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = TestNISelector.getSLHDSANI().generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);

           slhDSAServiceNI.initSign(slhdsaRef, keyRef, new byte[1024], 0, 0, 0, TestUtil.RNDSrc);
            Assertions.fail();
        } catch (AccessException e)
        {
            Assertions.assertEquals("unable to access context array", e.getMessage());

        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
            slhDSAServiceNI.disposeSigner(slhdsaRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI__initSign_createPKEYCTX() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = TestNISelector.getSLHDSANI().generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);


            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            long code = slhDSAServiceNI.ni_initSign(slhdsaRef, keyRef, new byte[1024], 0, 0, 0, TestUtil.RNDSrc);
            Assertions.assertEquals(-1002, code); // OpenSSL error with offset
        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
            slhDSAServiceNI.disposeSigner(slhdsaRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI__initSign_EVP_PKEY_sign_message_init() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = TestNISelector.getSLHDSANI().generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);


            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            long code = slhDSAServiceNI.ni_initSign(slhdsaRef, keyRef, new byte[1024], 0, 0, 0, TestUtil.RNDSrc);
            Assertions.assertEquals(-1003, code); // OpenSSL error with offset
        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
            slhDSAServiceNI.disposeSigner(slhdsaRef);
        }
    }


    @Test()
    public void SLHDSAServiceJNI__initVerify_accessContextArray() throws Exception
    {

        Assumptions.assumeFalse(Loader.isFFI());
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = TestNISelector.getSLHDSANI().generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);

           slhDSAServiceNI.initVerify(slhdsaRef, keyRef, new byte[1024], 0, 1024, 0);
            Assertions.fail();
        } catch (AccessException e)
        {
            Assertions.assertEquals("unable to access context array", e.getMessage());

        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
            slhDSAServiceNI.disposeSigner(slhdsaRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI__initVerify_createPKEYCTX() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = TestNISelector.getSLHDSANI().generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);


            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            long code = slhDSAServiceNI.ni_initVerify(slhdsaRef, keyRef, new byte[1024], 0, 0, 0);
            Assertions.assertEquals(-1005, code); // OpenSSL error with offset
        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
            slhDSAServiceNI.disposeSigner(slhdsaRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI__initVerify_EVP_PKEY_sign_message_init() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = TestNISelector.getSLHDSANI().generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);


            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            long code = slhDSAServiceNI.ni_initVerify(slhdsaRef, keyRef, new byte[1024], 0, 0, 0);
            Assertions.assertEquals(-1006, code); // OpenSSL error with offset
        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
            slhDSAServiceNI.disposeSigner(slhdsaRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_slhdsa_update_accessInputArray() throws Exception
    {

        Assumptions.assumeFalse(Loader.isFFI());
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhDSAServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
           slhDSAServiceNI.initSign(slhdsaRef, keyRef, new byte[0], 0, 0, 0, TestUtil.RNDSrc);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
           slhDSAServiceNI.update(slhdsaRef, new byte[10], 0, 10);

            Assertions.fail();
        } catch (AccessException e)
        {
            Assertions.assertEquals("unable to access input array", e.getMessage());
        } finally
        {
            operationsTestNI.resetFlags();
            slhDSAServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void SLHDSAServiceJNI_slhdsa_update_osslError_extMu() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhDSAServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
           slhDSAServiceNI.initSign(slhdsaRef, keyRef, new byte[0], 0, SLHDSASignatureSpi.MessageEncoding.PURE.ordinal(), 0, TestUtil.RNDSrc);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
           slhDSAServiceNI.update(slhdsaRef, new byte[10], 0, 10);

            Assertions.fail();
        } catch (OpenSSLException e)
        {
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        } finally
        {
            operationsTestNI.resetFlags();
            slhDSAServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void SLHDSAServiceJNI_slhdsa_sign_outputRange() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());

        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhDSAServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
           slhDSAServiceNI.initSign(slhdsaRef, keyRef, new byte[0], 0, 0, 0, TestUtil.RNDSrc);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
           slhDSAServiceNI.sign(slhdsaRef, new byte[1], 0, TestUtil.RNDSrc);

            Assertions.fail();
        } catch (AccessException e)
        {
            Assertions.assertEquals("unable to access output array", e.getMessage());
        } finally
        {
            operationsTestNI.resetFlags();
            slhDSAServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void SLHDSAServiceJNI_slhdsa_sign_osslErrorGettingLen() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhDSAServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
           slhDSAServiceNI.initSign(slhdsaRef, keyRef, new byte[0], 0, SLHDSASignatureSpi.MessageEncoding.PURE.ordinal(), 0, TestUtil.RNDSrc);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            long len =slhDSAServiceNI.sign(slhdsaRef, null, 0, TestUtil.RNDSrc);

            Assertions.fail();
        } catch (OpenSSLException e)
        {
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        } finally
        {
            slhDSAServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_slhdsa_sign_osslErrorCalculatingSig() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhDSAServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
           slhDSAServiceNI.initSign(slhdsaRef, keyRef, new byte[0], 0, SLHDSASignatureSpi.MessageEncoding.PURE.ordinal(), 0, TestUtil.RNDSrc);

            long len =slhDSAServiceNI.sign(slhdsaRef, null, 0, TestUtil.RNDSrc);

            byte[] sig = new byte[(int) len];

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
           slhDSAServiceNI.sign(slhdsaRef, sig, 0, TestUtil.RNDSrc);


            Assertions.fail();
        } catch (OpenSSLException e)
        {
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        } finally
        {
            slhDSAServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_slhdsa_sign_unexpectedSigLenChange() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhDSAServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
           slhDSAServiceNI.initSign(slhdsaRef, keyRef, new byte[0], 0, SLHDSASignatureSpi.MessageEncoding.PURE.ordinal(), 0, TestUtil.RNDSrc);

            long len =slhDSAServiceNI.sign(slhdsaRef, null, 0, TestUtil.RNDSrc);

            byte[] sig = new byte[(int) len];

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_LEN_CHANGE_1);
           slhDSAServiceNI.sign(slhdsaRef, sig, 0, TestUtil.RNDSrc);

            Assertions.fail();
        } catch (IllegalStateException e)
        {
            Assertions.assertEquals("unexpected sig length change", e.getMessage());
        } finally
        {
            slhDSAServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void SLHDSAServiceJNI_slhdsa_verify_accessSigBytes() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());

        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhDSAServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
           slhDSAServiceNI.initVerify(slhdsaRef, keyRef, new byte[0], 0, SLHDSASignatureSpi.MessageEncoding.PURE.ordinal(), 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
           slhDSAServiceNI.verify(slhdsaRef, new byte[1], 1);

            Assertions.fail();
        } catch (AccessException e)
        {
            Assertions.assertEquals("unable to access signature array", e.getMessage());
        } finally
        {
            slhDSAServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void SLHDSAServiceJNI_slhdsa_verify_osslError() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhDSAServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
           slhDSAServiceNI.initVerify(slhdsaRef, keyRef, new byte[0], 0, SLHDSASignatureSpi.MessageEncoding.PURE.ordinal(), 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
           slhDSAServiceNI.verify(slhdsaRef, new byte[1], 1);

            Assertions.fail();
        } catch (OpenSSLException e)
        {
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        } finally
        {
            slhDSAServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }


    // -------------------------------------------------------------------------
    // Wave 7 OPS coverage: keygen EVP failure paths + BIO_new in init paths.
    // Each path has a distinct OPS cookie AND a distinct OPS_OFFSET so the
    // raw return code uniquely identifies the branch that fired.
    // -------------------------------------------------------------------------

    private static final long JO_OPENSSL_ERROR = ErrorCode.JO_OPENSSL_ERROR.getCode();

    private void assertGenerateKeyPairReturns(OperationsTestNI.OpsTestFlag flag, long expectedCode) throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long keyRef = 0;
        try
        {
            int[] err = new int[1];
            operationsTestNI.setFlag(flag);
            keyRef = slhDSAServiceNI.ni_generateKeyPair(
                    OSSLKeyType.SLH_DSA_SHA2_128f.getKsType(), err, TestUtil.RNDSrc);
            Assertions.assertEquals(0L, keyRef);
            Assertions.assertEquals(expectedCode, err[0]);
        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSA_generateKeyPair_ctxNew_fail() throws Exception
    {
        assertGenerateKeyPairReturns(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3, JO_OPENSSL_ERROR - 2100);
    }

    @Test()
    public void SLHDSA_generateKeyPair_keygenInit_fail() throws Exception
    {
        assertGenerateKeyPairReturns(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_4, JO_OPENSSL_ERROR - 2101);
    }

    @Test()
    public void SLHDSA_generateKeyPair_setParams_fail() throws Exception
    {
        assertGenerateKeyPairReturns(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_5, JO_OPENSSL_ERROR - 2102);
    }

    @Test()
    public void SLHDSA_generateKeyPair_keygen_fail() throws Exception
    {
        assertGenerateKeyPairReturns(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_6, JO_OPENSSL_ERROR - 2103);
    }


    @Test()
    public void SLHDSA_initSign_bioNew_fail() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhDSAServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType(), TestUtil.RNDSrc);
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_CREATE_2);
            long code = slhDSAServiceNI.ni_initSign(slhdsaRef, keyRef, new byte[0], 0,
                    SLHDSASignatureSpi.MessageEncoding.PURE.ordinal(), 0, TestUtil.RNDSrc);
            // BIO_new failure path returns JO_OPENSSL_ERROR with offset 1002.
            Assertions.assertEquals(JO_OPENSSL_ERROR - 1002, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            slhDSAServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSA_initVerify_bioNew_fail() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhDSAServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType(), TestUtil.RNDSrc);
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_CREATE_2);
            long code = slhDSAServiceNI.ni_initVerify(slhdsaRef, keyRef, new byte[0], 0,
                    SLHDSASignatureSpi.MessageEncoding.PURE.ordinal(), 0);
            // BIO_new failure path returns JO_OPENSSL_ERROR with offset 1005.
            Assertions.assertEquals(JO_OPENSSL_ERROR - 1005, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            slhDSAServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }


    // -------------------------------------------------------------------------
    // EVP_SIGNATURE_fetch NULL short-circuit in init_sign / init_verify.
    // OPS_FAILED_CREATE_1 forces ctx->sig == NULL post-fetch; the function
    // exits with plain JO_OPENSSL_ERROR (no offset).
    // -------------------------------------------------------------------------

    @Test()
    public void SLHDSA_initSign_signatureFetchNull() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhDSAServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType(), TestUtil.RNDSrc);
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_CREATE_1);
            long code = slhDSAServiceNI.ni_initSign(slhdsaRef, keyRef, new byte[0], 0,
                    SLHDSASignatureSpi.MessageEncoding.PURE.ordinal(), 0, TestUtil.RNDSrc);
            Assertions.assertEquals(JO_OPENSSL_ERROR, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            slhDSAServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSA_initVerify_signatureFetchNull() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhDSAServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType(), TestUtil.RNDSrc);
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_CREATE_1);
            long code = slhDSAServiceNI.ni_initVerify(slhdsaRef, keyRef, new byte[0], 0,
                    SLHDSASignatureSpi.MessageEncoding.PURE.ordinal(), 0);
            Assertions.assertEquals(JO_OPENSSL_ERROR, code);
        }
        finally
        {
            operationsTestNI.resetFlags();
            slhDSAServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }
}
