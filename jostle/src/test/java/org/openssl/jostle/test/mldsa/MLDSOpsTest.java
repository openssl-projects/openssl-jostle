package org.openssl.jostle.test.mldsa;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.AccessException;
import org.openssl.jostle.jcajce.provider.OpenSSL;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.OverflowException;
import org.openssl.jostle.jcajce.provider.mldsa.MLDSAServiceNI;
import org.openssl.jostle.jcajce.provider.mldsa.MLDSASignatureSpi;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.test.crypto.TestNISelector;
import org.openssl.jostle.util.ops.OperationsTestNI;

public class MLDSOpsTest
{

    static
    {
        CryptoServicesRegistrar.isNativeAvailable(); // Trigger Loading
    }

    MLDSAServiceNI mldsaServiceNI = TestNISelector.getMLDSANI();
    SpecNI specNI = TestNISelector.getSpecNI();
    OperationsTestNI operationsTestNI = TestNISelector.getOperationsTestNI();


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
            mldsaServiceNI.handleErrors(mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType()));

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
    public void MLDSAServiceJNI_generateKeyPair_seedLenNegative() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            mldsaServiceNI.handleErrors(
                    mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.ordinal(), new byte[32], 32)
            );
            Assertions.fail();
        } catch (AccessException e)
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
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);

            mldsaServiceNI.handleErrors(mldsaServiceNI.getPublicKey(keyRef, new byte[2048]));
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
    public void MLDSAServiceJNI_getPrivateKey_accessByteArray() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());

        long keyRef = 0;
        try
        {
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);

            mldsaServiceNI.handleErrors(mldsaServiceNI.getPrivateKey(keyRef, new byte[4096]));
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
    public void MLDSAService_getPrivateKey_OpenSSLError_1() throws Exception
    {
        //
        // Where min_len is determined
        //

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = 0;
        try
        {
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);

            mldsaServiceNI.handleErrors(mldsaServiceNI.getPrivateKey(keyRef, new byte[4096]));
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
    public void MLDSAService_getPrivateKey_OpenSSLError_2() throws Exception
    {
        //
        // Where encoding operation occurs, uses offset to the error code during ops testing.
        //

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = 0;
        try
        {
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);

            long code = mldsaServiceNI.getPrivateKey(keyRef, new byte[4096]);
            Assertions.assertEquals(-1002,code);

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
    public void MLDSAService_getPrivateKey_OutputInt32Overflow() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = 0;
        try
        {
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);

            mldsaServiceNI.handleErrors(mldsaServiceNI.getPrivateKey(keyRef, new byte[4096]));
            Assertions.fail();
        } catch (OverflowException e)
        {
            Assertions.assertEquals("output size overflow", e.getMessage());
        } finally
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
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);

            mldsaServiceNI.handleErrors(mldsaServiceNI.getPublicKey(keyRef, new byte[2048]));
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
    public void MLDSAService_getPublicKey_OpenSSLError_2() throws Exception
    {
        //
        // Where encoding operation occurs, uses offset to the error code during ops testing.
        //

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = 0;
        try
        {
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);

            long code = mldsaServiceNI.getPublicKey(keyRef, new byte[2048]);
            Assertions.assertEquals(-1002,code);

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
    public void MLDSAService_getPublicKey_OutputInt32Overflow() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = 0;
        try
        {
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);

            mldsaServiceNI.handleErrors(mldsaServiceNI.getPublicKey(keyRef, new byte[2048]));
            Assertions.fail();
        } catch (OverflowException e)
        {
            Assertions.assertEquals("output size overflow", e.getMessage());
        } finally
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
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);

            mldsaServiceNI.handleErrors(mldsaServiceNI.getSeed(keyRef, new byte[2048]));
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
    public void MLDSAServiceJNI_getSeed_OpenSSLError() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = 0;
        try
        {
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);

            mldsaServiceNI.handleErrors(mldsaServiceNI.getSeed(keyRef, new byte[2048]));
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
    public void MLDSAServiceJNI_getSeed_OutputInt32Overflow() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = 0;
        try
        {
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);

            mldsaServiceNI.handleErrors(mldsaServiceNI.getSeed(keyRef, new byte[2048]));
            Assertions.fail();
        } catch (OverflowException e)
        {
            Assertions.assertEquals("output size overflow", e.getMessage());
        } finally
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

            mldsaServiceNI.handleErrors(mldsaServiceNI.decode_publicKey(keyRef, OSSLKeyType.ML_DSA_44.getKsType(), new byte[1024], 0, 1024));
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
                mldsaServiceNI.handleErrors(mldsaServiceNI.decode_publicKey(keyRef, keyType, key, 0, key.length));
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

            mldsaServiceNI.handleErrors(mldsaServiceNI.decode_privateKey(keyRef, OSSLKeyType.ML_DSA_44.getKsType(), new byte[1024], 0, 1024));
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
            keyRef = TestNISelector.getMLDSANI().generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());

            Assertions.assertTrue(keyRef > 0);
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);

            mldsaServiceNI.handleErrors(mldsaServiceNI.initSign(mldsaRef, keyRef, new byte[1024], 0, 0));
            Assertions.fail();
        } catch (AccessException e)
        {
            Assertions.assertEquals("unable to access context array", e.getMessage());

        } finally
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
            keyRef = TestNISelector.getMLDSANI().generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());

            Assertions.assertTrue(keyRef > 0);


            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            long code = mldsaServiceNI.initSign(mldsaRef, keyRef, new byte[1024], 0, 0);
            Assertions.assertEquals(-1002, code); // OpenSSL error with offset
        } finally
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
            keyRef = TestNISelector.getMLDSANI().generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());

            Assertions.assertTrue(keyRef > 0);


            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            long code = mldsaServiceNI.initSign(mldsaRef, keyRef, new byte[1024], 0, 0);
            Assertions.assertEquals(-1003, code); // OpenSSL error with offset
        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
            mldsaServiceNI.disposeSigner(mldsaRef);
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
            keyRef = TestNISelector.getMLDSANI().generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());

            Assertions.assertTrue(keyRef > 0);
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);

            mldsaServiceNI.handleErrors(mldsaServiceNI.initVerify(mldsaRef, keyRef, new byte[1024], 0, 1024));
            Assertions.fail();
        } catch (AccessException e)
        {
            Assertions.assertEquals("unable to access context array", e.getMessage());

        } finally
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
            keyRef = TestNISelector.getMLDSANI().generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());

            Assertions.assertTrue(keyRef > 0);


            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            long code = mldsaServiceNI.initVerify(mldsaRef, keyRef, new byte[1024], 0, 0);
            Assertions.assertEquals(-1005, code); // OpenSSL error with offset
        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
            mldsaServiceNI.disposeSigner(mldsaRef);
        }
    }

    @Test()
    public void MLDSAServiceJNI__initVerify_EVP_PKEY_sign_message_init() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = TestNISelector.getMLDSANI().generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());

            Assertions.assertTrue(keyRef > 0);


            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            long code = mldsaServiceNI.initVerify(mldsaRef, keyRef, new byte[1024], 0, 0);
            Assertions.assertEquals(-1006, code); // OpenSSL error with offset
        } finally
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
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.initSign(mldsaRef, keyRef, new byte[0], 0, 0));

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            mldsaServiceNI.handleErrors(mldsaServiceNI.update(mldsaRef, new byte[10], 0, 10));

            Assertions.fail();
        } catch (AccessException e)
        {
            Assertions.assertEquals("unable to access input array", e.getMessage());
        } finally
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
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.initSign(mldsaRef, keyRef, new byte[0], 0, MLDSASignatureSpi.MuHandling.EXTERNAL_MU.ordinal()));

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            mldsaServiceNI.handleErrors(mldsaServiceNI.update(mldsaRef, new byte[10], 0, 10));

            Assertions.fail();
        } catch (OpenSSLException e)
        {
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        } finally
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
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.initSign(mldsaRef, keyRef, new byte[0], 0, MLDSASignatureSpi.MuHandling.INTERNAL.ordinal()));

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            mldsaServiceNI.handleErrors(mldsaServiceNI.update(mldsaRef, new byte[10], 0, 10));

            Assertions.fail();
        } catch (OpenSSLException e)
        {
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        } finally
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
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.initSign(mldsaRef, keyRef, new byte[0], 0, 0));

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            mldsaServiceNI.handleErrors(mldsaServiceNI.sign(mldsaRef, new byte[1], 0));

            Assertions.fail();
        } catch (AccessException e)
        {
            Assertions.assertEquals("unable to access output array", e.getMessage());
        } finally
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
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.initSign(mldsaRef, keyRef, new byte[0], 0, MLDSASignatureSpi.MuHandling.INTERNAL.ordinal()));

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            OpenSSL.getOpenSSLErrors(); // Purge any errors
            long len = mldsaServiceNI.handleErrors(mldsaServiceNI.sign(mldsaRef, null, 0));

            Assertions.fail();
        } catch (OpenSSLException e)
        {
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        } finally
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
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.initSign(mldsaRef, keyRef, new byte[0], 0, MLDSASignatureSpi.MuHandling.INTERNAL.ordinal()));


            long len = mldsaServiceNI.handleErrors(mldsaServiceNI.sign(mldsaRef, null, 0));

            byte[] sig = new byte[(int) len];

            OpenSSL.getOpenSSLErrors(); // Purge any errors
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            mldsaServiceNI.handleErrors(mldsaServiceNI.sign(mldsaRef, sig, 0));


            Assertions.fail();
        } catch (OpenSSLException e)
        {
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        } finally
        {
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
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.initSign(mldsaRef, keyRef, new byte[0], 0, MLDSASignatureSpi.MuHandling.INTERNAL.ordinal()));

            long len = mldsaServiceNI.handleErrors(mldsaServiceNI.sign(mldsaRef, null, 0));

            byte[] sig = new byte[(int) len];

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_LEN_CHANGE_1);
            mldsaServiceNI.handleErrors(mldsaServiceNI.sign(mldsaRef, sig, 0));

            Assertions.fail();
        } catch (IllegalStateException e)
        {
            Assertions.assertEquals("unexpected sig length change", e.getMessage());
        } finally
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
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.initVerify(mldsaRef, keyRef, new byte[0], 0, MLDSASignatureSpi.MuHandling.INTERNAL.ordinal()));

            OpenSSL.getOpenSSLErrors(); // Purge any errors
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            mldsaServiceNI.handleErrors(mldsaServiceNI.verify(mldsaRef, new byte[1], 1));

            Assertions.fail();
        } catch (AccessException e)
        {
            Assertions.assertEquals("unable to access signature array", e.getMessage());
        } finally
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
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.initVerify(mldsaRef, keyRef, new byte[0], 0, MLDSASignatureSpi.MuHandling.INTERNAL.ordinal()));

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            mldsaServiceNI.handleErrors(mldsaServiceNI.verify(mldsaRef, new byte[1], 1));

            Assertions.fail();
        } catch (OpenSSLException e)
        {
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        } finally
        {
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }
}

