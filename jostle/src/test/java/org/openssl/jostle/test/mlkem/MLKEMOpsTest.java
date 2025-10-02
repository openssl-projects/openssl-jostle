package org.openssl.jostle.test.mlkem;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.AccessException;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.OverflowException;
import org.openssl.jostle.jcajce.provider.mlkem.MLKEMServiceNI;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.test.crypto.TestNISelector;
import org.openssl.jostle.util.ops.OperationsTestNI;

public class MLKEMOpsTest
{

    static
    {
        CryptoServicesRegistrar.isNativeAvailable(); // Trigger Loading
    }

    MLKEMServiceNI mlkemServiceNI = TestNISelector.getMLKEMNI();
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
    public void testMLKEMGenerateKeyPair_openSSLError() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = 0;
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            mlkemServiceNI.handleErrors(mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType()));

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
    public void MLKEMServiceJNI_generateKeyPair_seedLenNegative() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            mlkemServiceNI.handleErrors(
                    mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.ordinal(), new byte[64], 64)
            );
            Assertions.fail();
        } catch (AccessException e)
        {
            Assertions.assertEquals("unable to access seed array", e.getMessage());
        }
    }


    @Test()
    public void MLKEMServiceJNI_getPublicKey_accessByteArray() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());

        long keyRef = 0;
        try
        {
            keyRef = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType());
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);

            mlkemServiceNI.handleErrors(mlkemServiceNI.getPublicKey(keyRef, new byte[2048]));
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
    public void MLKEMServiceJNI_getPrivateKey_accessByteArray() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());

        long keyRef = 0;
        try
        {
            keyRef = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType());
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);

            mlkemServiceNI.handleErrors(mlkemServiceNI.getPrivateKey(keyRef, new byte[4096]));
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
    public void MLKEMService_getPrivateKey_OpenSSLError_1() throws Exception
    {
        //
        // Where min_len is determined
        //

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = 0;
        try
        {
            keyRef = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType());
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);

            mlkemServiceNI.handleErrors(mlkemServiceNI.getPrivateKey(keyRef, new byte[4096]));
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
    public void MLKEMService_getPrivateKey_OpenSSLError_2() throws Exception
    {
        //
        // Where encoding operation occurs, uses offset to the error code during ops testing.
        //

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = 0;
        try
        {
            keyRef = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType());
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);

            long code = mlkemServiceNI.getPrivateKey(keyRef, new byte[4096]);
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
    public void MLKEMService_getPrivateKey_OutputInt32Overflow() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = 0;
        try
        {
            keyRef = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType());
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);

            mlkemServiceNI.handleErrors(mlkemServiceNI.getPrivateKey(keyRef, new byte[4096]));
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
    public void MLKEMService_getPublicKey_OpenSSLError_1() throws Exception
    {
        //
        // Where min_len is determined
        //

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = 0;
        try
        {
            keyRef = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType());
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);

            mlkemServiceNI.handleErrors(mlkemServiceNI.getPublicKey(keyRef, new byte[2048]));
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
    public void MLKEMService_getPublicKey_OpenSSLError_2() throws Exception
    {
        //
        // Where encoding operation occurs, uses offset to the error code during ops testing.
        //

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = 0;
        try
        {
            keyRef = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType());
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);

            long code = mlkemServiceNI.getPublicKey(keyRef, new byte[2048]);
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
    public void MLKEMService_getPublicKey_OutputInt32Overflow() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = 0;
        try
        {
            keyRef = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType());
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);

            mlkemServiceNI.handleErrors(mlkemServiceNI.getPublicKey(keyRef, new byte[2048]));
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
    public void MLKEMServiceJNI_getSeed_accessByteArray() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());
        long keyRef = 0;
        try
        {
            keyRef = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType());
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);

            mlkemServiceNI.handleErrors(mlkemServiceNI.getSeed(keyRef, new byte[2048]));
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
    public void MLKEMServiceJNI_getSeed_OpenSSLError() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = 0;
        try
        {
            keyRef = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType());
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);

            mlkemServiceNI.handleErrors(mlkemServiceNI.getSeed(keyRef, new byte[2048]));
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
    public void MLKEMServiceJNI_getSeed_OutputInt32Overflow() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = 0;
        try
        {
            keyRef = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType());
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);

            mlkemServiceNI.handleErrors(mlkemServiceNI.getSeed(keyRef, new byte[2048]));
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
    public void MLKEMServiceJNI_decode_1publicKey_accessByteArray() throws Exception
    {
        Assumptions.assumeFalse(Loader.isFFI());
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);

            mlkemServiceNI.handleErrors(mlkemServiceNI.decode_publicKey(keyRef, OSSLKeyType.ML_KEM_512.getKsType(), new byte[1024], 0, 1024));
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
    public void MLKEMServiceJNI_decode_1publicKey_openSSLErrorDecoding() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long keyRef = 0;

        final Object[][] tuples = new Object[][]{
                {
                        OSSLKeyType.ML_KEM_512.getKsType(),
                        new byte[800]
                },
                {
                        OSSLKeyType.ML_KEM_768.getKsType(),
                        new byte[1184]
                },
                {
                        OSSLKeyType.ML_KEM_1024.getKsType(),
                        new byte[1568]
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
                mlkemServiceNI.handleErrors(mlkemServiceNI.decode_publicKey(keyRef, keyType, key, 0, key.length));
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
    public void MLKEMServiceJNI_decode_1privateKey_accessByteArray() throws Exception
    {

        Assumptions.assumeFalse(Loader.isFFI());
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);

            mlkemServiceNI.handleErrors(mlkemServiceNI.decode_privateKey(keyRef, OSSLKeyType.ML_KEM_512.getKsType(), new byte[1024], 0, 1024));
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


    //
    // Encap and decap testing is done in SpecOpsTest
    //


}
