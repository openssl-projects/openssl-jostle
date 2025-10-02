package org.openssl.jostle.test.slhdsa;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.*;
import org.openssl.jostle.jcajce.provider.slhdsa.JOSLHDSAPrivateKey;
import org.openssl.jostle.jcajce.provider.slhdsa.JOSLHDSAPublicKey;
import org.openssl.jostle.jcajce.provider.slhdsa.SLHDSASignatureSpi;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.SLHDSAParameterSpec;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.test.crypto.TestNISelector;
import org.openssl.jostle.util.ops.OperationsTestNI;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

public class SLHDSAOpsTest
{
    static
    {
        CryptoServicesRegistrar.isNativeAvailable(); // Trigger Loading
    }

    SLHDSAServiceNI slhDSAServiceNI = TestNISelector.getSLHDSANI();
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
    public void testSLHDSAGenerateKeyPair_openSSLError() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = 0;
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            slhDSAServiceNI.handleErrors(slhDSAServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType()));

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
            slhDSAServiceNI.handleErrors(
                    slhDSAServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.ordinal(), new byte[32], 32)
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
            keyRef = slhDSAServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType());
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);

            slhDSAServiceNI.handleErrors(slhDSAServiceNI.getPrivateKey(keyRef, new byte[4096]));
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
            keyRef = slhDSAServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType());
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);

            slhDSAServiceNI.handleErrors(slhDSAServiceNI.getPrivateKey(keyRef, new byte[4096]));
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
            keyRef = slhDSAServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType());
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);

            long code = slhDSAServiceNI.getPrivateKey(keyRef, new byte[4096]);
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
            keyRef = slhDSAServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType());
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);

            slhDSAServiceNI.handleErrors(slhDSAServiceNI.getPrivateKey(keyRef, new byte[4096]));
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

    //--

    @Test()
    public void SLHDSAServiceJNI_getPublicKey_accessByteArray() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());

        long keyRef = 0;
        try
        {
            keyRef = slhDSAServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType());
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);

            slhDSAServiceNI.handleErrors(slhDSAServiceNI.getPublicKey(keyRef, new byte[2048]));
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
            keyRef = slhDSAServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType());
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);

            slhDSAServiceNI.handleErrors(slhDSAServiceNI.getPublicKey(keyRef, new byte[2048]));
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
            keyRef = slhDSAServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType());
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);

            slhDSAServiceNI.handleErrors(slhDSAServiceNI.getPublicKey(keyRef, new byte[2048]));
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

            slhDSAServiceNI.handleErrors(slhDSAServiceNI.decode_publicKey(keyRef, OSSLKeyType.SLH_DSA_SHA2_128f.getKsType(), new byte[1024], 0, 1024));
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
        Security.addProvider(new JostleProvider());

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long keyRef = 0;

        List<Object[]> tuples = new ArrayList<Object[]>();


        for (SLHDSAParameterSpec parameterSpec : SLHDSAParameterSpec.getParameterSpecs())
        {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("SLHDSA", JostleProvider.PROVIDER_NAME);
            keyPairGenerator.initialize(parameterSpec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            tuples.add(new Object[]{parameterSpec.getKeyType().getKsType(), ((JOSLHDSAPublicKey) keyPair.getPublic()).getDirectEncoding()});

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
                slhDSAServiceNI.handleErrors(slhDSAServiceNI.decode_publicKey(keyRef, keyType, key, 0, key.length));
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

            slhDSAServiceNI.handleErrors(slhDSAServiceNI.decode_privateKey(keyRef, OSSLKeyType.SLH_DSA_SHA2_128f.getKsType(), new byte[1024], 0, 1024));
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
        Security.addProvider(new JostleProvider());

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long keyRef = 0;

        List<Object[]> tuples = new ArrayList<Object[]>();


        for (SLHDSAParameterSpec parameterSpec : SLHDSAParameterSpec.getParameterSpecs())
        {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("SLHDSA", JostleProvider.PROVIDER_NAME);
            keyPairGenerator.initialize(parameterSpec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            tuples.add(new Object[]{parameterSpec.getKeyType().getKsType(), ((JOSLHDSAPrivateKey) keyPair.getPrivate()).getDirectEncoding()});

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
                slhDSAServiceNI.handleErrors(slhDSAServiceNI.decode_privateKey(keyRef, keyType, key, 0, key.length));
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
        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = TestNISelector.getSLHDSANI().generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType());

            Assertions.assertTrue(keyRef > 0);
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);

            slhDSAServiceNI.handleErrors(slhDSAServiceNI.initSign(mldsaRef, keyRef, new byte[1024], 0, 0, 0));
            Assertions.fail();
        } catch (AccessException e)
        {
            Assertions.assertEquals("unable to access context array", e.getMessage());

        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
            slhDSAServiceNI.disposeSigner(mldsaRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI__initSign_createPKEYCTX() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = TestNISelector.getSLHDSANI().generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType());

            Assertions.assertTrue(keyRef > 0);


            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            long code = slhDSAServiceNI.initSign(mldsaRef, keyRef, new byte[1024], 0, 0, 0);
            Assertions.assertEquals(-1002, code); // OpenSSL error with offset
        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
            slhDSAServiceNI.disposeSigner(mldsaRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI__initSign_EVP_PKEY_sign_message_init() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = TestNISelector.getSLHDSANI().generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType());

            Assertions.assertTrue(keyRef > 0);


            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            long code = slhDSAServiceNI.initSign(mldsaRef, keyRef, new byte[1024], 0, 0, 0);
            Assertions.assertEquals(-1003, code); // OpenSSL error with offset
        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
            slhDSAServiceNI.disposeSigner(mldsaRef);
        }
    }


    @Test()
    public void SLHDSAServiceJNI__initVerify_accessContextArray() throws Exception
    {

        Assumptions.assumeFalse(Loader.isFFI());
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = TestNISelector.getSLHDSANI().generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType());

            Assertions.assertTrue(keyRef > 0);
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);

            slhDSAServiceNI.handleErrors(slhDSAServiceNI.initVerify(mldsaRef, keyRef, new byte[1024], 0, 1024, 0));
            Assertions.fail();
        } catch (AccessException e)
        {
            Assertions.assertEquals("unable to access context array", e.getMessage());

        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
            slhDSAServiceNI.disposeSigner(mldsaRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI__initVerify_createPKEYCTX() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = TestNISelector.getSLHDSANI().generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType());

            Assertions.assertTrue(keyRef > 0);


            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            long code = slhDSAServiceNI.initVerify(mldsaRef, keyRef, new byte[1024], 0, 0, 0);
            Assertions.assertEquals(-1005, code); // OpenSSL error with offset
        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
            slhDSAServiceNI.disposeSigner(mldsaRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI__initVerify_EVP_PKEY_sign_message_init() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = TestNISelector.getSLHDSANI().generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType());

            Assertions.assertTrue(keyRef > 0);


            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            long code = slhDSAServiceNI.initVerify(mldsaRef, keyRef, new byte[1024], 0, 0, 0);
            Assertions.assertEquals(-1006, code); // OpenSSL error with offset
        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
            slhDSAServiceNI.disposeSigner(mldsaRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_mldsa_update_accessInputArray() throws Exception
    {

        Assumptions.assumeFalse(Loader.isFFI());
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = slhDSAServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType());

            Assertions.assertTrue(keyRef > 0);
            slhDSAServiceNI.handleErrors(slhDSAServiceNI.initSign(mldsaRef, keyRef, new byte[0], 0, 0, 0));

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            slhDSAServiceNI.handleErrors(slhDSAServiceNI.update(mldsaRef, new byte[10], 0, 10));

            Assertions.fail();
        } catch (AccessException e)
        {
            Assertions.assertEquals("unable to access input array", e.getMessage());
        } finally
        {
            operationsTestNI.resetFlags();
            slhDSAServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void SLHDSAServiceJNI_mldsa_update_osslError_extMu() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = slhDSAServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType());

            Assertions.assertTrue(keyRef > 0);
            slhDSAServiceNI.handleErrors(slhDSAServiceNI.initSign(mldsaRef, keyRef, new byte[0], 0, SLHDSASignatureSpi.MessageEncoding.PURE.ordinal(), 0));

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            slhDSAServiceNI.handleErrors(slhDSAServiceNI.update(mldsaRef, new byte[10], 0, 10));

            Assertions.fail();
        } catch (OpenSSLException e)
        {
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        } finally
        {
            operationsTestNI.resetFlags();
            slhDSAServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void SLHDSAServiceJNI_mldsa_sign_outputRange() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());

        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = slhDSAServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType());

            Assertions.assertTrue(keyRef > 0);
            slhDSAServiceNI.handleErrors(slhDSAServiceNI.initSign(mldsaRef, keyRef, new byte[0], 0, 0, 0));

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            slhDSAServiceNI.handleErrors(slhDSAServiceNI.sign(mldsaRef, new byte[1], 0));

            Assertions.fail();
        } catch (AccessException e)
        {
            Assertions.assertEquals("unable to access output array", e.getMessage());
        } finally
        {
            operationsTestNI.resetFlags();
            slhDSAServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void SLHDSAServiceJNI_mldsa_sign_osslErrorGettingLen() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = slhDSAServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType());

            Assertions.assertTrue(keyRef > 0);
            slhDSAServiceNI.handleErrors(slhDSAServiceNI.initSign(mldsaRef, keyRef, new byte[0], 0, SLHDSASignatureSpi.MessageEncoding.PURE.ordinal(), 0));

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            long len = slhDSAServiceNI.handleErrors(slhDSAServiceNI.sign(mldsaRef, null, 0));

            Assertions.fail();
        } catch (OpenSSLException e)
        {
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        } finally
        {
            slhDSAServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_mldsa_sign_osslErrorCalculatingSig() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = slhDSAServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType());

            Assertions.assertTrue(keyRef > 0);
            slhDSAServiceNI.handleErrors(slhDSAServiceNI.initSign(mldsaRef, keyRef, new byte[0], 0, SLHDSASignatureSpi.MessageEncoding.PURE.ordinal(), 0));

            long len = slhDSAServiceNI.handleErrors(slhDSAServiceNI.sign(mldsaRef, null, 0));

            byte[] sig = new byte[(int) len];

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            slhDSAServiceNI.handleErrors(slhDSAServiceNI.sign(mldsaRef, sig, 0));


            Assertions.fail();
        } catch (OpenSSLException e)
        {
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        } finally
        {
            slhDSAServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_mldsa_sign_unexpectedSigLenChange() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = slhDSAServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType());

            Assertions.assertTrue(keyRef > 0);
            slhDSAServiceNI.handleErrors(slhDSAServiceNI.initSign(mldsaRef, keyRef, new byte[0], 0, SLHDSASignatureSpi.MessageEncoding.PURE.ordinal(), 0));

            long len = slhDSAServiceNI.handleErrors(slhDSAServiceNI.sign(mldsaRef, null, 0));

            byte[] sig = new byte[(int) len];

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_LEN_CHANGE_1);
            slhDSAServiceNI.handleErrors(slhDSAServiceNI.sign(mldsaRef, sig, 0));

            Assertions.fail();
        } catch (IllegalStateException e)
        {
            Assertions.assertEquals("unexpected sig length change", e.getMessage());
        } finally
        {
            slhDSAServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void SLHDSAServiceJNI_mldsa_verify_accessSigBytes() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());

        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = slhDSAServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType());

            Assertions.assertTrue(keyRef > 0);
            slhDSAServiceNI.handleErrors(slhDSAServiceNI.initVerify(mldsaRef, keyRef, new byte[0], 0, SLHDSASignatureSpi.MessageEncoding.PURE.ordinal(), 0));

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            slhDSAServiceNI.handleErrors(slhDSAServiceNI.verify(mldsaRef, new byte[1], 1));

            Assertions.fail();
        } catch (AccessException e)
        {
            Assertions.assertEquals("unable to access signature array", e.getMessage());
        } finally
        {
            slhDSAServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void SLHDSAServiceJNI_mldsa_verify_osslError() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = slhDSAServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType());

            Assertions.assertTrue(keyRef > 0);
            slhDSAServiceNI.handleErrors(slhDSAServiceNI.initVerify(mldsaRef, keyRef, new byte[0], 0, SLHDSASignatureSpi.MessageEncoding.PURE.ordinal(), 0));

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            slhDSAServiceNI.handleErrors(slhDSAServiceNI.verify(mldsaRef, new byte[1], 1));

            Assertions.fail();
        } catch (OpenSSLException e)
        {
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        } finally
        {
            slhDSAServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }
}
