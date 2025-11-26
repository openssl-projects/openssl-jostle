package org.openssl.jostle.test.asn1;

import org.junit.jupiter.api.*;
import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.interfaces.MLDSAPrivateKey;
import org.openssl.jostle.jcajce.provider.AccessException;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.OverflowException;
import org.openssl.jostle.jcajce.provider.mldsa.MLDSAServiceNI;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.test.crypto.TestNISelector;
import org.openssl.jostle.util.asn1.Asn1Ni;
import org.openssl.jostle.util.asn1.PrivateKeyOptions;
import org.openssl.jostle.util.ops.OperationsTestNI;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;

public class ASN1UtilOpsTest
{

    static
    {
        CryptoServicesRegistrar.isNativeAvailable(); // Trigger Loading
    }

    Asn1Ni asn1NI = TestNISelector.getAsn1NI();
    OperationsTestNI operationsTestNI = TestNISelector.getOperationsTestNI();
    SpecNI specNI = TestNISelector.getSpecNI();
    MLDSAServiceNI mldsaServiceNI = TestNISelector.getMLDSANI();


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
    public void opsTestDecodePublicKey_Int32Overflow() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long keyRef = 0;

        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);
            keyRef = asn1NI.fromPublicKeyInfo(new byte[10], 0, 10);
            asn1NI.handleErrors(keyRef);
            Assertions.fail();
        } catch (OverflowException e)
        {
            Assertions.assertEquals("input size int32 overflow", e.getMessage());
        } finally
        {
            if (keyRef > 0)
            {
                specNI.dispose(keyRef);
            }
            operationsTestNI.resetFlags();
        }

    }


    @Test
    public void opsTestDecodePrivateKey_Int32Overflow() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long keyRef = 0;

        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);
            keyRef = asn1NI.fromPrivateKeyInfo(new byte[10], 0, 10);
            asn1NI.handleErrors(keyRef);
            Assertions.fail();
        } catch (OverflowException e)
        {
            Assertions.assertEquals("input size int32 overflow", e.getMessage());
        } finally
        {
            if (keyRef > 0)
            {
                specNI.dispose(keyRef);
            }
            operationsTestNI.resetFlags();
        }

    }


    @Test
    public void opsTestEncodePublicKey_Int32Overflow() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long asn1Ref = 0;
        long keyRef = 0;

        try
        {
            asn1Ref = asn1NI.allocate();
            keyRef = asn1NI.allocate();

            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());
            Assertions.assertTrue(keyRef > 0);
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);
            asn1NI.handleErrors(asn1NI.encodePublicKey(asn1Ref, keyRef));
            Assertions.fail();
        } catch (OverflowException e)
        {
            Assertions.assertEquals("output size int32 overflow", e.getMessage());

        } finally
        {
            asn1NI.dispose(asn1Ref);
            specNI.dispose(keyRef);
            operationsTestNI.resetFlags();
        }

    }


    @Test
    public void opsTestEncodePrivateKey_Int32Overflow() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long asn1Ref = 0;
        long keyRef = 0;

        try
        {
            asn1Ref = asn1NI.allocate();
            keyRef = asn1NI.allocate();

            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());
            Assertions.assertTrue(keyRef > 0);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);

            asn1NI.handleErrors(asn1NI.encodePrivateKey(asn1Ref, keyRef, PrivateKeyOptions.DEFAULT.getValue()));
            Assertions.fail();

        } catch (OverflowException e)
        {
            Assertions.assertEquals("output size int32 overflow", e.getMessage());
        } finally
        {
            asn1NI.dispose(asn1Ref);
            specNI.dispose(keyRef);
            operationsTestNI.resetFlags();
        }

    }

    @Test
    public void opsTestGetData_accessByteArray() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());
        long asn1Ref = 0;

        try
        {
            asn1Ref = asn1NI.allocate();
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            asn1NI.handleErrors(asn1NI.getData(asn1Ref, new byte[1024]));
            Assertions.fail();
        } catch (AccessException e)
        {
            Assertions.assertEquals("unable to access output array", e.getMessage());
        } finally
        {
            asn1NI.dispose(asn1Ref);
            operationsTestNI.resetFlags();
        }

    }


    @Test
    public void opsTestEncodePrivateKey_accessOptionsString() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());


        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(org.openssl.jostle.jcajce.spec.MLDSAParameterSpec.ml_dsa_44);
        KeyPair keyPair = keyGen.generateKeyPair();

        MLDSAPrivateKey privateKey = (MLDSAPrivateKey) keyPair.getPrivate();


        long asn1Ref = TestNISelector.Asn1NI.allocate();

        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            long len = TestNISelector.Asn1NI.handleErrors(TestNISelector.Asn1NI.encodePrivateKey(asn1Ref, privateKey.getSpec().getReference(), PrivateKeyOptions.DEFAULT.getValue()));
            byte[] out = new byte[(int) len];
            TestNISelector.Asn1NI.handleErrors(TestNISelector.Asn1NI.getData(asn1Ref, out));
            Assertions.fail("Should have thrown exception");

        } catch (AccessException e)
        {
            Assertions.assertEquals("unable to access string with encoding option", e.getMessage());
        } finally
        {
            asn1NI.dispose(asn1Ref);
            operationsTestNI.resetFlags();
        }


    }


    @Test
    public void opsTestGetData_Int32Overflow() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long asn1Ref = 0;

        try
        {
            asn1Ref = asn1NI.allocate();

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);
            asn1NI.handleErrors(asn1NI.getData(asn1Ref, null));

            Assertions.fail();

        } catch (OverflowException ex)
        {
            Assertions.assertEquals("output size int32 overflow", ex.getMessage());
        } finally
        {
            asn1NI.dispose(asn1Ref);
            operationsTestNI.resetFlags();

        }

    }
}
