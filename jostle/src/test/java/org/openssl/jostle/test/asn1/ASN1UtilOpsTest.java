package org.openssl.jostle.test.asn1;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.AccessException;
import org.openssl.jostle.jcajce.provider.OverflowException;
import org.openssl.jostle.jcajce.provider.mldsa.MLDSAServiceNI;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.test.crypto.TestNISelector;
import org.openssl.jostle.util.asn1.Asn1Ni;
import org.openssl.jostle.util.ops.OperationsTestNI;

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


    @BeforeEach
    public void beforeEach()
    {
        if (operationsTestNI.opsTestAvailable())
        {
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

            asn1NI.handleErrors(asn1NI.encodePrivateKey(asn1Ref, keyRef));
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
