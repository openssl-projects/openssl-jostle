package org.openssl.jostle.test.crypto;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.jcajce.provider.mldsa.MLDSAServiceNI;
import org.openssl.jostle.jcajce.provider.mldsa.MLDSASignatureSpi;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.util.ops.OperationsTestNI;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;

/**
 * Test paths where that we cannot test using simple arguments
 */
public class MLDSAInternalLayerTest
{
    static
    {
        CryptoServicesRegistrar.isNativeAvailable(); // Trigger Loading
    }

    MLDSAServiceNI mldsaServiceNI = TestNISelector.getMLDSANI();
    SpecNI specNI = TestNISelector.getSpecNI();
    OperationsTestNI operationsTestNI = TestNISelector.getOperationsTestNI();

    private static final SymbolLookup lookup = SymbolLookup.loaderLookup();
    private static final Linker linker = Linker.nativeLinker();





    @Test
    public void MLDSAServiceJNI_mldsa_update_intOverflow_extMu() throws Throwable
    {

        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.initSign(mldsaRef, keyRef, new byte[0], 0, MLDSASignatureSpi.MuHandling.EXTERNAL_MU.ordinal()));

            MemorySegment ms = lookup.find("mldsa_update").orElseThrow();
            MethodHandle mh = linker.downcallHandle(ms, FunctionDescriptor.of(
                    ValueLayout.JAVA_INT,
                    ValueLayout.ADDRESS,
                    ValueLayout.ADDRESS,
                    ValueLayout.JAVA_LONG
            ),Linker.Option.critical(true));

            byte[] input = new byte[0];
            MemorySegment inputAddress = MemorySegment.ofArray(input);
            int code = (int) mh.invoke(MemorySegment.ofAddress(mldsaRef), inputAddress, 1L + (long) Integer.MAX_VALUE);
            mldsaServiceNI.handleErrors(code);
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input too long int32", e.getMessage());
        } finally
        {
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test
    public void MLDSAServiceJNI_mldsa_sign_invalidMuType() throws Throwable
    {


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

            byte[] sig = new byte[(int)len];

            MemorySegment ctx = MemorySegment.ofAddress(mldsaRef).reinterpret(376);

            ctx.set(ValueLayout.JAVA_BYTE, 364, (byte) 4);


            mldsaServiceNI.handleErrors(mldsaServiceNI.sign(mldsaRef, sig, 0));

            Assertions.fail();
        } catch (IllegalStateException e)
        {
            Assertions.assertEquals("unexpected state", e.getMessage());
        } finally
        {
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void MLDSAServiceJNI_mldsa_sign_invalidHashType() throws Throwable
    {

        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.initVerify(mldsaRef, keyRef, new byte[0], 0, MLDSASignatureSpi.MuHandling.INTERNAL.ordinal()));

            MemorySegment ctx = MemorySegment.ofAddress(mldsaRef).reinterpret(376);

            ctx.set(ValueLayout.JAVA_BYTE, 28, (byte) 0x7f);

            mldsaServiceNI.handleErrors(mldsaServiceNI.verify(mldsaRef, new byte[1024], 1024));

            Assertions.fail();
        } catch (IllegalStateException e)
        {
            Assertions.assertEquals("unexpected state", e.getMessage());
        } finally
        {
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void MLDSAServiceJNI_mldsa_verify_invalidHashType() throws Throwable
    {

        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.initVerify(mldsaRef, keyRef, new byte[0], 0, MLDSASignatureSpi.MuHandling.INTERNAL.ordinal()));

            MemorySegment ctx = MemorySegment.ofAddress(mldsaRef).reinterpret(376);

            ctx.set(ValueLayout.JAVA_BYTE, 28, (byte) 0x7f);

            mldsaServiceNI.handleErrors(mldsaServiceNI.verify(mldsaRef, new byte[1024], 1024));

            Assertions.fail();
        } catch (IllegalStateException e)
        {
            Assertions.assertEquals("unexpected state", e.getMessage());
        } finally
        {
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }

}
