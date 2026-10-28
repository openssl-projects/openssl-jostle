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

package org.openssl.jostle.test.fips;

import org.junit.jupiter.api.*;
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.AccessException;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.OverflowException;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.provider.mlkem.MLKEMServiceNI;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.util.ops.OperationsTestNI;

import java.security.KeyPairGenerator;
import java.security.ProviderException;

/**
 * FIPS mirror of {@code MLKEMOpsTest} driving {@link FIPSNISelector#MLKEMServiceNI}: the fault sites live in
 * interface/fips/util/mlkem.c and interface/fips/jni/mlkem_ni_jni.c, which differ from the base only by the lib ctx
 * accessor, so the sites, offsets and codes match the base. Needs an OPS build of the FIPS library and a module that
 * serves ML-KEM; on 3.1.2 only {@link #mlKemIsRegisteredIffTheModuleServesIt} runs.
 */
public class FIPSMLKEMOpsTest
{


    MLKEMServiceNI mlkemServiceNI = FIPSNISelector.MLKEMServiceNI;
    SpecNI specNI = FIPSNISelector.SpecNI;
    OperationsTestNI operationsTestNI = FIPSNISelector.OperationsTestNI;

    private static final long JO_OPENSSL_ERROR = ErrorCode.JO_OPENSSL_ERROR.getCode();

    private void assertGenerateKeyPairReturns(OperationsTestNI.OpsTestFlag flag, long expectedCode) throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        assumeMlKem();
        long keyRef = 0;
        try
        {
            int[] err = new int[1];
            operationsTestNI.setFlag(flag);
            keyRef = mlkemServiceNI.ni_generateKeyPair(
                    OSSLKeyType.ML_KEM_512.getKsType(), err, TestUtil.RNDSrc);
            Assertions.assertEquals(0L, keyRef);
            Assertions.assertEquals(expectedCode, err[0]);
        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }


    @BeforeAll
    public static void beforeAll()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        TestUtil.addFipsProvider();
    }

    private static void assumeMlKem()
    {
        Assumptions.assumeTrue(FIPSTestUtil.moduleServesKeyMgmt("ML-KEM-768"),
                "the loaded FIPS module implements no ML-KEM (3.1.2)");
    }

    /** Where the module has no ML-KEM, JSLFIPS registers none: the one cell that runs there. */
    @Test
    public void mlKemIsRegisteredIffTheModuleServesIt()
    {
        boolean registered = FIPSTestUtil.assumeFipsProvider().getService("KeyPairGenerator", "ML-KEM-768") != null;
        Assertions.assertEquals(FIPSTestUtil.moduleServesKeyMgmt("ML-KEM-768"), registered);
        Assertions.assertEquals(!FipsModuleProfile.get().isVersion312(), registered);
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
    public void testMLKEMGenerateKeyPair_openSSLError() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        assumeMlKem();

        long keyRef = 0;
        try
        {
            // Exercises interface/fips/util/mlkem.c:95
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);

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
    public void MLKEMServiceJNI_generateKeyPair_seedLenNegative() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        assumeMlKem();
        Assumptions.assumeFalse(Loader.isFFM());
        try
        {
            // Exercises interface/fips/jni/mlkem_ni_jni.c:93
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.ordinal(), new byte[64], 64, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access seed array", e.getMessage());
        }
    }


    @Test()
    public void MLKEMServiceJNI_getPublicKey_accessByteArray() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        assumeMlKem();
        Assumptions.assumeFalse(Loader.isFFM());

        long keyRef = 0;
        try
        {
            keyRef = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
            Assertions.assertTrue(keyRef > 0);

            // Exercises interface/fips/jni/mlkem_ni_jni.c:145
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);

            mlkemServiceNI.getPublicKey(keyRef, new byte[2048]);
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
    public void MLKEMServiceJNI_getPrivateKey_accessByteArray() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        assumeMlKem();
        Assumptions.assumeFalse(Loader.isFFM());

        long keyRef = 0;
        try
        {
            keyRef = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
            Assertions.assertTrue(keyRef > 0);

            // Exercises interface/fips/jni/mlkem_ni_jni.c:179
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);

            mlkemServiceNI.getPrivateKey(keyRef, new byte[4096]);
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
    public void MLKEMService_getPrivateKey_OpenSSLError_1() throws Exception
    {
        //
        // Where min_len is determined
        //

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        assumeMlKem();

        long keyRef = 0;
        try
        {
            keyRef = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
            Assertions.assertTrue(keyRef > 0);

            // Exercises interface/fips/util/mlkem.c:189
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);

            mlkemServiceNI.getPrivateKey(keyRef, new byte[4096]);
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
    public void MLKEMService_getPrivateKey_OpenSSLError_2() throws Exception
    {
        //
        // Where encoding operation occurs, uses offset to the error code during ops testing.
        //

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        assumeMlKem();

        long keyRef = 0;
        try
        {

            keyRef = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
            Assertions.assertTrue(keyRef > 0);

            // Exercises interface/fips/util/mlkem.c:210
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);

            mlkemServiceNI.getPrivateKey(keyRef, new byte[4096]);
            Assertions.fail();

        }
        catch (IllegalStateException ise)
        {
            Assertions.assertEquals("unexpected error code JO_UNKNOWN: -1004", ise.getMessage());
        }

        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void MLKEMService_getPrivateKey_OutputInt32Overflow() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        assumeMlKem();

        long keyRef = 0;
        try
        {
            keyRef = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
            Assertions.assertTrue(keyRef > 0);

            // Exercises interface/fips/util/mlkem.c:195
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);

            mlkemServiceNI.getPrivateKey(keyRef, new byte[4096]);
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
    public void MLKEMService_getPublicKey_OpenSSLError_1() throws Exception
    {
        //
        // Where min_len is determined
        //

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        assumeMlKem();

        long keyRef = 0;
        try
        {
            keyRef = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
            Assertions.assertTrue(keyRef > 0);

            // Exercises interface/fips/util/mlkem.c:138
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);

            mlkemServiceNI.getPublicKey(keyRef, new byte[2048]);
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
    public void MLKEMService_getPublicKey_OpenSSLError_2() throws Exception
    {
        //
        // Where encoding operation occurs, uses offset to the error code during ops testing.
        //

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        assumeMlKem();

        long keyRef = 0;
        try
        {
            keyRef = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
            Assertions.assertTrue(keyRef > 0);

            // Exercises interface/fips/util/mlkem.c:160
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            mlkemServiceNI.getPublicKey(keyRef, new byte[2048]);
            Assertions.fail();

        }
        catch (IllegalStateException ise)
        {
            Assertions.assertEquals("unexpected error code JO_UNKNOWN: -1002", ise.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void MLKEMService_getPublicKey_OutputInt32Overflow() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        assumeMlKem();

        long keyRef = 0;
        try
        {
            keyRef = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
            Assertions.assertTrue(keyRef > 0);

            // Exercises interface/fips/util/mlkem.c:144
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);

            mlkemServiceNI.getPublicKey(keyRef, new byte[2048]);
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
    public void MLKEMServiceJNI_getSeed_accessByteArray() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        assumeMlKem();
        Assumptions.assumeFalse(Loader.isFFM());
        long keyRef = 0;
        try
        {
            keyRef = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
            Assertions.assertTrue(keyRef > 0);

            // Exercises interface/fips/jni/mlkem_ni_jni.c:216
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);

            mlkemServiceNI.getSeed(keyRef, new byte[2048]);
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
    public void MLKEMServiceJNI_getSeed_OpenSSLError() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        assumeMlKem();

        long keyRef = 0;
        try
        {
            keyRef = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
            Assertions.assertTrue(keyRef > 0);

            // Exercises interface/fips/util/mlkem.c:272
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);

            mlkemServiceNI.getSeed(keyRef, new byte[2048]);
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
    public void MLKEMServiceJNI_getSeed_OutputInt32Overflow() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        assumeMlKem();

        long keyRef = 0;
        try
        {
            keyRef = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
            Assertions.assertTrue(keyRef > 0);

            // Exercises interface/fips/util/mlkem.c:257
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);

            mlkemServiceNI.getSeed(keyRef, new byte[2048]);
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
    public void MLKEMServiceJNI_decode_1publicKey_accessByteArray() throws Exception
    {
        Assumptions.assumeFalse(Loader.isFFM());
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        assumeMlKem();

        long keyRef = 0;
        try
        {
            keyRef = FIPSNISelector.SpecNI.allocate();
            Assertions.assertTrue(keyRef > 0);
            // Exercises interface/fips/jni/mlkem_ni_jni.c:262
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);

            mlkemServiceNI.decode_publicKey(keyRef, OSSLKeyType.ML_KEM_512.getKsType(), new byte[1024], 0, 1024,
                    TestUtil.RNDSrc);
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
    public void MLKEMServiceJNI_decode_1publicKey_openSSLErrorDecoding() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        assumeMlKem();
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
                keyRef = FIPSNISelector.SpecNI.allocate();
                Assertions.assertTrue(keyRef > 0);
                // Exercises interface/fips/util/mlkem.c:398
                operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
                mlkemServiceNI.decode_publicKey(keyRef, keyType, key, 0, key.length, TestUtil.RNDSrc);
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
    public void MLKEMServiceJNI_decode_1privateKey_accessByteArray() throws Exception
    {

        Assumptions.assumeFalse(Loader.isFFM());
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        assumeMlKem();

        long keyRef = 0;
        try
        {
            keyRef = FIPSNISelector.SpecNI.allocate();
            Assertions.assertTrue(keyRef > 0);
            // Exercises interface/fips/jni/mlkem_ni_jni.c:323
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);

            mlkemServiceNI.decode_privateKey(keyRef, OSSLKeyType.ML_KEM_512.getKsType(), new byte[1024], 0, 1024,
                    TestUtil.RNDSrc);
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
    public void MLKEMServiceJNI_decode_1privateKey_openSSLErrorDecoding() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        assumeMlKem();
        long keyRef = 0;

        // Buffer sizes are the minimum private-key length per variant
        // (mlkem_decode_private_key switch). Content is zero-filled, which
        // EVP_PKEY_new_raw_private_key_ex will reject; this still drives the
        // OPS_OPENSSL_ERROR_1 cookie line and the JO_OPENSSL_ERROR return
        // path so gcov sees the cookie line as covered.

        final Object[][] tuples = new Object[][]{
                {
                        OSSLKeyType.ML_KEM_512.getKsType(),
                        new byte[1632]
                },
                {
                        OSSLKeyType.ML_KEM_768.getKsType(),
                        new byte[2400]
                },
                {
                        OSSLKeyType.ML_KEM_1024.getKsType(),
                        new byte[3168]
                }
        };

        for (Object[] tuple : tuples)
        {

            int keyType = (Integer) tuple[0];
            byte[] key = (byte[]) tuple[1];

            try
            {
                keyRef = FIPSNISelector.SpecNI.allocate();
                Assertions.assertTrue(keyRef > 0);
                // Exercises interface/fips/util/mlkem.c:333
                operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
                mlkemServiceNI.decode_privateKey(keyRef, keyType, key, 0, key.length, TestUtil.RNDSrc);
                Assertions.fail();
            }
            catch (OpenSSLException e)
            {
                Assertions.assertNotNull(e.getMessage());
            }
            finally
            {
                operationsTestNI.resetFlags();
                specNI.dispose(keyRef);
            }
        }
    }


    @Test()
    public void MLKEM_generateKeyPair_ctxNew_fail() throws Exception
    {
        // Exercises interface/fips/util/mlkem.c:67
        assertGenerateKeyPairReturns(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3, JO_OPENSSL_ERROR - 1100);
    }

    @Test()
    public void MLKEM_generateKeyPair_keygenInit_fail() throws Exception
    {
        // Exercises interface/fips/util/mlkem.c:72
        assertGenerateKeyPairReturns(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_4, JO_OPENSSL_ERROR - 1101);
    }

    @Test()
    public void MLKEM_generateKeyPair_setParams_fail() throws Exception
    {
        // Exercises interface/fips/util/mlkem.c:77
        assertGenerateKeyPairReturns(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_5, JO_OPENSSL_ERROR - 1102);
    }

    @Test()
    public void MLKEM_generateKeyPair_keygen_fail() throws Exception
    {
        // Exercises interface/fips/util/mlkem.c:88
        assertGenerateKeyPairReturns(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_6, JO_OPENSSL_ERROR - 1103);
    }


    //
    // Encap and decap testing is done in SpecOpsTest
    //



    @Test
    public void generateKeyPair_nativeFailureIsAProviderException() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        assumeMlKem();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM", FIPSTestUtil.assumeFipsProvider());
        try
        {
            // Exercises interface/fips/util/mlkem.c:95
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            ProviderException e = Assertions.assertThrows(ProviderException.class, kpg::generateKeyPair);
            Assertions.assertEquals("unable to generate an ML-KEM key pair: OpenSSL Error: null", e.getMessage());
            Assertions.assertEquals(OpenSSLException.class, e.getCause().getClass());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }

        // Control: the same generator works once the flag is cleared.
        Assertions.assertNotNull(kpg.generateKeyPair().getPrivate());
    }
}
