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

package org.openssl.jostle.test.spec;

import org.junit.jupiter.api.*;
import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.AccessException;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.mlkem.MLKEMServiceNI;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.test.crypto.TestNISelector;
import org.openssl.jostle.util.ops.OperationsTestNI;

import java.security.Security;

public class SpecOpsTest
{


    MLKEMServiceNI mlkemServiceNI = TestNISelector.getMLKEMNI();
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
    public void encap_inputArrayAccess() throws Exception
    {
        Assumptions.assumeFalse(Loader.isFFI()); // JNI
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long keyRef = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);

        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            specNI.encap(keyRef, null, new byte[32], 0, 32, new byte[1024], 0, 1024, TestUtil.RNDSrc);
            Assertions.fail();
        } catch (AccessException arex)
        {
            Assertions.assertEquals("unable to access input array", arex.getMessage());
        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void encap_outputArrayAccess() throws Exception
    {
        Assumptions.assumeFalse(Loader.isFFI()); // JNI only
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_2);
            specNI.encap(keyRef, null, new byte[32], 0, 32, new byte[1024], 0, 1024, TestUtil.RNDSrc);
            Assertions.fail();
        } catch (AccessException arex)
        {
            Assertions.assertEquals("unable to access output array", arex.getMessage());
        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void encap_opsString() throws Exception
    {
        Assumptions.assumeFalse(Loader.isFFI()); // JNI issue only
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_3);
            specNI.encap(keyRef, "cats", new byte[32], 0, 32, new byte[1024], 0, 1024, TestUtil.RNDSrc);
            Assertions.fail();
        } catch (AccessException arex)
        {
            Assertions.assertEquals("unable to access operation string", arex.getMessage());
        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }


    @Test
    public void encap_pkey_ctx_create() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 1101, specNI.ni_encap(keyRef, null, new byte[32], 0, 32, new byte[1024], 0, 1024, TestUtil.RNDSrc));
        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void encap_EVP_PKEY_encapsulate_init() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 1102, specNI.ni_encap(keyRef, null, new byte[32], 0, 32, new byte[1024], 0, 1024, TestUtil.RNDSrc));
        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void encap_EVP_PKEY_CTX_set_kem_op() throws Exception
    {
        // If this get renamed there is a comment mentioning it in SpecLimitTest
        // You should go update the name there.

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);
            Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 1103, specNI.ni_encap(keyRef, "cats", new byte[32], 0, 32, new byte[1024], 0, 1024, TestUtil.RNDSrc));
        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void encap_EVP_PKEY_encapsulate() throws Exception // Call that gets length
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_4);
            Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 1104, specNI.ni_encap(keyRef, null, new byte[32], 0, 32, new byte[1024], 0, 1024, TestUtil.RNDSrc));
        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }


    @Test
    public void encap_minLenOverflowInt32() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);
            Assertions.assertEquals(ErrorCode.JO_OUTPUT_SIZE_INT_OVERFLOW.getCode(), specNI.ni_encap(keyRef, null, new byte[32], 0, 32, new byte[1024], 0, 1024, TestUtil.RNDSrc));
        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }
    
    @Test
    public void encap_EVP_PKEY_encapsulate_1() throws Exception // Call that does work
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_5);
            Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 1105, specNI.ni_encap(keyRef, null, new byte[32], 0, 32, new byte[1024], 0, 1024, TestUtil.RNDSrc));
        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }

    // Decap



    @Test
    public void decap_inputArrayAccess() throws Exception
    {
        Assumptions.assumeFalse(Loader.isFFI());
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            specNI.decap(keyRef, null, new byte[32], 0, 32, new byte[1024], 0, 1024);
            Assertions.fail();
        } catch (AccessException arex)
        {
            Assertions.assertEquals("unable to access input array", arex.getMessage());
        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void decap_outputArrayAccess() throws Exception
    {
        Assumptions.assumeFalse(Loader.isFFI());
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_2);
            specNI.decap(keyRef, null, new byte[32], 0, 32, new byte[1024], 0, 1024);
            Assertions.fail();
        } catch (AccessException arex)
        {
            Assertions.assertEquals("unable to access output array", arex.getMessage());
        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void decap_opsString() throws Exception
    {
        Assumptions.assumeFalse(Loader.isFFI()); // JNI issue only
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_3);
            specNI.decap(keyRef, "cats", new byte[32], 0, 32, new byte[1024], 0, 1024);
            Assertions.fail();
        } catch (AccessException arex)
        {
            Assertions.assertEquals("unable to access operation string", arex.getMessage());
        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }


    @Test
    public void decap_pkey_ctx_create() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 1201, specNI.ni_decap(keyRef, null, new byte[32], 0, 32, new byte[1024], 0, 1024));
        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void decap_EVP_PKEY_decapsulate_init() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 1202, specNI.ni_decap(keyRef, null, new byte[32], 0, 32, new byte[1024], 0, 1024));
        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void decap_EVP_PKEY_CTX_set_kem_op() throws Exception
    {
        // If this get renamed there is a comment mentioning it in SpecLimitTest
        // You should go update the name there.

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);
            Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 1203, specNI.ni_decap(keyRef, "cats", new byte[32], 0, 32, new byte[1024], 0, 1024));
        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void decap_EVP_PKEY_decapsulate() throws Exception // Call that gets length
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_4);
            Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 1204, specNI.ni_decap(keyRef, null, new byte[32], 0, 32, new byte[1024], 0, 1024));
        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }


    @Test
    public void decap_minLenOverflowInt32() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);
            Assertions.assertEquals(ErrorCode.JO_OUTPUT_SIZE_INT_OVERFLOW.getCode(), specNI.ni_decap(keyRef, null, new byte[32], 0, 32, new byte[1024], 0, 1024));
        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }



    @Test
    public void decap_EVP_PKEY_decapsulate_1() throws Exception // Call that does work
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_5);
            Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 1205, specNI.ni_decap(keyRef, null, new byte[32], 0, 32, new byte[1024], 0, 1024));
        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }
    
    
    

}
