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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.AccessException;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.provider.mlkem.MLKEMServiceNI;
import org.openssl.jostle.jcajce.provider.rsa.RSAServiceNI;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.rand.RandSource;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.util.ops.OperationsTestNI;

/**
 * The fault sites of the FIPS library's spec bridge and encap/decap, driven with an RSA key and RSASVE, which both
 * supported modules serve, so no cell depends on the module's ML-KEM.
 */
public class FIPSSpecOpsTest
{
    private static final RandSource RND = TestUtil.RNDSrc;

    private static final String KEM_OP = "RSASVE";

    /** RSASVE's encapsulation and secret are each the modulus length. */
    private static final int NLEN = 256;

    private final SpecNI specNI = FIPSNISelector.SpecNI;
    private final RSAServiceNI rsaServiceNI = FIPSNISelector.RSAServiceNI;
    private final MLKEMServiceNI mlkemServiceNI = FIPSNISelector.MLKEMServiceNI;
    private final OperationsTestNI operationsTestNI = FIPSNISelector.OperationsTestNI;

    @BeforeAll
    public static void beforeAll()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        TestUtil.addFipsProvider();
    }

    @BeforeEach
    public void beforeEach()
    {
        if (operationsTestNI.opsTestAvailable())
        {
            operationsTestNI.resetFlags();
        }
    }

    /** An RSA-2048 keypair handle in the FIPS library. Caller disposes. */
    private long rsaKey()
    {
        long ref = rsaServiceNI.generateKeyPair(NLEN * 8, new byte[]{1, 0, 1}, RND);
        Assertions.assertTrue(ref > 0);
        return ref;
    }

    @Test
    public void encap_inputArrayAccess() throws Exception
    {
        Assumptions.assumeFalse(Loader.isFFM()); // JNI
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long keyRef = rsaKey();

        try
        {
            // Exercises interface/fips/jni/spec_ni_jni.c:168
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            specNI.encap(keyRef, KEM_OP, new byte[NLEN], 0, NLEN, new byte[1024], 0, 1024, RND);
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
        Assumptions.assumeFalse(Loader.isFFM()); // JNI only
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = rsaKey();
        try
        {
            // Exercises interface/fips/jni/spec_ni_jni.c:194
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_2);
            specNI.encap(keyRef, KEM_OP, new byte[NLEN], 0, NLEN, new byte[1024], 0, 1024, RND);
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
        Assumptions.assumeFalse(Loader.isFFM()); // JNI issue only
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = rsaKey();
        try
        {
            // Exercises interface/fips/jni/spec_ni_jni.c:222
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_3);
            specNI.encap(keyRef, "cats", new byte[NLEN], 0, NLEN, new byte[1024], 0, 1024, RND);
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

        long keyRef = rsaKey();
        try
        {
            // Exercises interface/fips/util/encapdecap.c:39
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 1101,
                    specNI.ni_encap(keyRef, KEM_OP, new byte[NLEN], 0, NLEN, new byte[1024], 0, 1024, RND));
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

        long keyRef = rsaKey();
        try
        {
            // Exercises interface/fips/util/encapdecap.c:44
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 1102,
                    specNI.ni_encap(keyRef, KEM_OP, new byte[NLEN], 0, NLEN, new byte[1024], 0, 1024, RND));
        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void encap_EVP_PKEY_CTX_set_kem_op() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = rsaKey();
        try
        {
            // Exercises interface/fips/util/encapdecap.c:50
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);
            Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 1103,
                    specNI.ni_encap(keyRef, "cats", new byte[NLEN], 0, NLEN, new byte[1024], 0, 1024, RND));
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

        long keyRef = rsaKey();
        try
        {
            // Exercises interface/fips/util/encapdecap.c:60
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_4);
            Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 1104,
                    specNI.ni_encap(keyRef, KEM_OP, new byte[NLEN], 0, NLEN, new byte[1024], 0, 1024, RND));
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

        long keyRef = rsaKey();
        try
        {
            // Exercises interface/fips/util/encapdecap.c:66
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);
            Assertions.assertEquals(ErrorCode.JO_OUTPUT_SIZE_INT_OVERFLOW.getCode(),
                    specNI.ni_encap(keyRef, KEM_OP, new byte[NLEN], 0, NLEN, new byte[1024], 0, 1024, RND));
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

        long keyRef = rsaKey();
        try
        {
            // Exercises interface/fips/util/encapdecap.c:88
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_5);
            Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 1105,
                    specNI.ni_encap(keyRef, KEM_OP, new byte[NLEN], 0, NLEN, new byte[1024], 0, 1024, RND));
        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }

    // Encap secret length

    @Test
    public void encapSecretLength_oppAccess() throws Exception
    {
        Assumptions.assumeFalse(Loader.isFFM()); // JNI
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = rsaKey();
        try
        {
            // Exercises interface/fips/jni/spec_ni_jni.c:379
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_3);
            Assertions.assertEquals(ErrorCode.JO_FAILED_ACCESS_ENCAP_OPP.getCode(),
                    specNI.ni_encapSecretLength(keyRef, "cats", RND));
        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void encapSecretLength_pkey_ctx_create() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = rsaKey();
        try
        {
            // Exercises interface/fips/util/encapdecap.c:200
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 1301,
                    specNI.ni_encapSecretLength(keyRef, KEM_OP, RND));
        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void encapSecretLength_EVP_PKEY_encapsulate_init() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = rsaKey();
        try
        {
            // Exercises interface/fips/util/encapdecap.c:205
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 1302,
                    specNI.ni_encapSecretLength(keyRef, KEM_OP, RND));
        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void encapSecretLength_EVP_PKEY_CTX_set_kem_op() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = rsaKey();
        try
        {
            // Exercises interface/fips/util/encapdecap.c:211
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);
            Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 1303,
                    specNI.ni_encapSecretLength(keyRef, "cats", RND));
        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void encapSecretLength_EVP_PKEY_encapsulate() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = rsaKey();
        try
        {
            // Exercises interface/fips/util/encapdecap.c:222
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_4);
            Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 1304,
                    specNI.ni_encapSecretLength(keyRef, KEM_OP, RND));
        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void encapSecretLength_secretLenOverflowInt32() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = rsaKey();
        try
        {
            // Exercises interface/fips/util/encapdecap.c:227
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);
            Assertions.assertEquals(ErrorCode.JO_OUTPUT_SIZE_INT_OVERFLOW.getCode(),
                    specNI.ni_encapSecretLength(keyRef, KEM_OP, RND));
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
        Assumptions.assumeFalse(Loader.isFFM());
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = rsaKey();
        try
        {
            // Exercises interface/fips/jni/spec_ni_jni.c:279
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            specNI.decap(keyRef, KEM_OP, new byte[NLEN], 0, NLEN, new byte[1024], 0, 1024, RND);
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
        Assumptions.assumeFalse(Loader.isFFM());
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = rsaKey();
        try
        {
            // Exercises interface/fips/jni/spec_ni_jni.c:305
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_2);
            specNI.decap(keyRef, KEM_OP, new byte[NLEN], 0, NLEN, new byte[1024], 0, 1024, RND);
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
        Assumptions.assumeFalse(Loader.isFFM()); // JNI issue only
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = rsaKey();
        try
        {
            // Exercises interface/fips/jni/spec_ni_jni.c:333
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_3);
            specNI.decap(keyRef, "cats", new byte[NLEN], 0, NLEN, new byte[1024], 0, 1024, RND);
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

        long keyRef = rsaKey();
        try
        {
            // Exercises interface/fips/util/encapdecap.c:126
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 1201,
                    specNI.ni_decap(keyRef, KEM_OP, new byte[NLEN], 0, NLEN, new byte[1024], 0, 1024, RND));
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

        long keyRef = rsaKey();
        try
        {
            // Exercises interface/fips/util/encapdecap.c:131
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 1202,
                    specNI.ni_decap(keyRef, KEM_OP, new byte[NLEN], 0, NLEN, new byte[1024], 0, 1024, RND));
        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void decap_EVP_PKEY_CTX_set_kem_op() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = rsaKey();
        try
        {
            // Exercises interface/fips/util/encapdecap.c:137
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);
            Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 1203,
                    specNI.ni_decap(keyRef, "cats", new byte[NLEN], 0, NLEN, new byte[1024], 0, 1024, RND));
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

        long keyRef = rsaKey();
        try
        {
            // Exercises interface/fips/util/encapdecap.c:144
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_4);
            Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 1204,
                    specNI.ni_decap(keyRef, KEM_OP, new byte[NLEN], 0, NLEN, new byte[1024], 0, 1024, RND));
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

        long keyRef = rsaKey();
        try
        {
            // Exercises interface/fips/util/encapdecap.c:150
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);
            Assertions.assertEquals(ErrorCode.JO_OUTPUT_SIZE_INT_OVERFLOW.getCode(),
                    specNI.ni_decap(keyRef, KEM_OP, new byte[NLEN], 0, NLEN, new byte[1024], 0, 1024, RND));
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

        long keyRef = rsaKey();
        try
        {
            // Exercises interface/fips/util/encapdecap.c:165
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_5);
            Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 1205,
                    specNI.ni_decap(keyRef, KEM_OP, new byte[NLEN], 0, NLEN, new byte[1024], 0, 1024, RND));
        } finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }

    /**
     * ML-KEM reaches the same sites; served only where the module implements it, so the RSA cells above carry
     * the coverage on every module.
     */
    @Test
    public void encap_EVP_PKEY_encapsulate_1_mlKem() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeTrue(FIPSTestUtil.moduleServesKeyMgmt("ML-KEM-768"),
                "the loaded FIPS module implements no ML-KEM (3.1.2)");

        long keyRef = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), RND);
        try
        {
            // Exercises interface/fips/util/encapdecap.c:88
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_5);
            Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 1105,
                    specNI.ni_encap(keyRef, null, new byte[32], 0, 32, new byte[1024], 0, 1024, RND));
        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void decap_EVP_PKEY_decapsulate_1_mlKem() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeTrue(FIPSTestUtil.moduleServesKeyMgmt("ML-KEM-768"),
                "the loaded FIPS module implements no ML-KEM (3.1.2)");

        long keyRef = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), RND);
        try
        {
            // Exercises interface/fips/util/encapdecap.c:165
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_5);
            Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode() - 1205,
                    specNI.ni_decap(keyRef, null, new byte[768], 0, 768, new byte[32], 0, 32, RND));
        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }

    /**
     * The shared secret crosses JNI through the cleansing contexts: one load for the encap's secret window and one
     * for the decap's output. FFM copies into arena segments that it fills with zero before the arena closes, which
     * the ledger cannot see.
     */
    @Test
    public void sharedSecretCopiesAreCleansed() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long keyRef = rsaKey();
        try
        {
            byte[] secret = new byte[NLEN];
            byte[] enc = new byte[NLEN];
            byte[] back = new byte[NLEN];
            operationsTestNI.ledgerReset();
            Assertions.assertEquals(NLEN, specNI.encap(keyRef, KEM_OP, secret, 0, NLEN, enc, 0, NLEN, RND));
            Assertions.assertEquals(NLEN, specNI.decap(keyRef, KEM_OP, enc, 0, NLEN, back, 0, NLEN, RND));
            Assertions.assertArrayEquals(secret, back);

            int expected = Loader.isFFM() ? 0 : 2;
            for (OperationsTestNI.LedgerType t : new OperationsTestNI.LedgerType[]{
                    OperationsTestNI.LedgerType.SECRET_BYTEARRAY, OperationsTestNI.LedgerType.SECRET_CLEANSE})
            {
                Assertions.assertEquals(expected, operationsTestNI.ledgerCreated(t), t + " created");
                Assertions.assertEquals(expected, operationsTestNI.ledgerDestroyed(t), t + " destroyed");
            }
        }
        finally
        {
            specNI.dispose(keyRef);
        }
    }
}
