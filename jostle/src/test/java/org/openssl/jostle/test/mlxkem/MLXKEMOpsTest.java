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

package org.openssl.jostle.test.mlxkem;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.AccessException;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.OverflowException;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.mlxkem.MLXKEMServiceNI;
import org.openssl.jostle.jcajce.spec.MLXKEMParameterSpec;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.test.crypto.TestNISelector;
import org.openssl.jostle.util.ops.OperationsTestNI;

import java.security.KeyPairGenerator;
import java.security.ProviderException;
import java.security.Security;

/**
 * Fault injection at every instrumented hybrid KEM site: the keygen, the two getters' size query, length check and
 * fetch, the decode, and the JNI array loads. Needs an OPS build; on a plain build every cell skips.
 */
public class MLXKEMOpsTest
{
    private final MLXKEMServiceNI ni = TestNISelector.getMLXKEMNI();
    private final SpecNI specNI = TestNISelector.getSpecNI();
    private final OperationsTestNI operationsTestNI = TestNISelector.getOperationsTestNI();

    private static final long JO_OPENSSL_ERROR = ErrorCode.JO_OPENSSL_ERROR.getCode();
    private static final int KS_TYPE = MLXKEMParameterSpec.x25519_mlkem768.getKeyType().getKsType();
    private static final String EXPORT_REFUSED = "this hybrid variant does not expose its private key material";
    // Above every group's share and private half.
    private static final int OUT_LEN = 4096;

    @BeforeAll
    public static void beforeAll()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    private void assertGenerateKeyPairReturns(OperationsTestNI.OpsTestFlag flag, long expectedCode)
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long keyRef = 0;
        try
        {
            int[] err = new int[1];
            operationsTestNI.setFlag(flag);
            keyRef = ni.ni_generateKeyPair(KS_TYPE, err, TestUtil.RNDSrc);
            Assertions.assertEquals(0L, keyRef);
            Assertions.assertEquals(expectedCode, err[0]);
        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }

    /** Generates a key, sets the flag, then runs the call under it; the key is disposed whatever happens. */
    private void withKeyUnderFlag(OperationsTestNI.OpsTestFlag flag, KeyCall call) throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long keyRef = ni.generateKeyPair(KS_TYPE, TestUtil.RNDSrc);
        try
        {
            operationsTestNI.setFlag(flag);
            call.run(keyRef);
        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
        }
    }

    private interface KeyCall
    {
        void run(long keyRef) throws Exception;
    }

    /** Both decoders under the flag, on a share and private half that import cleanly without it. */
    private void assertDecodeReturns(OperationsTestNI.OpsTestFlag flag, long expectedCode)
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long keyRef = ni.generateKeyPair(KS_TYPE, TestUtil.RNDSrc);
        long target = specNI.allocate();
        try
        {
            byte[] pub = new byte[ni.getPublicKey(keyRef, null)];
            ni.getPublicKey(keyRef, pub);
            byte[] priv = new byte[ni.getPrivateKey(keyRef, null)];
            ni.getPrivateKey(keyRef, priv);
            Assertions.assertEquals(0, ni.ni_decode_publicKey(target, KS_TYPE, pub, 0, pub.length));
            Assertions.assertEquals(0, ni.ni_decode_privateKey(target, KS_TYPE, priv, 0, priv.length, TestUtil.RNDSrc));

            operationsTestNI.setFlag(flag);
            Assertions.assertEquals(expectedCode, ni.ni_decode_publicKey(target, KS_TYPE, pub, 0, pub.length));
            Assertions.assertEquals(expectedCode,
                    ni.ni_decode_privateKey(target, KS_TYPE, priv, 0, priv.length, TestUtil.RNDSrc));
        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(target);
            specNI.dispose(keyRef);
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
    public void generateKeyPair_ctxNew_fail()
    {
        // Exercises interface/nonfips/util/mlxkem.c:77
        assertGenerateKeyPairReturns(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1, JO_OPENSSL_ERROR - 1400);
    }

    @Test
    public void generateKeyPair_keygenInit_fail()
    {
        // Exercises interface/nonfips/util/mlxkem.c:82
        assertGenerateKeyPairReturns(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2, JO_OPENSSL_ERROR - 1401);
    }

    @Test
    public void generateKeyPair_keygen_fail()
    {
        // Exercises interface/nonfips/util/mlxkem.c:93
        assertGenerateKeyPairReturns(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3, JO_OPENSSL_ERROR - 1402);
    }

    /** The keygen reported success and left no key: the generic code, no offset. */
    @Test
    public void generateKeyPair_noKey_fail()
    {
        // Exercises interface/nonfips/util/mlxkem.c:99
        assertGenerateKeyPairReturns(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_4, JO_OPENSSL_ERROR);
    }

    /** The size query refuses: the public getter reports the library's error, the private one the export refusal. */
    @Test
    public void getters_sizeQuery_fail() throws Exception
    {
        // Exercises interface/nonfips/util/mlxkem.c:143
        withKeyUnderFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_5, ref ->
        {
            OpenSSLException e = Assertions.assertThrows(OpenSSLException.class, () -> ni.getPublicKey(ref, null));
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
            UnsupportedOperationException u = Assertions.assertThrows(UnsupportedOperationException.class,
                    () -> ni.getPrivateKey(ref, null));
            Assertions.assertEquals(EXPORT_REFUSED, u.getMessage());
        });
    }

    @Test
    public void getters_lengthOverflow() throws Exception
    {
        // Exercises interface/nonfips/util/mlxkem.c:147
        withKeyUnderFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1, ref ->
        {
            OverflowException e = Assertions.assertThrows(OverflowException.class, () -> ni.getPublicKey(ref, null));
            Assertions.assertEquals("output too long int32", e.getMessage());
            e = Assertions.assertThrows(OverflowException.class, () -> ni.getPrivateKey(ref, new byte[OUT_LEN]));
            Assertions.assertEquals("output too long int32", e.getMessage());
        });
    }

    /** The size query answers and the fetch refuses: each getter reports as it does for a refused size query. */
    @Test
    public void getters_fetch_fail() throws Exception
    {
        // Exercises interface/nonfips/util/mlxkem.c:161
        withKeyUnderFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_6, ref ->
        {
            OpenSSLException e = Assertions.assertThrows(OpenSSLException.class,
                    () -> ni.getPublicKey(ref, new byte[OUT_LEN]));
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
            UnsupportedOperationException u = Assertions.assertThrows(UnsupportedOperationException.class,
                    () -> ni.getPrivateKey(ref, new byte[OUT_LEN]));
            Assertions.assertEquals(EXPORT_REFUSED, u.getMessage());
        });
    }

    @Test
    public void decode_ctxNew_fail()
    {
        // Exercises interface/nonfips/util/mlxkem.c:218
        assertDecodeReturns(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_7, JO_OPENSSL_ERROR - 1403);
    }

    @Test
    public void decode_fromdataInit_fail()
    {
        // Exercises interface/nonfips/util/mlxkem.c:223
        assertDecodeReturns(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_8, JO_OPENSSL_ERROR - 1404);
    }

    /** The import refuses: both decoders answer the typed key-type refusal. */
    @Test
    public void decode_fromdata_fail()
    {
        // Exercises interface/nonfips/util/mlxkem.c:236
        assertDecodeReturns(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_9, ErrorCode.JO_INVALID_KEY_TYPE.getCode());
    }

    @Test
    public void getPublicKey_accessOutput() throws Exception
    {
        Assumptions.assumeFalse(Loader.isFFM());
        // Exercises interface/nonfips/jni/mlxkem_ni_jni.c:73
        withKeyUnderFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1, ref ->
        {
            AccessException e = Assertions.assertThrows(AccessException.class,
                    () -> ni.getPublicKey(ref, new byte[OUT_LEN]));
            Assertions.assertEquals("unable to access output array", e.getMessage());
        });
    }

    @Test
    public void getPrivateKey_accessOutput() throws Exception
    {
        Assumptions.assumeFalse(Loader.isFFM());
        // Exercises interface/nonfips/jni/mlxkem_ni_jni.c:107
        withKeyUnderFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_2, ref ->
        {
            AccessException e = Assertions.assertThrows(AccessException.class,
                    () -> ni.getPrivateKey(ref, new byte[OUT_LEN]));
            Assertions.assertEquals("unable to access output array", e.getMessage());
        });
    }

    @Test
    public void decode_accessInput() throws Exception
    {
        Assumptions.assumeFalse(Loader.isFFM());
        // Exercises interface/nonfips/jni/mlxkem_ni_jni.c:148
        withKeyUnderFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_3, ref ->
        {
            AccessException e = Assertions.assertThrows(AccessException.class,
                    () -> ni.decode_publicKey(ref, KS_TYPE, new byte[OUT_LEN], 0, OUT_LEN));
            Assertions.assertEquals("unable to access input array", e.getMessage());
            e = Assertions.assertThrows(AccessException.class,
                    () -> ni.decode_privateKey(ref, KS_TYPE, new byte[OUT_LEN], 0, OUT_LEN, TestUtil.RNDSrc));
            Assertions.assertEquals("unable to access input array", e.getMessage());
        });
    }

    /** The no-key site returns the plain library code, which the JCA surface reports; the offset sites do not. */
    @Test
    public void generateKeyPair_nativeFailureIsAProviderException() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        // Exercises interface/nonfips/util/mlxkem.c:99
        assertProviderException(KeyPairGenerator.getInstance("X25519MLKEM768", JostleProvider.PROVIDER_NAME),
                operationsTestNI, OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_4);
    }

    private static void assertProviderException(KeyPairGenerator kpg, OperationsTestNI ops,
                                                OperationsTestNI.OpsTestFlag flag) throws Exception
    {
        try
        {
            ops.setFlag(flag);
            ProviderException e = Assertions.assertThrows(ProviderException.class, kpg::generateKeyPair);
            Assertions.assertEquals("unable to generate a X25519MLKEM768 key pair: OpenSSL Error: null",
                    e.getMessage());
            Assertions.assertEquals(OpenSSLException.class, e.getCause().getClass());
        }
        finally
        {
            ops.resetFlags();
        }

        // Control: the same generator works once the flag is cleared.
        Assertions.assertNotNull(kpg.generateKeyPair().getPrivate());
    }
}
