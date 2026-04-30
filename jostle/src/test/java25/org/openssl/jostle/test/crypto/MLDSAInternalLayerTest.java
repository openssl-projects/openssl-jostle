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

package org.openssl.jostle.test.crypto;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.OverflowException;
import org.openssl.jostle.jcajce.provider.mldsa.MLDSAServiceNI;
import org.openssl.jostle.jcajce.provider.mldsa.MLDSASignatureSpi;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.test.TestUtil;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.security.Security;

/**
 * Test paths where that we cannot test using simple arguments
 */
public class MLDSAInternalLayerTest
{
    @BeforeAll
    public static void beforeAll()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    MLDSAServiceNI mldsaServiceNI = TestNISelector.getMLDSANI();
    SpecNI specNI = TestNISelector.getSpecNI();


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
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
           mldsaServiceNI.initSign(mldsaRef, keyRef, new byte[0], 0, MLDSASignatureSpi.MuHandling.EXTERNAL_MU.ordinal(), TestUtil.RNDSrc);

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
        } catch (OverflowException e)
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
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.initSign(mldsaRef, keyRef, new byte[0], 0, MLDSASignatureSpi.MuHandling.INTERNAL.ordinal(), TestUtil.RNDSrc);

            long len = mldsaServiceNI.sign(mldsaRef, null, 0, TestUtil.RNDSrc);

            byte[] sig = new byte[(int)len];

            MemorySegment ctx = MemorySegment.ofAddress(mldsaRef).reinterpret(376);

            ctx.set(ValueLayout.JAVA_BYTE, 364, (byte) 4);


            mldsaServiceNI.sign(mldsaRef, sig, 0, TestUtil.RNDSrc);

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
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.initVerify(mldsaRef, keyRef, new byte[0], 0, MLDSASignatureSpi.MuHandling.INTERNAL.ordinal());

            MemorySegment ctx = MemorySegment.ofAddress(mldsaRef).reinterpret(376);

            ctx.set(ValueLayout.JAVA_BYTE, 28, (byte) 0x7f);

           mldsaServiceNI.verify(mldsaRef, new byte[1024], 1024);

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
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.initVerify(mldsaRef, keyRef, new byte[0], 0, MLDSASignatureSpi.MuHandling.INTERNAL.ordinal());

            MemorySegment ctx = MemorySegment.ofAddress(mldsaRef).reinterpret(376);

            ctx.set(ValueLayout.JAVA_BYTE, 28, (byte) 0x7f);

           mldsaServiceNI.verify(mldsaRef, new byte[1024], 1024);

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
    public void extract_tr_invalidKeyType() throws Throwable
    {
        // The default branch in extract_tr's switch is unreachable through the
        // normal callers (init_sign / init_verify pre-validate the typeId via
        // EVP_PKEY_is_a). Reach it directly via FFI to confirm the diagnostic
        // wiring (ret_code = JO_INCORRECT_KEY_TYPE, return = 0).
        long keyRef = 0;
        try
        {
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType(), TestUtil.RNDSrc);
            Assertions.assertTrue(keyRef > 0);

            MemorySegment ms = lookup.find("extract_tr").orElseThrow();
            MethodHandle mh = linker.downcallHandle(ms, FunctionDescriptor.of(
                    ValueLayout.JAVA_INT,    // return: 1 success, 0 fail
                    ValueLayout.ADDRESS,     // const key_spec *
                    ValueLayout.JAVA_INT,    // int32_t type
                    ValueLayout.ADDRESS,     // uint8_t *tr (64 bytes)
                    ValueLayout.ADDRESS      // int32_t *ret_code
            ), Linker.Option.critical(true));

            try (Arena arena = Arena.ofConfined())
            {
                MemorySegment trBuf = arena.allocate(64);
                MemorySegment retCode = arena.allocate(ValueLayout.JAVA_INT);

                int result = (int) mh.invoke(
                        MemorySegment.ofAddress(keyRef),
                        99, // unrecognised type id
                        trBuf,
                        retCode);

                Assertions.assertEquals(0, result);
                Assertions.assertEquals(ErrorCode.JO_INCORRECT_KEY_TYPE.getCode(),
                        retCode.get(ValueLayout.JAVA_INT, 0));
            }
        } finally
        {
            specNI.dispose(keyRef);
        }
    }


    @Test
    public void decode_publicKey_reusedSpec() throws Throwable
    {
        // Calling decode_public_key twice on the same spec exercises the
        // pre-existing-key free guard. The wrappers always pass fresh specs,
        // so the only way to reach this path is a direct FFI call.
        long sourceRef1 = 0;
        long sourceRef2 = 0;
        long targetRef = 0;
        try
        {
            sourceRef1 = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType(), TestUtil.RNDSrc);
            sourceRef2 = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType(), TestUtil.RNDSrc);
            Assertions.assertTrue(sourceRef1 > 0);
            Assertions.assertTrue(sourceRef2 > 0);

            int len = mldsaServiceNI.getPublicKey(sourceRef1, null);
            byte[] pub1 = new byte[len];
            byte[] pub2 = new byte[len];
            Assertions.assertEquals(len, mldsaServiceNI.getPublicKey(sourceRef1, pub1));
            Assertions.assertEquals(len, mldsaServiceNI.getPublicKey(sourceRef2, pub2));
            Assertions.assertFalse(java.util.Arrays.equals(pub1, pub2));

            targetRef = specNI.allocate();
            Assertions.assertTrue(targetRef > 0);

            MemorySegment ms = lookup.find("mldsa_decode_public_key").orElseThrow();
            MethodHandle mh = linker.downcallHandle(ms, FunctionDescriptor.of(
                    ValueLayout.JAVA_INT,    // int32_t return
                    ValueLayout.ADDRESS,     // key_spec *
                    ValueLayout.JAVA_INT,    // int32_t typeId
                    ValueLayout.ADDRESS,     // uint8_t *src
                    ValueLayout.JAVA_LONG    // size_t src_len
            ), Linker.Option.critical(true));

            try (Arena arena = Arena.ofConfined())
            {
                MemorySegment srcSeg1 = arena.allocate(pub1.length);
                MemorySegment.copy(pub1, 0, srcSeg1, ValueLayout.JAVA_BYTE, 0, pub1.length);
                int code1 = (int) mh.invoke(
                        MemorySegment.ofAddress(targetRef),
                        OSSLKeyType.ML_DSA_44.getKsType(),
                        srcSeg1,
                        (long) pub1.length);
                Assertions.assertEquals(ErrorCode.JO_SUCCESS.getCode(), code1);

                // Second call into the same spec — exercises the defensive free
                // of the pre-existing EVP_PKEY before the new one is decoded.
                MemorySegment srcSeg2 = arena.allocate(pub2.length);
                MemorySegment.copy(pub2, 0, srcSeg2, ValueLayout.JAVA_BYTE, 0, pub2.length);
                int code2 = (int) mh.invoke(
                        MemorySegment.ofAddress(targetRef),
                        OSSLKeyType.ML_DSA_44.getKsType(),
                        srcSeg2,
                        (long) pub2.length);
                Assertions.assertEquals(ErrorCode.JO_SUCCESS.getCode(), code2);
            }

            // Confirm the spec now contains the second key, not the first —
            // both the raw exported bytes and a functional sign/verify
            // roundtrip have to agree, so we know the EVP_PKEY behind the spec
            // really matches pub2 rather than coincidentally producing the
            // same byte pattern.
            byte[] target = new byte[len];
            Assertions.assertEquals(len, mldsaServiceNI.getPublicKey(targetRef, target));
            Assertions.assertArrayEquals(pub2, target);
            Assertions.assertFalse(java.util.Arrays.equals(pub1, target));

            // Sign with sourceRef2's private key (the source of pub2), verify
            // with targetRef. If targetRef is functionally pub2's pubkey, the
            // sig verifies; if it were any other key the verify would fail.
            byte[] msg = "decode_publicKey_reusedSpec".getBytes();
            long mldsaRef = 0;
            try
            {
                mldsaRef = mldsaServiceNI.allocateSigner();
                Assertions.assertTrue(mldsaRef > 0);

                mldsaServiceNI.initSign(mldsaRef, sourceRef2, new byte[0], 0,
                        MLDSASignatureSpi.MuHandling.INTERNAL.ordinal(), TestUtil.RNDSrc);
                mldsaServiceNI.update(mldsaRef, msg, 0, msg.length);
                int sigLen = mldsaServiceNI.sign(mldsaRef, null, 0, TestUtil.RNDSrc);
                byte[] sig = new byte[sigLen];
                Assertions.assertEquals(sigLen, mldsaServiceNI.sign(mldsaRef, sig, 0, TestUtil.RNDSrc));

                mldsaServiceNI.initVerify(mldsaRef, targetRef, new byte[0], 0,
                        MLDSASignatureSpi.MuHandling.INTERNAL.ordinal());
                mldsaServiceNI.update(mldsaRef, msg, 0, msg.length);
                Assertions.assertEquals(ErrorCode.JO_SUCCESS.getCode(),
                        mldsaServiceNI.verify(mldsaRef, sig, sig.length));

                // And cross-check: a signature produced with sourceRef1's
                // private key must NOT verify under targetRef.
                mldsaServiceNI.initSign(mldsaRef, sourceRef1, new byte[0], 0,
                        MLDSASignatureSpi.MuHandling.INTERNAL.ordinal(), TestUtil.RNDSrc);
                mldsaServiceNI.update(mldsaRef, msg, 0, msg.length);
                byte[] sig1 = new byte[sigLen];
                Assertions.assertEquals(sigLen, mldsaServiceNI.sign(mldsaRef, sig1, 0, TestUtil.RNDSrc));

                mldsaServiceNI.initVerify(mldsaRef, targetRef, new byte[0], 0,
                        MLDSASignatureSpi.MuHandling.INTERNAL.ordinal());
                mldsaServiceNI.update(mldsaRef, msg, 0, msg.length);
                Assertions.assertEquals(ErrorCode.JO_FAIL.getCode(),
                        mldsaServiceNI.verify(mldsaRef, sig1, sig1.length));
            } finally
            {
                mldsaServiceNI.disposeSigner(mldsaRef);
            }
        } finally
        {
            specNI.dispose(targetRef);
            specNI.dispose(sourceRef1);
            specNI.dispose(sourceRef2);
        }
    }


    @Test
    public void decode_privateKey_reusedSpec() throws Throwable
    {
        // Mirror of the public-key test — exercises the pre-existing-key
        // free in mldsa_decode_private_key.
        long sourceRef1 = 0;
        long sourceRef2 = 0;
        long targetRef = 0;
        try
        {
            sourceRef1 = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType(), TestUtil.RNDSrc);
            sourceRef2 = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType(), TestUtil.RNDSrc);
            Assertions.assertTrue(sourceRef1 > 0);
            Assertions.assertTrue(sourceRef2 > 0);

            int len = mldsaServiceNI.getPrivateKey(sourceRef1, null);
            byte[] priv1 = new byte[len];
            byte[] priv2 = new byte[len];
            Assertions.assertEquals(len, mldsaServiceNI.getPrivateKey(sourceRef1, priv1));
            Assertions.assertEquals(len, mldsaServiceNI.getPrivateKey(sourceRef2, priv2));
            Assertions.assertFalse(java.util.Arrays.equals(priv1, priv2));

            targetRef = specNI.allocate();
            Assertions.assertTrue(targetRef > 0);

            MemorySegment ms = lookup.find("mldsa_decode_private_key").orElseThrow();
            MethodHandle mh = linker.downcallHandle(ms, FunctionDescriptor.of(
                    ValueLayout.JAVA_INT,    // int32_t return
                    ValueLayout.ADDRESS,     // key_spec *
                    ValueLayout.JAVA_INT,    // int32_t typeId
                    ValueLayout.ADDRESS,     // uint8_t *src
                    ValueLayout.JAVA_LONG    // size_t src_len
            ), Linker.Option.critical(true));

            try (Arena arena = Arena.ofConfined())
            {
                MemorySegment srcSeg1 = arena.allocate(priv1.length);
                MemorySegment.copy(priv1, 0, srcSeg1, ValueLayout.JAVA_BYTE, 0, priv1.length);
                int code1 = (int) mh.invoke(
                        MemorySegment.ofAddress(targetRef),
                        OSSLKeyType.ML_DSA_44.getKsType(),
                        srcSeg1,
                        (long) priv1.length);
                Assertions.assertEquals(ErrorCode.JO_SUCCESS.getCode(), code1);

                MemorySegment srcSeg2 = arena.allocate(priv2.length);
                MemorySegment.copy(priv2, 0, srcSeg2, ValueLayout.JAVA_BYTE, 0, priv2.length);
                int code2 = (int) mh.invoke(
                        MemorySegment.ofAddress(targetRef),
                        OSSLKeyType.ML_DSA_44.getKsType(),
                        srcSeg2,
                        (long) priv2.length);
                Assertions.assertEquals(ErrorCode.JO_SUCCESS.getCode(), code2);
            }

            byte[] target = new byte[len];
            Assertions.assertEquals(len, mldsaServiceNI.getPrivateKey(targetRef, target));
            Assertions.assertArrayEquals(priv2, target);
            Assertions.assertFalse(java.util.Arrays.equals(priv1, target));

            // Functional roundtrip: sign with targetRef (now holding priv2),
            // verify with sourceRef2's public key. If targetRef is genuinely
            // priv2 the sig verifies; if it were any other private key the
            // signature wouldn't validate under sourceRef2's public key.
            byte[] msg = "decode_privateKey_reusedSpec".getBytes();
            long mldsaRef = 0;
            try
            {
                mldsaRef = mldsaServiceNI.allocateSigner();
                Assertions.assertTrue(mldsaRef > 0);

                mldsaServiceNI.initSign(mldsaRef, targetRef, new byte[0], 0,
                        MLDSASignatureSpi.MuHandling.INTERNAL.ordinal(), TestUtil.RNDSrc);
                mldsaServiceNI.update(mldsaRef, msg, 0, msg.length);
                int sigLen = mldsaServiceNI.sign(mldsaRef, null, 0, TestUtil.RNDSrc);
                byte[] sig = new byte[sigLen];
                Assertions.assertEquals(sigLen, mldsaServiceNI.sign(mldsaRef, sig, 0, TestUtil.RNDSrc));

                mldsaServiceNI.initVerify(mldsaRef, sourceRef2, new byte[0], 0,
                        MLDSASignatureSpi.MuHandling.INTERNAL.ordinal());
                mldsaServiceNI.update(mldsaRef, msg, 0, msg.length);
                Assertions.assertEquals(ErrorCode.JO_SUCCESS.getCode(),
                        mldsaServiceNI.verify(mldsaRef, sig, sig.length));

                // And cross-check: targetRef's signature must NOT verify
                // under sourceRef1's public key.
                mldsaServiceNI.initVerify(mldsaRef, sourceRef1, new byte[0], 0,
                        MLDSASignatureSpi.MuHandling.INTERNAL.ordinal());
                mldsaServiceNI.update(mldsaRef, msg, 0, msg.length);
                Assertions.assertEquals(ErrorCode.JO_FAIL.getCode(),
                        mldsaServiceNI.verify(mldsaRef, sig, sig.length));
            } finally
            {
                mldsaServiceNI.disposeSigner(mldsaRef);
            }
        } finally
        {
            specNI.dispose(targetRef);
            specNI.dispose(sourceRef1);
            specNI.dispose(sourceRef2);
        }
    }

}
