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

package org.openssl.jostle.jcajce.provider.mldsa;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.cache.NativeLengthCache;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.rand.RandSource;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;

/**
 * The raw key getters bound each allocation by the length the library gave first for that type and part: a stub NI
 * that answers one byte more on a later size query is refused before anything is allocated from it. In the key
 * classes' package because they are package-private.
 */
public class MLDSAKeyLengthBoundTest
{
    @BeforeAll
    public static void before()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    @Test
    public void aKeyLengthThatDisagreesWithTheMemoIsRefused() throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance("ML-DSA-44", JostleProvider.PROVIDER_NAME).generateKeyPair();
        PKEYKeySpec spec = ((JOMLDSAPublicKey) kp.getPublic()).getSpec();
        Assertions.assertEquals(OSSLKeyType.ML_DSA_44, spec.getType());
        OversizingNI stub = new OversizingNI(NISelector.MLDSAServiceNI);
        JOMLDSAPublicKey pub = new JOMLDSAPublicKey(stub, NISelector.Asn1NI, spec);
        JOMLDSAPrivateKey priv = new JOMLDSAPrivateKey(stub, NISelector.Asn1NI, spec);

        Assertions.assertEquals(1312, pub.getPublicData().length);
        Assertions.assertEquals(2560, priv.getPrivateData().length);
        Assertions.assertEquals(32, priv.getSeed().length);

        stub.oversize = true;
        IllegalStateException e = Assertions.assertThrows(IllegalStateException.class, pub::getPublicData);
        Assertions.assertEquals("the library reported a PUBLIC length of 1313 for ML_DSA_44, not 1312",
                e.getMessage());
        e = Assertions.assertThrows(IllegalStateException.class, priv::getPrivateData);
        Assertions.assertEquals("the library reported a PRIVATE length of 2561 for ML_DSA_44, not 2560",
                e.getMessage());
        e = Assertions.assertThrows(IllegalStateException.class, priv::getSeed);
        Assertions.assertEquals("the library reported a SEED length of 33 for ML_DSA_44, not 32", e.getMessage());

        // Control: the same getters through the real NI still answer.
        stub.oversize = false;
        Assertions.assertEquals(1312, pub.getPublicData().length);
    }

    /** Delegates to a real NI; while oversize is set, every size query answers one byte more. */
    private static final class OversizingNI implements MLDSAServiceNI
    {
        private final MLDSAServiceNI real;
        private final NativeLengthCache<OSSLKeyType> lengthCache = new NativeLengthCache<OSSLKeyType>();
        private final NativeLengthCache<String> keyLengthCache = new NativeLengthCache<String>();
        volatile boolean oversize;

        OversizingNI(MLDSAServiceNI real)
        {
            this.real = real;
        }

        private int size(byte[] output, int answer)
        {
            return output == null && oversize ? answer + 1 : answer;
        }

        @Override
        public NativeLengthCache<OSSLKeyType> lengthCache()
        {
            return lengthCache;
        }

        @Override
        public NativeLengthCache<String> keyLengthCache()
        {
            return keyLengthCache;
        }

        @Override
        public long ni_generateKeyPair(int type, int[] err, RandSource randSource)
        {
            return real.ni_generateKeyPair(type, err, randSource);
        }

        @Override
        public long ni_generateKeyPair(int type, int[] err, byte[] seed, int seedLen, RandSource rndSource)
        {
            return real.ni_generateKeyPair(type, err, seed, seedLen, rndSource);
        }

        @Override
        public int ni_getPublicKey(long ref, byte[] output)
        {
            return size(output, real.ni_getPublicKey(ref, output));
        }

        @Override
        public int ni_getPrivateKey(long ref, byte[] output)
        {
            return size(output, real.ni_getPrivateKey(ref, output));
        }

        @Override
        public int ni_getSeed(long ref, byte[] output)
        {
            return size(output, real.ni_getSeed(ref, output));
        }

        @Override
        public void ni_disposeSigner(long reference)
        {
            real.ni_disposeSigner(reference);
        }

        @Override
        public long ni_allocateSigner(int[] err)
        {
            return real.ni_allocateSigner(err);
        }

        @Override
        public int ni_initVerify(long ref, long keyReference, byte[] context, int contextLen, int muHandlingOrdinal)
        {
            return real.ni_initVerify(ref, keyReference, context, contextLen, muHandlingOrdinal);
        }

        @Override
        public int ni_initSign(long reference, long keyReference, byte[] context, int contextLen,
                               int muHandlingOrdinal, RandSource randSource)
        {
            return real.ni_initSign(reference, keyReference, context, contextLen, muHandlingOrdinal, randSource);
        }

        @Override
        public int ni_update(long reference, byte[] input, int inputOffset, int inputLen)
        {
            return real.ni_update(reference, input, inputOffset, inputLen);
        }

        @Override
        public int ni_sign(long reference, byte[] output, int offset, RandSource randSource)
        {
            return real.ni_sign(reference, output, offset, randSource);
        }

        @Override
        public int ni_verify(long reference, byte[] sigBytes, int sigLen)
        {
            return real.ni_verify(reference, sigBytes, sigLen);
        }

        @Override
        public int ni_decode_publicKey(long specRef, int keyType, byte[] input, int inputOffset, int inputLen)
        {
            return real.ni_decode_publicKey(specRef, keyType, input, inputOffset, inputLen);
        }

        @Override
        public int ni_decode_privateKey(long specRef, int keyType, byte[] input, int inputOffset, int inputLen)
        {
            return real.ni_decode_privateKey(specRef, keyType, input, inputOffset, inputLen);
        }
    }
}
