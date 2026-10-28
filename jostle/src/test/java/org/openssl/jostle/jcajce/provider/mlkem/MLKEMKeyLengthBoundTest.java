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

package org.openssl.jostle.jcajce.provider.mlkem;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.cache.NativeLengthCache;
import org.openssl.jostle.jcajce.provider.kts.KemSizes;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.rand.RandSource;
import org.openssl.jostle.test.TestUtil;

import java.security.KeyPair;
import java.security.Security;

/**
 * Lengths the library could answer that the Java side must not trust: a key encoding length, or a KEM encapsulation
 * or shared-secret length, that disagrees with the first answer the same library gave for that type is refused
 * before anything is allocated from it. In the key classes' package because they are package-private.
 */
public class MLKEMKeyLengthBoundTest
{
    private static final RandSource RND = TestUtil.RNDSrc;

    @BeforeAll
    public static void before()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    @Test
    public void aKeyLengthThatDisagreesWithTheMemoIsRefused()
    {
        StubNI stub = new StubNI(NISelector.MLKEMServiceNI);
        KeyPair kp = new MLKEMKeyPairGenerator(stub, NISelector.SpecNI, NISelector.Asn1NI, "ML-KEM-768")
                .generateKeyPair();
        JOMLKEMPublicKey pub = (JOMLKEMPublicKey) kp.getPublic();
        JOMLKEMPrivateKey priv = (JOMLKEMPrivateKey) kp.getPrivate();

        Assertions.assertEquals(1184, pub.getPublicData().length);
        Assertions.assertEquals(2400, priv.getDirectEncoding().length);
        Assertions.assertEquals(64, priv.getSeed().length);

        stub.oversize = true;
        IllegalStateException e = Assertions.assertThrows(IllegalStateException.class, pub::getPublicData);
        Assertions.assertEquals("the library reported a PUBLIC length of 1185 for ML_KEM_768, not 1184",
                e.getMessage());
        e = Assertions.assertThrows(IllegalStateException.class, priv::getDirectEncoding);
        Assertions.assertEquals("the library reported a PRIVATE length of 2401 for ML_KEM_768, not 2400",
                e.getMessage());
        e = Assertions.assertThrows(IllegalStateException.class, priv::getSeed);
        Assertions.assertEquals("the library reported a SEED length of 65 for ML_KEM_768, not 64", e.getMessage());

        // Control: the same getters through the real answers still work.
        stub.oversize = false;
        Assertions.assertEquals(1184, pub.getPublicData().length);
    }

    @Test
    public void aKemLengthThatDisagreesWithTheMemoIsRefused()
    {
        StubSpecNI stub = new StubSpecNI(NISelector.SpecNI);
        long ref = NISelector.MLKEMServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_768.getKsType(), RND);
        PKEYKeySpec key = new PKEYKeySpec(stub, ref, OSSLKeyType.ML_KEM_768);

        Assertions.assertEquals(32, KemSizes.sharedSecretLength(key, RND));
        Assertions.assertEquals(1088, KemSizes.ciphertextLength(key, RND));
        Assertions.assertEquals(32, KemSizes.checkedSharedSecretLength(key, 32));
        Assertions.assertEquals(1088, KemSizes.checkedCiphertextLength(key, 1088));

        IllegalStateException e = Assertions.assertThrows(IllegalStateException.class,
                () -> KemSizes.checkedSharedSecretLength(key, 33));
        Assertions.assertEquals("the library reported a shared secret length of 33 for ML_KEM_768, not 32",
                e.getMessage());
        e = Assertions.assertThrows(IllegalStateException.class, () -> KemSizes.checkedCiphertextLength(key, 1089));
        Assertions.assertEquals("the library reported a ciphertext length of 1089 for ML_KEM_768, not 1088",
                e.getMessage());

        // A first answer that is not positive is refused, not memoised.
        StubSpecNI zero = new StubSpecNI(NISelector.SpecNI);
        zero.answerZero = true;
        PKEYKeySpec zeroKey = new PKEYKeySpec(zero, NISelector.MLKEMServiceNI.generateKeyPair(
                OSSLKeyType.ML_KEM_768.getKsType(), RND), OSSLKeyType.ML_KEM_768);
        e = Assertions.assertThrows(IllegalStateException.class, () -> KemSizes.sharedSecretLength(zeroKey, RND));
        Assertions.assertEquals(
                "the library reported a shared secret length of 0 for ML_KEM_768, which is not a length",
                e.getMessage());
    }

    /** Delegates to a real NI with its own memo; on demand a size query answers one byte more. */
    private static final class StubNI implements MLKEMServiceNI
    {
        private final MLKEMServiceNI real;
        private final NativeLengthCache<String> keyLengthCache = new NativeLengthCache<String>();
        volatile boolean oversize;

        StubNI(MLKEMServiceNI real)
        {
            this.real = real;
        }

        private int size(byte[] output, int answer)
        {
            return output == null && oversize ? answer + 1 : answer;
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
        public long ni_generateKeyPair(int type, int[] err, byte[] seed, int seedLen, RandSource randSource)
        {
            return real.ni_generateKeyPair(type, err, seed, seedLen, randSource);
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
        public int ni_decode_publicKey(long specRef, int keyType, byte[] input, int inputOffset, int inputLen,
                                       RandSource randSource)
        {
            return real.ni_decode_publicKey(specRef, keyType, input, inputOffset, inputLen, randSource);
        }

        @Override
        public int ni_decode_privateKey(long specRef, int keyType, byte[] input, int inputOffset, int inputLen,
                                        RandSource randSource)
        {
            return real.ni_decode_privateKey(specRef, keyType, input, inputOffset, inputLen, randSource);
        }
    }

    /** Delegates to a real spec NI with fresh memos of its own; on demand the secret-length query answers zero. */
    private static final class StubSpecNI implements SpecNI
    {
        private final SpecNI real;
        private final NativeLengthCache<OSSLKeyType> lengthCache = new NativeLengthCache<OSSLKeyType>();
        private final NativeLengthCache<OSSLKeyType> secretLengthCache = new NativeLengthCache<OSSLKeyType>();
        volatile boolean answerZero;

        StubSpecNI(SpecNI real)
        {
            this.real = real;
        }

        @Override
        public void ni_dispose(long reference)
        {
            real.ni_dispose(reference);
        }

        @Override
        public long ni_allocate(int[] err)
        {
            return real.ni_allocate(err);
        }

        @Override
        public String ni_getName(long keyRef)
        {
            return real.ni_getName(keyRef);
        }

        @Override
        public String ni_getKeyProvider(long keyRef)
        {
            return real.ni_getKeyProvider(keyRef);
        }

        @Override
        public int ni_encap(long keyRef, String opt, byte[] secret, int inOff, int inLen, byte[] out, int off,
                            int len, RandSource randSource)
        {
            return real.ni_encap(keyRef, opt, secret, inOff, inLen, out, off, len, randSource);
        }

        @Override
        public int ni_decap(long keyRef, String opt, byte[] input, int inOff, int inLen, byte[] out, int off,
                            int len, RandSource randSource)
        {
            return real.ni_decap(keyRef, opt, input, inOff, inLen, out, off, len, randSource);
        }

        @Override
        public int ni_encapSecretLength(long keyRef, String opt, RandSource randSource)
        {
            return answerZero ? 0 : real.ni_encapSecretLength(keyRef, opt, randSource);
        }

        @Override
        public NativeLengthCache<OSSLKeyType> lengthCache()
        {
            return lengthCache;
        }

        @Override
        public NativeLengthCache<OSSLKeyType> secretLengthCache()
        {
            return secretLengthCache;
        }
    }
}
