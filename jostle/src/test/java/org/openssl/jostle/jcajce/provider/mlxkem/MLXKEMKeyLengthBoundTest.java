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

package org.openssl.jostle.jcajce.provider.mlxkem;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.cache.NativeLengthCache;
import org.openssl.jostle.jcajce.spec.MLXKEMParameterSpec;
import org.openssl.jostle.rand.RandSource;

import java.security.Security;

/**
 * A wire-share length the library could answer that the Java side must not trust: one that disagrees with the first
 * answer the same library gave for that group is refused before anything is allocated from it. In the key classes'
 * package because they are package-private.
 */
public class MLXKEMKeyLengthBoundTest
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
    public void aShareLengthThatDisagreesWithTheMemoIsRefused()
    {
        StubNI stub = new StubNI(NISelector.MLXKEMServiceNI);
        JOMLXKEMPublicKey pub = (JOMLXKEMPublicKey) new MLXKEMKeyPairGenerator(stub, NISelector.SpecNI,
                MLXKEMParameterSpec.x25519_mlkem768).generateKeyPair().getPublic();

        int length = pub.getPublicData().length;
        Assertions.assertEquals(length, stub.keyLengthCache().get("X25519MLKEM768/PUBLIC"));

        stub.oversize = true;
        IllegalStateException e = Assertions.assertThrows(IllegalStateException.class, pub::getPublicData);
        Assertions.assertEquals("the library reported a PUBLIC length of " + (length + 1)
                + " for X25519MLKEM768, not " + length, e.getMessage());

        // Control: the same getter through the real answer still works.
        stub.oversize = false;
        Assertions.assertEquals(length, pub.getPublicData().length);
    }

    @Test
    public void aFirstAnswerThatIsNotALengthIsRefusedAndNotMemoised()
    {
        StubNI stub = new StubNI(NISelector.MLXKEMServiceNI);
        JOMLXKEMPublicKey pub = (JOMLXKEMPublicKey) new MLXKEMKeyPairGenerator(stub, NISelector.SpecNI,
                MLXKEMParameterSpec.x25519_mlkem768).generateKeyPair().getPublic();

        stub.answerZero = true;
        IllegalStateException e = Assertions.assertThrows(IllegalStateException.class, pub::getPublicData);
        Assertions.assertEquals("the library reported a PUBLIC length of 0 for X25519MLKEM768, which is not a length",
                e.getMessage());
        Assertions.assertEquals(NativeLengthCache.UNKNOWN, stub.keyLengthCache().get("X25519MLKEM768/PUBLIC"));
    }

    /** Delegates to a real NI with its own memo; on demand a size query answers one byte more, or zero. */
    private static final class StubNI implements MLXKEMServiceNI
    {
        private final MLXKEMServiceNI real;
        private final NativeLengthCache<String> keyLengthCache = new NativeLengthCache<String>();
        volatile boolean oversize;
        volatile boolean answerZero;

        StubNI(MLXKEMServiceNI real)
        {
            this.real = real;
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
        public int ni_getPublicKey(long ref, byte[] output)
        {
            int answer = real.ni_getPublicKey(ref, output);
            if (output != null)
            {
                return answer;
            }
            if (answerZero)
            {
                return 0;
            }
            return oversize ? answer + 1 : answer;
        }

        @Override
        public int ni_getPrivateKey(long ref, byte[] output)
        {
            return real.ni_getPrivateKey(ref, output);
        }

        @Override
        public int ni_decode_publicKey(long specRef, int keyType, byte[] input, int inputOffset, int inputLen)
        {
            return real.ni_decode_publicKey(specRef, keyType, input, inputOffset, inputLen);
        }

        @Override
        public int ni_decode_privateKey(long specRef, int keyType, byte[] input, int inputOffset, int inputLen,
                                        RandSource randSource)
        {
            return real.ni_decode_privateKey(specRef, keyType, input, inputOffset, inputLen, randSource);
        }
    }
}
