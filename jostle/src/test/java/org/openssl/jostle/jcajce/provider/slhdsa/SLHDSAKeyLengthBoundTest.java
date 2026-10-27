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

package org.openssl.jostle.jcajce.provider.slhdsa;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.cache.NativeLengthCache;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.rand.RandSource;

import java.security.KeyPair;
import java.security.Security;

/**
 * Two answers the library could give that the Java side must not trust: a size query that disagrees with the length
 * the library gave first for that type and part is refused before anything is allocated from it, and a JO_FAIL from
 * update is refused rather than ignored. In the key classes' package because they are package-private.
 */
public class SLHDSAKeyLengthBoundTest
{
    @BeforeAll
    public static void before()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    /** Unbound keys from a directly constructed generator, so the unbound SPI below accepts them. */
    private static KeyPair keyPair(SLHDSAServiceNI ni)
    {
        return new SLHDSAKeyPairGenerator(ni, NISelector.SpecNI, NISelector.Asn1NI, "SLH-DSA-SHA2-128F")
                .generateKeyPair();
    }

    @Test
    public void aKeyLengthThatDisagreesWithTheMemoIsRefused()
    {
        StubNI stub = new StubNI(NISelector.SLHDSAServiceNI);
        KeyPair kp = keyPair(stub);
        JOSLHDSAPublicKey pub = (JOSLHDSAPublicKey) kp.getPublic();
        JOSLHDSAPrivateKey priv = (JOSLHDSAPrivateKey) kp.getPrivate();
        Assertions.assertEquals(OSSLKeyType.SLH_DSA_SHA2_128f, pub.getSpec().getType());

        Assertions.assertEquals(32, pub.getPublicData().length);
        Assertions.assertEquals(64, priv.getDirectEncoding().length);

        stub.oversize = true;
        IllegalStateException e = Assertions.assertThrows(IllegalStateException.class, pub::getPublicData);
        Assertions.assertEquals("the library reported a PUBLIC length of 33 for SLH_DSA_SHA2_128f, not 32",
                e.getMessage());
        e = Assertions.assertThrows(IllegalStateException.class, priv::getDirectEncoding);
        Assertions.assertEquals("the library reported a PRIVATE length of 65 for SLH_DSA_SHA2_128f, not 64",
                e.getMessage());

        // Control: the same getters through the real answers still work.
        stub.oversize = false;
        Assertions.assertEquals(32, pub.getPublicData().length);
    }

    @Test
    public void aFailFromUpdateIsRefusedNotIgnored() throws Exception
    {
        StubNI stub = new StubNI(NISelector.SLHDSAServiceNI);
        KeyPair kp = keyPair(stub);
        SLHDSASignatureSpi spi = new SLHDSASignatureSpi(stub,
                new SLHDSAKeyFactorySpi(stub, NISelector.SpecNI, NISelector.Asn1NI), OSSLKeyType.NONE,
                SLHDSASignatureSpi.MessageEncoding.PURE, SLHDSASignatureSpi.Deterministic.NON_DETERMINISTIC);
        spi.engineInitSign(kp.getPrivate());
        spi.engineUpdate(new byte[4], 0, 4);

        stub.failUpdate = true;
        IllegalStateException e = Assertions.assertThrows(IllegalStateException.class,
                () -> spi.engineUpdate(new byte[4], 0, 4));
        Assertions.assertEquals("unexpected error code " + ErrorCode.JO_FAIL + ": -1", e.getMessage());
    }

    /** Delegates to a real NI; on demand a size query answers one byte more, or update answers JO_FAIL. */
    private static final class StubNI implements SLHDSAServiceNI
    {
        private final SLHDSAServiceNI real;
        private final NativeLengthCache<OSSLKeyType> lengthCache = new NativeLengthCache<OSSLKeyType>();
        private final NativeLengthCache<String> keyLengthCache = new NativeLengthCache<String>();
        volatile boolean oversize;
        volatile boolean failUpdate;

        StubNI(SLHDSAServiceNI real)
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
        public long ni_generateKeyPair(int type, int[] err, byte[] seed, int seedLen, RandSource randSource)
        {
            return real.ni_generateKeyPair(type, err, seed, seedLen, randSource);
        }

        @Override
        public int ni_getPrivateKey(long reference, byte[] output)
        {
            return size(output, real.ni_getPrivateKey(reference, output));
        }

        @Override
        public int ni_getPublicKey(long reference, byte[] output)
        {
            return size(output, real.ni_getPublicKey(reference, output));
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

        @Override
        public long ni_allocateSigner(int[] err)
        {
            return real.ni_allocateSigner(err);
        }

        @Override
        public int ni_initVerify(long ref, long keyRef, byte[] context, int contextLen, int messageEncoding,
                                 int deterministic)
        {
            return real.ni_initVerify(ref, keyRef, context, contextLen, messageEncoding, deterministic);
        }

        @Override
        public int ni_update(long ref, byte[] b, int off, int len)
        {
            return failUpdate ? ErrorCode.JO_FAIL.getCode() : real.ni_update(ref, b, off, len);
        }

        @Override
        public int ni_sign(long ref, byte[] sig, int offset, RandSource randSource)
        {
            return real.ni_sign(ref, sig, offset, randSource);
        }

        @Override
        public int ni_verify(long reference, byte[] sigBytes, int len)
        {
            return real.ni_verify(reference, sigBytes, len);
        }

        @Override
        public int ni_initSign(long reference, long keyRef, byte[] context, int contextLen, int messageEncoding,
                               int deterministic, RandSource randSource)
        {
            return real.ni_initSign(reference, keyRef, context, contextLen, messageEncoding, deterministic,
                    randSource);
        }

        @Override
        public void ni_disposeSigner(long reference)
        {
            real.ni_disposeSigner(reference);
        }
    }
}
