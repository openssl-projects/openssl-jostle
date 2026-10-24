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

package org.openssl.jostle.test.dsa;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.dsa.DSAKeyFactorySpi;
import org.openssl.jostle.jcajce.provider.dsa.DSAKeyPairGenerator;
import org.openssl.jostle.jcajce.provider.dsa.DSAServiceNI;
import org.openssl.jostle.jcajce.provider.dsa.DSASignatureSpi;
import org.openssl.jostle.rand.RandSource;

import java.security.KeyPair;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;

/**
 * A library failure inside sign reaches the caller as the SignatureException Signature.sign declares, with the
 * failure as its cause. No real input makes an initialised DSA sign fail, so the NI answers the library's generic
 * error from its sign entry; every other entry is the real one.
 */
public class DSASignFailureTypeTest
{
    private static KeyPair pair;

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        // Unbound, as the SPI under test is.
        DSAKeyPairGenerator kpg = new DSAKeyPairGenerator();
        kpg.initialize(1024);
        pair = kpg.generateKeyPair();
    }

    private static Provider providerOver(DSAServiceNI ni)
    {
        return new OneSignature(ni);
    }

    /** One Signature service whose SPI runs over the given NI. */
    private static final class OneSignature extends Provider
    {
        @SuppressWarnings("deprecation")
        OneSignature(final DSAServiceNI ni)
        {
            super("DSASignFailureType", 1.0, "one DSA Signature over a chosen NI");
            putService(new Service(this, "Signature", "SHA256withDSA", DSASignatureSpi.class.getName(), null, null)
            {
                @Override
                public Object newInstance(Object constructorParameter)
                {
                    return new DSASignatureSpi(ni, new DSAKeyFactorySpi(), "SHA256");
                }
            });
        }
    }

    @Test
    public void aSignFailureIsASignatureExceptionWithTheCause() throws Exception
    {
        Provider failing = providerOver(new FailingSign(NISelector.DSAServiceNI));
        Signature signer = Signature.getInstance("SHA256withDSA", failing);
        signer.initSign(pair.getPrivate());
        signer.update(new byte[32]);
        SignatureException e = Assertions.assertThrows(SignatureException.class, signer::sign);
        Assertions.assertEquals(OpenSSLException.class, e.getCause().getClass());
        Assertions.assertTrue(e.getMessage().startsWith("OpenSSL Error:"), e.getMessage());
    }

    /** The control: the same provider over the real NI signs, and the signature verifies. */
    @Test
    public void theRealNiSigns() throws Exception
    {
        Provider p = providerOver(NISelector.DSAServiceNI);
        Signature signer = Signature.getInstance("SHA256withDSA", p);
        signer.initSign(pair.getPrivate());
        signer.update(new byte[32]);
        byte[] sig = signer.sign();
        Signature verifier = Signature.getInstance("SHA256withDSA", p);
        verifier.initVerify(pair.getPublic());
        verifier.update(new byte[32]);
        Assertions.assertTrue(verifier.verify(sig));
    }

    /** The real NI, except that sign answers the library's generic error. */
    private static final class FailingSign implements DSAServiceNI
    {
        private final DSAServiceNI real;

        FailingSign(DSAServiceNI real)
        {
            this.real = real;
        }

        public long ni_generateParameters(int pBits, int qBits, int[] err, RandSource rndSource)
        {
            return real.ni_generateParameters(pBits, qBits, err, rndSource);
        }

        public long ni_makeParamsFromComponents(byte[] p, byte[] q, byte[] g, int[] err)
        {
            return real.ni_makeParamsFromComponents(p, q, g, err);
        }

        public long ni_generateKeyPair(long paramsRef, int[] err, RandSource rndSource)
        {
            return real.ni_generateKeyPair(paramsRef, err, rndSource);
        }

        public long ni_makePrivateFromComponents(byte[] p, byte[] q, byte[] g, byte[] x, int[] err,
                                                 RandSource rndSource)
        {
            return real.ni_makePrivateFromComponents(p, q, g, x, err, rndSource);
        }

        public long ni_makePublicFromComponents(byte[] p, byte[] q, byte[] g, byte[] y, int[] err)
        {
            return real.ni_makePublicFromComponents(p, q, g, y, err);
        }

        public int ni_getComponent(long specRef, int component, byte[] out)
        {
            return real.ni_getComponent(specRef, component, out);
        }

        public long ni_allocateSigner(int[] err)
        {
            return real.ni_allocateSigner(err);
        }

        public void ni_disposeSigner(long reference)
        {
            real.ni_disposeSigner(reference);
        }

        public int ni_initSign(long ref, long keyRef, String digestName, RandSource rndSource)
        {
            return real.ni_initSign(ref, keyRef, digestName, rndSource);
        }

        public int ni_initVerify(long ref, long keyRef, String digestName)
        {
            return real.ni_initVerify(ref, keyRef, digestName);
        }

        public int ni_update(long ref, byte[] input, int inOff, int inLen)
        {
            return real.ni_update(ref, input, inOff, inLen);
        }

        public int ni_sign(long ref, byte[] sig, int outOff, RandSource rndSource)
        {
            return ErrorCode.JO_OPENSSL_ERROR.getCode();
        }

        public int ni_verify(long ref, byte[] sig, int sigLen, RandSource rndSource)
        {
            return real.ni_verify(ref, sig, sigLen, rndSource);
        }
    }
}
