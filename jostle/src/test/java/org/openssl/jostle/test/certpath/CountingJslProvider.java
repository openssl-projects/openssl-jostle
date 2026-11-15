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

package org.openssl.jostle.test.certpath;

import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A provider serving JSL's X.509 factory and counting ECDSA verifiers, so a test can count the signature checks
 * the PKIX builder and validator make when they order certificates. Handed to an SPI as its provider instance.
 */
final class CountingJslProvider
    extends Provider
{
    /** SHA256withECDSA initVerify calls since the last reset. */
    static final AtomicInteger VERIFICATIONS = new AtomicInteger();
    /** SHA384withECDSA initVerify calls since the last reset, so a test can sign one kind of object with it. */
    static final AtomicInteger VERIFICATIONS_384 = new AtomicInteger();

    CountingJslProvider()
    {
        super("CountingJSL", 1.0, "JSL's X.509 factory and a counting ECDSA verifier");
        final Provider jsl = Security.getProvider(JostleProvider.PROVIDER_NAME);
        putService(new Service(this, "CertificateFactory", "X.509", "unused", null, null)
        {
            @Override
            public Object newInstance(Object parameter) throws NoSuchAlgorithmException
            {
                return jsl.getService("CertificateFactory", "X.509").newInstance(parameter);
            }
        });
        counting("SHA256withECDSA", "1.2.840.10045.4.3.2", VERIFICATIONS);
        counting("SHA384withECDSA", "1.2.840.10045.4.3.3", VERIFICATIONS_384);
    }

    private void counting(final String algorithm, String oid, final AtomicInteger counter)
    {
        putService(new Service(this, "Signature", algorithm, "unused",
                Arrays.asList(algorithm.toUpperCase(), oid), null)
        {
            @Override
            public Object newInstance(Object parameter) throws NoSuchAlgorithmException
            {
                try
                {
                    return new CountingSignature(algorithm, counter);
                }
                catch (Exception e)
                {
                    throw new NoSuchAlgorithmException(e);
                }
            }
        });
    }

    /** A Signature that counts initVerify and forwards to JSL's. */
    public static final class CountingSignature
        extends SignatureSpi
    {
        private final Signature inner;
        private final AtomicInteger counter;

        public CountingSignature(String algorithm, AtomicInteger counter) throws Exception
        {
            inner = Signature.getInstance(algorithm, JostleProvider.PROVIDER_NAME);
            this.counter = counter;
        }

        @Override
        protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException
        {
            counter.incrementAndGet();
            inner.initVerify(publicKey);
        }

        @Override
        protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException
        {
            throw new InvalidKeyException("verification only");
        }

        @Override
        protected void engineUpdate(byte b) throws SignatureException
        {
            inner.update(b);
        }

        @Override
        protected void engineUpdate(byte[] b, int off, int len) throws SignatureException
        {
            inner.update(b, off, len);
        }

        @Override
        protected byte[] engineSign() throws SignatureException
        {
            throw new SignatureException("verification only");
        }

        @Override
        protected boolean engineVerify(byte[] sig) throws SignatureException
        {
            return inner.verify(sig);
        }

        @Override
        protected void engineSetParameter(AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException
        {
            inner.setParameter(params);
        }

        @Override
        @Deprecated
        protected void engineSetParameter(String param, Object value)
        {
            throw new UnsupportedOperationException();
        }

        @Override
        @Deprecated
        protected Object engineGetParameter(String param)
        {
            throw new UnsupportedOperationException();
        }
    }
}
