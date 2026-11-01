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

package org.openssl.jostle.test.cert;

import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A test-only provider serving Signature for the named algorithms by delegating to another provider INSTANCE,
 * and counting the verifications started through it. Installed at position 1, a non-zero count means a
 * Signature was resolved by JCA search order; zero means the caller's provider was used.
 */
public final class RecordingSignatureProvider
    extends Provider
{
    public static final String NAME = "JostleTestRecorder";

    private final AtomicInteger verifications = new AtomicInteger();

    public RecordingSignatureProvider(Provider delegate, String... algorithms)
    {
        super(NAME, 1.0, "records Signature resolution by search order");
        for (String algorithm : algorithms)
        {
            putService(new RecordingService(this, algorithm, delegate));
        }
    }

    /** The number of initVerify calls made on Signatures this provider served. */
    public int verifications()
    {
        return verifications.get();
    }

    private static final class RecordingService
        extends Service
    {
        private final RecordingSignatureProvider recorder;
        private final Provider delegate;

        RecordingService(RecordingSignatureProvider recorder, String algorithm, Provider delegate)
        {
            super(recorder, "Signature", algorithm, RecordingSignature.class.getName(), null, null);
            this.recorder = recorder;
            this.delegate = delegate;
        }

        @Override
        public Object newInstance(Object constructorParameter)
            throws NoSuchAlgorithmException
        {
            return new RecordingSignature(getAlgorithm(), Signature.getInstance(getAlgorithm(), delegate),
                    recorder.verifications);
        }
    }

    /** A Signature subclass, so the JCA uses it directly and its methods reach the delegate's public API. */
    private static final class RecordingSignature
        extends Signature
    {
        private final Signature inner;
        private final AtomicInteger verifications;

        RecordingSignature(String algorithm, Signature inner, AtomicInteger verifications)
        {
            super(algorithm);
            this.inner = inner;
            this.verifications = verifications;
        }

        @Override
        protected void engineInitVerify(PublicKey publicKey)
            throws InvalidKeyException
        {
            verifications.incrementAndGet();
            inner.initVerify(publicKey);
        }

        @Override
        protected void engineInitSign(PrivateKey privateKey)
            throws InvalidKeyException
        {
            inner.initSign(privateKey);
        }

        @Override
        protected void engineUpdate(byte b)
            throws SignatureException
        {
            inner.update(b);
        }

        @Override
        protected void engineUpdate(byte[] b, int off, int len)
            throws SignatureException
        {
            inner.update(b, off, len);
        }

        @Override
        protected byte[] engineSign()
            throws SignatureException
        {
            return inner.sign();
        }

        @Override
        protected boolean engineVerify(byte[] sigBytes)
            throws SignatureException
        {
            return inner.verify(sigBytes);
        }

        @Override
        protected void engineSetParameter(AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException
        {
            inner.setParameter(params);
        }

        @Override
        @SuppressWarnings("deprecation")
        protected void engineSetParameter(String param, Object value)
        {
            throw new InvalidParameterException("not supported by the recorder");
        }

        @Override
        @SuppressWarnings("deprecation")
        protected Object engineGetParameter(String param)
        {
            throw new InvalidParameterException("not supported by the recorder");
        }
    }
}
