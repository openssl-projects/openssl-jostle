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

package org.openssl.jostle.jcajce.provider.rsa;

import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.disposal.NativeDisposer;
import org.openssl.jostle.disposal.NativeReference;
import org.openssl.jostle.jcajce.interfaces.RSAKey;
import org.openssl.jostle.jcajce.interfaces.RSAPrivateKey;
import org.openssl.jostle.jcajce.interfaces.RSAPublicKey;
import org.openssl.jostle.jcajce.provider.AsymmetricKeyImpl;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.rand.DefaultRandSource;
import org.openssl.jostle.rand.RandSource;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.SignatureSpi;

/**
 * Common machinery for both PKCS#1 v1.5 and PSS RSA Signature SPI
 * classes. Holds the native-context lifecycle, key validation, and
 * the streaming update / sign / verify glue. Concrete subclasses
 * supply the digest name and the padding-mode descriptor that drives
 * native init.
 */
abstract class RSASignatureSpiBase extends SignatureSpi
{
    // Instance field, not a NISelector static: the SPI is bound to whichever
    // NI backend its provider passes in (NISelector for JSL, FIPSNISelector
    // for JSLFIPS).
    protected final RSAServiceNI rsaServiceNI;
    // Foreign keys translate (and other-provider Jostle keys are rejected)
    // through the matching KeyFactory.
    protected final RSAKeyFactorySpi keyFactory;

    private RSARef ref;
    private RandSource randSource = DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom());
    private RSAKey lastKey = null;


    /**
     * Concrete sign-init: subclass supplies digest name + padding +
     * optional PSS params. NULL mgf1 is honoured at the native layer
     * by defaulting to the signing hash; salt_len &lt; 0 means "use
     * digest output length".
     */
    protected RSASignatureSpiBase()
    {
        this(NISelector.RSAServiceNI, new RSAKeyFactorySpi());
    }

    protected RSASignatureSpiBase(RSAServiceNI rsaServiceNI, RSAKeyFactorySpi keyFactory)
    {
        this.rsaServiceNI = rsaServiceNI;
        this.keyFactory = keyFactory;
    }

    protected abstract void nativeInitSign(long ref, long keyRef, RandSource rnd);

    protected abstract void nativeInitVerify(long ref, long keyRef);


    // Foreign-key translation lives in RSAKeyImport (shared with the Cipher
    // SPIs); see RSAKeyImport.importPublic / importPrivate.


    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException
    {
        synchronized (this)
        {
            JORSAPublicKey key = RSAKeyImport.importPublic(keyFactory, publicKey);
            lastKey = key;
            initVerifyInternal(key);
        }
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException
    {
        engineInitSign(privateKey, CryptoServicesRegistrar.getSecureRandom());
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey, SecureRandom secureRandom) throws InvalidKeyException
    {
        this.randSource = DefaultRandSource.replaceWith(this.randSource, secureRandom);

        synchronized (this)
        {
            JORSAPrivateKey key = RSAKeyImport.importPrivate(keyFactory, privateKey);
            lastKey = key;
            initSignInternal(key);
        }
    }

    /**
     * Bind an already-imported private key for signing using the SPI's
     * current {@code randSource}. Separated from {@link #engineInitSign}
     * so {@link #reInit} can re-bind after a terminal op WITHOUT replacing
     * the caller-supplied SecureRandom (which {@code engineInitSign(key,
     * random)} would do via {@code replaceWith}).
     */
    private void initSignInternal(JORSAPrivateKey key)
    {
        ensureRef(key.getAlgorithm());
        nativeInitSign(ref.getReference(), key.getSpec().getReference(), randSource);
    }

    /** Verify-side counterpart to {@link #initSignInternal}. */
    private void initVerifyInternal(JORSAPublicKey key)
    {
        ensureRef(key.getAlgorithm());
        nativeInitVerify(ref.getReference(), key.getSpec().getReference());
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException
    {
        engineUpdate(new byte[]{b}, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException
    {
        synchronized (this)
        {
            requireInitialised();
            rsaServiceNI.update(ref.getReference(), b, off, len);
        }
    }

    @Override
    protected byte[] engineSign() throws SignatureException
    {
        synchronized (this)
        {
            requireInitialised();
            try
            {
                long len = rsaServiceNI.sign(ref.getReference(), null, 0, randSource);
                byte[] sig = new byte[(int) len];
                rsaServiceNI.sign(ref.getReference(), sig, 0, randSource);
                return sig;
            }
            finally
            {
                reInit();
            }
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException
    {
        synchronized (this)
        {
            requireInitialised();
            try
            {
                int code = rsaServiceNI.verify(
                        ref.getReference(),
                        sigBytes,
                        sigBytes != null ? sigBytes.length : 0);
                return code == ErrorCode.JO_SUCCESS.getCode();
            }
            finally
            {
                reInit();
            }
        }
    }

    @Override
    protected void engineSetParameter(String param, Object value)
    {
        throw new UnsupportedOperationException();
    }

    @Override
    protected Object engineGetParameter(String param)
    {
        throw new UnsupportedOperationException();
    }


    /**
     * Allocate the native rsa_ctx if we haven't yet. Subclasses
     * also call this before reInit-driven re-initialisation.
     */
    private void ensureRef(String algorithmName)
    {
        if (ref == null)
        {
            ref = new RSARef(rsaServiceNI, rsaServiceNI.allocateSigner(), algorithmName);
        }
    }

    /**
     * JCE convention is {@link IllegalStateException} for pre-init
     * misuse. Without this guard the entry points below would throw
     * NullPointerException on the first {@code ref.getReference()}
     * access — a leaky abstraction that makes pre-init misuse hard
     * to distinguish from native-layer failures.
     */
    private void requireInitialised()
    {
        if (ref == null)
        {
            throw new IllegalStateException("signature not initialised");
        }
    }

    /**
     * Re-initialise after a sign or verify so the next streaming
     * update starts fresh against the same key. Re-binds via the
     * {@code *Internal} helpers so the caller-supplied {@code randSource}
     * survives — re-entering {@code engineInitSign(key)} here would
     * silently swap it for the project default. Subclasses can
     * override if they need to re-apply parameters in addition to
     * restoring key state.
     */
    private void reInit()
    {
        try
        {
            if (lastKey instanceof JORSAPublicKey)
            {
                initVerifyInternal((JORSAPublicKey) lastKey);
            }
            else if (lastKey instanceof JORSAPrivateKey)
            {
                initSignInternal((JORSAPrivateKey) lastKey);
            }
            // No key set yet — nothing to do.
        }
        catch (Exception e)
        {
            throw new java.security.ProviderException("unable to reinitialise RSA signature engine", e);
        }
    }


    protected static class Disposer extends NativeDisposer
    {
        // The NI that allocated the signer frees it - a FIPS-allocated
        // signer must be disposed through the FIPS interface library.
        private final RSAServiceNI rsaServiceNI;

        Disposer(RSAServiceNI rsaServiceNI, long ref)
        {
            super(ref);
            this.rsaServiceNI = rsaServiceNI;
        }

        @Override
        protected void dispose(long reference)
        {
            rsaServiceNI.disposeSigner(reference);
        }
    }

    protected static class RSARef extends NativeReference
    {

        protected RSARef(RSAServiceNI rsaServiceNI, long reference, String name)
        {
            super(reference, name, new Disposer(rsaServiceNI, reference));
        }

    }
}
