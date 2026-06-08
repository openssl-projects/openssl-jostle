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

package org.openssl.jostle.jcajce.provider.xec;

import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.disposal.NativeDisposer;
import org.openssl.jostle.disposal.NativeReference;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.ec.ECServiceNI;
import org.openssl.jostle.rand.DefaultRandSource;
import org.openssl.jostle.rand.RandSource;

import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

/**
 * XDH (X25519 / X448) key-agreement SPI. The OpenSSL {@code EVP_PKEY_derive}
 * flow is type-agnostic, so this reuses the EC kex bridge
 * ({@link ECServiceNI} {@code allocateKex}/{@code kexInit}/{@code kexSetPeer}/
 * {@code kexDerive}) — the C-side predicate accepts X25519 / X448 keys.
 * For Montgomery keys {@code generateSecret} returns the raw shared secret
 * (32 bytes for X25519, 56 for X448), which Java's
 * {@code KeyAgreement.generateSecret} returns verbatim.
 *
 * <p>JCE state machine: created → init(priv) → doPhase(pub, true) →
 * generateSecret. Single-phase; reusable after derive (a fresh init is
 * required because OpenSSL invalidates the ctx after derive).
 */
public class XDHKeyAgreementSpi extends KeyAgreementSpi
{
    protected static final ECServiceNI ecServiceNI = NISelector.ECServiceNI;

    private KexRef ref;
    private RandSource randSource = DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom());

    /** Pinned to keep the {@code PKEYKeySpec} reachable across native calls. */
    private Object pinnedPriv = null;

    private boolean peerSet = false;


    @Override
    protected void engineInit(Key key, SecureRandom random) throws InvalidKeyException
    {
        engineInitInternal(key, random);
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        if (params != null)
        {
            throw new InvalidAlgorithmParameterException(
                    "no parameters accepted for XDH; got " + params.getClass().getSimpleName());
        }
        engineInitInternal(key, random);
    }

    private void engineInitInternal(Key key, SecureRandom random) throws InvalidKeyException
    {
        if (random != null)
        {
            this.randSource = DefaultRandSource.replaceWith(this.randSource, random);
        }

        synchronized (this)
        {
            if (!(key instanceof JOXECPrivateKey))
            {
                throw new InvalidKeyException("XDH init: expected a Jostle-provider XDH private key");
            }

            JOXECPrivateKey privateKey = (JOXECPrivateKey) key;
            pinnedPriv = privateKey;
            peerSet = false;

            ensureRef();
            ecServiceNI.kexInit(ref.getReference(),
                    privateKey.getSpec().getReference(),
                    randSource);
        }
    }

    @Override
    protected Key engineDoPhase(Key key, boolean lastPhase)
            throws InvalidKeyException, IllegalStateException
    {
        synchronized (this)
        {
            requireInitialised();

            if (!lastPhase)
            {
                throw new IllegalStateException(
                        "XDH is a single-phase protocol; lastPhase must be true");
            }

            if (!(key instanceof JOXECPublicKey))
            {
                throw new InvalidKeyException("XDH doPhase: expected a Jostle-provider XDH public key");
            }

            JOXECPublicKey peer = (JOXECPublicKey) key;
            try
            {
                ecServiceNI.kexSetPeer(ref.getReference(),
                        peer.getSpec().getReference(),
                        randSource);
            }
            catch (RuntimeException e)
            {
                // OpenSSL rejects a type mismatch (e.g. X25519 peer against
                // an X448 local) at set_peer time. Translate so callers get
                // the expected typed exception.
                throw new InvalidKeyException(
                        "XDH doPhase: peer key rejected (type mismatch?)", e);
            }
            peerSet = true;
            return null;
        }
    }

    @Override
    protected byte[] engineGenerateSecret() throws IllegalStateException
    {
        synchronized (this)
        {
            requireInitialised();
            if (!peerSet)
            {
                throw new IllegalStateException("XDH: must call doPhase before generateSecret");
            }

            int upper = ecServiceNI.kexDerive(ref.getReference(), null, 0, randSource);
            byte[] secret = new byte[upper];
            int actual = ecServiceNI.kexDerive(ref.getReference(), secret, 0, randSource);
            if (actual == secret.length)
            {
                return secret;
            }
            byte[] trimmed = new byte[actual];
            System.arraycopy(secret, 0, trimmed, 0, actual);
            return trimmed;
        }
    }

    @Override
    protected int engineGenerateSecret(byte[] sharedSecret, int offset)
            throws IllegalStateException, ShortBufferException
    {
        synchronized (this)
        {
            requireInitialised();
            if (!peerSet)
            {
                throw new IllegalStateException("XDH: must call doPhase before generateSecret");
            }
            if (sharedSecret == null)
            {
                throw new IllegalArgumentException("output buffer is null");
            }
            if (offset < 0 || offset > sharedSecret.length)
            {
                throw new IllegalArgumentException("offset out of range");
            }

            int need = ecServiceNI.kexDerive(ref.getReference(), null, 0, randSource);
            if (sharedSecret.length - offset < need)
            {
                throw new ShortBufferException(
                        "XDH generateSecret: buffer needs " + need
                                + " bytes from offset " + offset
                                + ", have " + (sharedSecret.length - offset));
            }
            return ecServiceNI.kexDerive(ref.getReference(), sharedSecret, offset, randSource);
        }
    }

    @Override
    protected SecretKey engineGenerateSecret(String algorithm)
            throws IllegalStateException, NoSuchAlgorithmException, InvalidKeyException
    {
        if (algorithm == null || algorithm.trim().isEmpty())
        {
            throw new NoSuchAlgorithmException("algorithm name must be non-null and non-blank");
        }
        byte[] secret = engineGenerateSecret();
        try
        {
            return new SecretKeySpec(secret, algorithm);
        }
        catch (IllegalArgumentException e)
        {
            throw new NoSuchAlgorithmException("invalid algorithm name", e);
        }
    }


    private void ensureRef()
    {
        if (ref == null)
        {
            ref = new KexRef(ecServiceNI.allocateKex(), "XDH");
        }
    }

    private void requireInitialised()
    {
        if (ref == null)
        {
            throw new IllegalStateException("XDH KeyAgreement not initialised");
        }
    }


    protected static class Disposer extends NativeDisposer
    {
        Disposer(long ref)
        {
            super(ref);
        }

        @Override
        protected void dispose(long reference)
        {
            NISelector.ECServiceNI.disposeKex(reference);
        }
    }

    protected static class KexRef extends NativeReference
    {
        protected KexRef(long reference, String name)
        {
            super(reference, name);
        }

        @Override
        protected Runnable createAction()
        {
            return new Disposer(reference);
        }
    }
}
