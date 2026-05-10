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

package org.openssl.jostle.jcajce.provider.ec;

import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.disposal.NativeDisposer;
import org.openssl.jostle.disposal.NativeReference;
import org.openssl.jostle.jcajce.provider.NISelector;
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
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;

/**
 * ECDH key-agreement SPI. Wraps OpenSSL's {@code EVP_PKEY_derive} flow:
 * {@code init(privKey)} binds the local private key,
 * {@code doPhase(pubKey, true)} sets the peer, and {@code generateSecret}
 * returns the affine X coordinate of the shared point as big-endian
 * unsigned magnitude (SEC 1 / ANSI X9.63), padded to the curve byte
 * length.
 *
 * <p>JCE state-machine contract:
 * <ol>
 *   <li>created → init: {@link #engineInit} pins the local private key
 *       and creates the native derive context.</li>
 *   <li>init → doPhase: {@link #engineDoPhase} sets the peer; the
 *       {@code lastPhase} flag MUST be {@code true} (ECDH is single-phase).</li>
 *   <li>doPhase → generateSecret: derives and returns the shared secret;
 *       the SPI is reusable post-derive (a fresh
 *       {@code init} is required because OpenSSL invalidates the ctx
 *       after derive).</li>
 * </ol>
 *
 * <p>Like the verify path of {@link ECDSASignatureSpi}, derive consumes
 * RAND for point blinding (a side-channel mitigation built into
 * OpenSSL's EC implementation), so a {@link RandSource} is plumbed
 * through {@code init} and {@code generateSecret}.
 */
public class ECDHKeyAgreementSpi extends KeyAgreementSpi
{
    protected static final ECServiceNI ecServiceNI = NISelector.ECServiceNI;

    private KexRef ref;
    private RandSource randSource = DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom());

    /**
     * Pinned to keep the underlying {@code PKEYKeySpec} reachable across
     * native calls — its native handle is what {@code kexInit} captured,
     * and a GC-driven disposer running mid-call would invalidate the
     * derive ctx.
     */
    private Object pinnedPriv = null;

    /**
     * Whether {@code engineDoPhase} has installed a peer public key.
     * {@code engineGenerateSecret} returns
     * {@link IllegalStateException} otherwise — without this guard the
     * native call would surface as a generic OpenSSL error.
     */
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
        // Plain ECDH ignores AlgorithmParameterSpec; specs other than
        // null are reserved for future ECDH-with-KDF variants.
        if (params != null)
        {
            throw new InvalidAlgorithmParameterException(
                    "no parameters accepted for ECDH; got "
                            + params.getClass().getSimpleName());
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
            if (!(key instanceof ECPrivateKey))
            {
                throw new InvalidKeyException("ECDH init: expected an ECPrivateKey");
            }
            if (!(key instanceof JOECPrivateKey))
            {
                throw new InvalidKeyException("ECDH init: expected a Jostle-provider ECPrivateKey");
            }

            JOECPrivateKey privateKey = (JOECPrivateKey) key;
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
                // ECDH is a single-phase protocol; multi-phase variants
                // (ECMQV etc.) are out of scope for the bare "ECDH"
                // KeyAgreement.
                throw new IllegalStateException(
                        "ECDH is a single-phase protocol; lastPhase must be true");
            }

            if (!(key instanceof ECPublicKey))
            {
                throw new InvalidKeyException("ECDH doPhase: expected an ECPublicKey");
            }
            if (!(key instanceof JOECPublicKey))
            {
                throw new InvalidKeyException("ECDH doPhase: expected a Jostle-provider ECPublicKey");
            }

            JOECPublicKey peer = (JOECPublicKey) key;
            try
            {
                // randSource needed for binary-field curves —
                // EVP_PKEY_derive_set_peer triggers an internal
                // EVP_PKEY_public_check that consumes RAND.
                ecServiceNI.kexSetPeer(ref.getReference(),
                        peer.getSpec().getReference(),
                        randSource);
            }
            catch (RuntimeException e)
            {
                // OpenSSL rejects mismatched curves at set_peer time.
                // Translate so JCE callers get the expected typed
                // exception rather than a provider-specific runtime.
                throw new InvalidKeyException(
                        "ECDH doPhase: peer key rejected (curve mismatch?)", e);
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
                throw new IllegalStateException(
                        "ECDH: must call doPhase before generateSecret");
            }

            int upper = ecServiceNI.kexDerive(ref.getReference(), null, 0, randSource);
            byte[] secret = new byte[upper];
            int actual = ecServiceNI.kexDerive(ref.getReference(), secret, 0, randSource);
            if (actual == secret.length)
            {
                return secret;
            }
            // EVP_PKEY_derive may return slightly fewer bytes than the
            // upper bound for some providers — trim defensively.
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
                throw new IllegalStateException(
                        "ECDH: must call doPhase before generateSecret");
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
                        "ECDH generateSecret: buffer needs " + need
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
        // Reject null / empty / whitespace-only algorithm names up
        // front. SecretKeySpec rejects null and empty internally but
        // accepts a string of just spaces and produces a SecretKey
        // with that as the algorithm name — almost certainly not what
        // the caller meant, and most JCE consumers would reject it
        // downstream with a less useful exception.
        if (algorithm == null || algorithm.trim().isEmpty())
        {
            throw new NoSuchAlgorithmException(
                    "algorithm name must be non-null and non-blank");
        }
        // Wrap the raw shared secret as a SecretKeySpec under the
        // requested algorithm name. Callers wanting a KDF-derived key
        // should run the bytes through a separate KDF SPI.
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
            ref = new KexRef(ecServiceNI.allocateKex(), "ECDH");
        }
    }

    private void requireInitialised()
    {
        if (ref == null)
        {
            throw new IllegalStateException("ECDH KeyAgreement not initialised");
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
