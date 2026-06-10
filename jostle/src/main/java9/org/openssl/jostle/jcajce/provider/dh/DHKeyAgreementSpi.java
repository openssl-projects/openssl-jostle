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

package org.openssl.jostle.jcajce.provider.dh;

import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.disposal.NativeDisposer;
import org.openssl.jostle.disposal.NativeReference;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.rand.DefaultRandSource;
import org.openssl.jostle.rand.RandSource;

import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.SecretKeySpec;
import java.lang.ref.Reference;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

/**
 * Finite-field Diffie-Hellman key-agreement SPI. The shared secret is
 * left-padded to the prime length — see the Java 8 baseline copy and
 * {@code dh_kex_init} in {@code interface/util/dh.c}.
 *
 * <p>Java 9+ override of the Java 8 baseline. Uses
 * {@link Reference#reachabilityFence} to keep this SPI instance
 * reachable across native calls, replacing the {@code synchronized(this)}
 * idiom used in the baseline.
 */
public class DHKeyAgreementSpi extends KeyAgreementSpi
{
    protected static final DHServiceNI dhServiceNI = NISelector.DHServiceNI;

    private KexRef ref;
    private RandSource randSource = DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom());

    /**
     * Pinned to keep the underlying {@code PKEYKeySpec} reachable across
     * native calls — its native handle is what {@code kexInit} captured,
     * and a GC-driven disposer running mid-call would invalidate the
     * derive ctx.
     */
    private Object pinnedPriv = null;
    private Object pinnedPeer = null;

    /**
     * Whether {@code engineDoPhase} has installed a peer public key.
     */
    private boolean peerSet = false;


    /** Coerce an arbitrary private key to a JSL DH private key. */
    private static JODHPrivateKey importPrivate(Key key) throws InvalidKeyException
    {
        if (key instanceof JODHPrivateKey)
        {
            return (JODHPrivateKey) key;
        }
        if (key instanceof DHPrivateKey)
        {
            Key translated = new DHKeyFactorySpi().engineTranslateKey(key);
            if (translated instanceof JODHPrivateKey)
            {
                return (JODHPrivateKey) translated;
            }
        }
        throw new InvalidKeyException("DH init: expected a DHPrivateKey");
    }

    /** Coerce an arbitrary public key to a JSL DH public key. */
    private static JODHPublicKey importPublic(Key key) throws InvalidKeyException
    {
        if (key instanceof JODHPublicKey)
        {
            return (JODHPublicKey) key;
        }
        if (key instanceof DHPublicKey)
        {
            Key translated = new DHKeyFactorySpi().engineTranslateKey(key);
            if (translated instanceof JODHPublicKey)
            {
                return (JODHPublicKey) translated;
            }
        }
        throw new InvalidKeyException("DH doPhase: expected a DHPublicKey");
    }


    @Override
    protected void engineInit(Key key, SecureRandom random) throws InvalidKeyException
    {
        engineInitInternal(key, random);
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        // Plain DH ignores AlgorithmParameterSpec; specs other than
        // null are reserved for future DH-with-KDF variants.
        if (params != null)
        {
            throw new InvalidAlgorithmParameterException(
                    "no parameters accepted for DH; got "
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

        try
        {
            JODHPrivateKey privateKey = importPrivate(key);
            pinnedPriv = privateKey;
            peerSet = false;

            ensureRef();
            dhServiceNI.kexInit(ref.getReference(),
                    privateKey.getSpec().getReference(),
                    randSource);
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }

    @Override
    protected Key engineDoPhase(Key key, boolean lastPhase)
            throws InvalidKeyException, IllegalStateException
    {
        requireInitialised();

        if (!lastPhase)
        {
            // The bare "DH" KeyAgreement is single-phase; multi-party
            // DH (doPhase chaining) is out of scope.
            throw new IllegalStateException(
                    "DH is a single-phase protocol here; lastPhase must be true");
        }

        JODHPublicKey peer = importPublic(key);
        // Pin the (possibly KeyFactory-translated) peer so its native
        // EVP_PKEY cannot be GC-disposed during the set-peer call — the
        // translated key is otherwise method-local with no later use.
        pinnedPeer = peer;
        try
        {
            dhServiceNI.kexSetPeer(ref.getReference(),
                    peer.getSpec().getReference(),
                    randSource);
        }
        catch (RuntimeException e)
        {
            // OpenSSL rejects mismatched groups at set_peer time.
            // Translate so JCE callers get the expected typed
            // exception rather than a provider-specific runtime.
            throw new InvalidKeyException(
                    "DH doPhase: peer key rejected (group mismatch?)", e);
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
        peerSet = true;
        return null;
    }

    @Override
    protected byte[] engineGenerateSecret() throws IllegalStateException
    {
        requireInitialised();
        if (!peerSet)
        {
            throw new IllegalStateException(
                    "DH: must call doPhase before generateSecret");
        }

        try
        {
            int upper = dhServiceNI.kexDerive(ref.getReference(), null, 0, randSource);
            byte[] secret = new byte[upper];
            int actual = dhServiceNI.kexDerive(ref.getReference(), secret, 0, randSource);
            if (actual == secret.length)
            {
                return secret;
            }
            // With the pad exchange parameter set the output is always
            // exactly the prime length, but trim defensively in case a
            // provider returns fewer bytes than the probe reported.
            byte[] trimmed = new byte[actual];
            System.arraycopy(secret, 0, trimmed, 0, actual);
            return trimmed;
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }

    @Override
    protected int engineGenerateSecret(byte[] sharedSecret, int offset)
            throws IllegalStateException, ShortBufferException
    {
        requireInitialised();
        if (!peerSet)
        {
            throw new IllegalStateException(
                    "DH: must call doPhase before generateSecret");
        }
        if (sharedSecret == null)
        {
            throw new IllegalArgumentException("output buffer is null");
        }
        if (offset < 0 || offset > sharedSecret.length)
        {
            throw new IllegalArgumentException("offset out of range");
        }

        try
        {
            int need = dhServiceNI.kexDerive(ref.getReference(), null, 0, randSource);
            if (sharedSecret.length - offset < need)
            {
                throw new ShortBufferException(
                        "DH generateSecret: buffer needs " + need
                                + " bytes from offset " + offset
                                + ", have " + (sharedSecret.length - offset));
            }
            return dhServiceNI.kexDerive(ref.getReference(), sharedSecret, offset, randSource);
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }

    @Override
    protected SecretKey engineGenerateSecret(String algorithm)
            throws IllegalStateException, NoSuchAlgorithmException, InvalidKeyException
    {
        // Reject null / empty / whitespace-only algorithm names up
        // front (ECDHKeyAgreementSpi rationale).
        if (algorithm == null || algorithm.trim().isEmpty())
        {
            throw new NoSuchAlgorithmException(
                    "algorithm name must be non-null and non-blank");
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
            ref = new KexRef(dhServiceNI.allocateKex(), "DH");
        }
    }

    private void requireInitialised()
    {
        if (ref == null)
        {
            throw new IllegalStateException("DH KeyAgreement not initialised");
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
            NISelector.DHServiceNI.disposeKex(reference);
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
