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

import org.openssl.jostle.jcajce.provider.agreement.NamedSharedSecret;
import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.disposal.NativeDisposer;
import org.openssl.jostle.disposal.NativeReference;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.rand.DefaultRandSource;
import org.openssl.jostle.rand.RandSource;
import org.openssl.jostle.util.Arrays;

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
    // Instance fields, not NISelector statics (NISelector for JSL,
    // FIPSNISelector for JSLFIPS); foreign keys translate through the
    // matching KeyFactory.
    protected final ECServiceNI ecServiceNI;
    protected final ECKeyFactorySpi keyFactory;

    public ECDHKeyAgreementSpi()
    {
        this(NISelector.ECServiceNI, new ECKeyFactorySpi());
    }

    public ECDHKeyAgreementSpi(ECServiceNI ecServiceNI, ECKeyFactorySpi keyFactory)
    {
        this.ecServiceNI = ecServiceNI;
        this.keyFactory = keyFactory;
    }

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
            // Foreign EC keys (e.g. sun.security.ec.* from a certificate)
            // are translated to JSL keys; only non-EC / untranslatable keys
            // are rejected.
            JOECPrivateKey privateKey = ECKeyImport.importPrivate(keyFactory, key,
                    "ECDH init: expected an ECPrivateKey");
            pinnedPriv = privateKey;
            peerSet = false;

            ensureRef();
            try
            {
                ecServiceNI.kexInit(ref.getReference(),
                        privateKey.getSpec().getReference(),
                        randSource);
            }
            catch (org.openssl.jostle.jcajce.provider.ProviderCapabilityException e)
            {
                // Carry the capability message verbatim.
                throw (InvalidKeyException) new InvalidKeyException(e.getMessage()).initCause(e);
            }
            catch (org.openssl.jostle.jcajce.provider.OpenSSLException e)
            {
                // InvalidKeyException is the JCE-canonical init failure and the
                // provider-fallback trigger. State what was refused, not why.
                throw (InvalidKeyException) new InvalidKeyException(
                        "ECDH init: the provider refused this private key: "
                                + e.getMessage()).initCause(e);
            }
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

            JOECPublicKey peer = ECKeyImport.importPublic(keyFactory, key,
                    "ECDH doPhase: expected an ECPublicKey");
            // Pin the (possibly KeyFactory-translated) peer so its native
            // EVP_PKEY cannot be GC-disposed during the set-peer call — the
            // translated key is otherwise method-local with no later use.
            pinnedPeer = peer;
            try
            {
                // randSource needed for binary-field curves —
                // EVP_PKEY_derive_set_peer triggers an internal
                // EVP_PKEY_public_check that consumes RAND.
                ecServiceNI.kexSetPeer(ref.getReference(),
                        peer.getSpec().getReference(),
                        randSource);
            }
            catch (IllegalStateException e)
            {
                // A not-initialised state error (e.g. a prior engineInit
                // failed at kexInit, leaving the derive ctx unset) is a
                // state problem, not a key problem — doPhase declares
                // IllegalStateException for exactly this case, so surface
                // it unchanged rather than mislabelling it as a curve
                // mismatch.
                throw e;
            }
            catch (org.openssl.jostle.jcajce.provider.ProviderCapabilityException e)
            {
                throw (InvalidKeyException) new InvalidKeyException(e.getMessage()).initCause(e);
            }
            catch (RuntimeException e)
            {
                // InvalidKeyException, as BC. The message states what was
                // refused, not why.
                throw new InvalidKeyException(
                        "ECDH doPhase: the provider refused the peer key: "
                                + e.getMessage(), e);
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
                // D5 (Megan, 2026-09-13): BC returns null here; we match it,
                // against the JCE contract. Pinned in ExceptionTypeDivergencePinTest.
                return null;
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
                // D5, as above: BC raises a raw NullPointerException here, not
                // ShortBufferException. Pinned in ExceptionTypeDivergencePinTest.
                throw new NullPointerException(
                        "ECDH generateSecret: doPhase has not been called");
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
        // The named algorithm fixes the key length; the secret is sized
        // to it, not labelled with it.
        byte[] secret = engineGenerateSecret();
        if (secret == null)
        {
            // D5, as above: BC raises a raw NullPointerException here. The
            // TYPE is the parity; the message is ours.
            throw new NullPointerException(
                    "ECDH generateSecret: doPhase has not been called");
        }
        try
        {
            return NamedSharedSecret.fromSharedSecret(secret, algorithm);
        }
        catch (IllegalArgumentException e)
        {
            throw new NoSuchAlgorithmException("invalid algorithm name", e);
        }
        finally
        {
            // SecretKeySpec copied the bytes — scrub our working copy
            // (DHKeyAgreementSpi precedent).
            Arrays.clear(secret);
        }
    }


    private void ensureRef()
    {
        if (ref == null)
        {
            ref = new KexRef(ecServiceNI, ecServiceNI.allocateKex(), "ECDH");
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
        private final ECServiceNI ecServiceNI;

        Disposer(ECServiceNI ecServiceNI, long ref)
        {
            super(ref);
            this.ecServiceNI = ecServiceNI;
        }

        @Override
        protected void dispose(long reference)
        {
            ecServiceNI.disposeKex(reference);
        }
    }

    protected static class KexRef extends NativeReference
    {

        protected KexRef(ECServiceNI ecServiceNI, long reference, String name)
        {
            super(reference, name, new Disposer(ecServiceNI, reference));
        }

    }
}
