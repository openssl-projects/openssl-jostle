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

import org.openssl.jostle.jcajce.provider.agreement.NamedSharedSecret;
import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.disposal.NativeDisposer;
import org.openssl.jostle.disposal.NativeReference;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.ec.ECServiceNI;
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
 * XDH (X25519 / X448) key-agreement SPI. The OpenSSL {@code EVP_PKEY_derive}
 * flow is type-agnostic, so this reuses the EC kex bridge
 * ({@link ECServiceNI} {@code allocateKex}/{@code kexInit}/{@code kexSetPeer}/
 * {@code kexDerive}) — the C-side predicate accepts X25519 / X448 keys.
 * For Montgomery keys {@code generateSecret} returns the raw shared secret
 * (32 bytes for X25519, 56 for X448), which Java's
 * {@code KeyAgreement.generateSecret} returns verbatim.
 *
 * <p>JCE state machine: created → init(priv) → doPhase(pub, true) →
 * generateSecret. Single-phase and reusable: the private-key init state
 * persists across {@code generateSecret} (per the JCA contract), so the
 * instance may be driven again through {@code doPhase} with a new peer
 * without re-initialising, or re-initialised with a fresh private key via
 * {@code init}.
 */
public class XDHKeyAgreementSpi extends KeyAgreementSpi
{
    // Instance fields, not NISelector statics (NISelector for JSL,
    // FIPSNISelector for JSLFIPS); foreign keys translate through the
    // matching KeyFactory.
    protected final ECServiceNI ecServiceNI;
    protected final XECKeyFactorySpi keyFactory;

    public XDHKeyAgreementSpi()
    {
        this(NISelector.ECServiceNI, new XECKeyFactorySpi());
    }

    public XDHKeyAgreementSpi(ECServiceNI ecServiceNI, XECKeyFactorySpi keyFactory)
    {
        this.ecServiceNI = ecServiceNI;
        this.keyFactory = keyFactory;
    }

    private KexRef ref;
    private RandSource randSource = DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom());

    /** Pinned to keep the {@code PKEYKeySpec} reachable across native calls. */
    private Object pinnedPriv = null;
    private Object pinnedPeer = null;

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
            // Foreign XDH keys (e.g. the JDK's XDH KeyFactory or a
            // certificate) are translated to JSL keys; only non-XDH /
            // untranslatable keys are rejected.
            JOXECPrivateKey privateKey = XDHKeyImport.importPrivate(keyFactory, key,
                    "XDH init: expected an XDH private key");
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
            catch (RuntimeException e)
            {
                // InvalidKeyException is the JCE-canonical init failure and the
                // provider-fallback trigger. State what was refused, not why.
                throw new InvalidKeyException(
                        "XDH init: the provider refused this private key: "
                                + e.getMessage(), e);
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
                throw new IllegalStateException(
                        "XDH is a single-phase protocol; lastPhase must be true");
            }

            JOXECPublicKey peer = XDHKeyImport.importPublic(keyFactory, key,
                    "XDH doPhase: expected an XDH public key");
            // Pin the (possibly KeyFactory-translated) peer so its native
            // EVP_PKEY cannot be GC-disposed during the set-peer call — the
            // translated key is otherwise method-local with no later use.
            pinnedPeer = peer;
            try
            {
                ecServiceNI.kexSetPeer(ref.getReference(),
                        peer.getSpec().getReference(),
                        randSource);
            }
            catch (IllegalStateException e)
            {
                // A not-initialised state error (e.g. a prior engineInit
                // failed at kexInit, leaving the derive ctx unset) is a state
                // problem, not a key problem — doPhase declares
                // IllegalStateException for exactly this case, so surface it
                // unchanged rather than mislabelling it as a type mismatch.
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
                        "XDH doPhase: the provider refused the peer key: "
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
            // Defensive: the oversized buffer still holds the full secret;
            // copy out the trimmed portion and scrub the original.
            byte[] trimmed = new byte[actual];
            System.arraycopy(secret, 0, trimmed, 0, actual);
            Arrays.clear(secret);
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
                        "XDH generateSecret: doPhase has not been called");
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
        if (secret == null)
        {
            // D5, as above: BC raises a raw NullPointerException here. The
            // TYPE is the parity; the message is ours.
            throw new NullPointerException(
                    "XDH generateSecret: doPhase has not been called");
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
            // (ECDHKeyAgreementSpi precedent).
            Arrays.clear(secret);
        }
    }


    private void ensureRef()
    {
        if (ref == null)
        {
            ref = new KexRef(ecServiceNI, ecServiceNI.allocateKex(), "XDH");
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
