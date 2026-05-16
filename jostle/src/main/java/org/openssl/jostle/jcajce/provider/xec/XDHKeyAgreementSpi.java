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
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
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
 * X25519 / X448 (RFC 7748) KeyAgreement SPI — the XDH equivalent of
 * {@link org.openssl.jostle.jcajce.provider.ec.ECDHKeyAgreementSpi}.
 *
 * <p>Internally this delegates to the same {@link ECServiceNI#kexInit}
 * / {@code kexSetPeer} / {@code kexDerive} entry points used for ECDH:
 * at the C level those functions operate on an {@code EVP_PKEY_CTX}
 * built via {@code EVP_PKEY_CTX_new_from_pkey} and are
 * key-type-agnostic. The only XDH-specific work is the Java-side type
 * checks (the keys must be X25519/X448, not prime-field EC).
 *
 * <p>Three registration variants:
 * <ol>
 *   <li>{@code KeyAgreement.getInstance("XDH")} — accepts either
 *       X25519 or X448 keys; the curve is inferred from the key.</li>
 *   <li>{@code KeyAgreement.getInstance("X25519")} — pinned to X25519,
 *       rejects an X448 key.</li>
 *   <li>{@code KeyAgreement.getInstance("X448")} — pinned to X448,
 *       rejects an X25519 key.</li>
 * </ol>
 */
public class XDHKeyAgreementSpi extends KeyAgreementSpi
{
    private static final ECServiceNI ecServiceNI = NISelector.ECServiceNI;

    /** Set when the transformation pins X25519 or X448. */
    private final OSSLKeyType mandatedType;

    private KexRef ref;
    private RandSource randSource = DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom());

    private Object pinnedPriv = null;
    private boolean peerSet = false;
    private OSSLKeyType activeType = null;


    /** "XDH" — curve type taken from the private key passed to init. */
    public XDHKeyAgreementSpi()
    {
        this.mandatedType = null;
    }

    /** "X25519" / "X448" — pins to one curve. */
    public XDHKeyAgreementSpi(OSSLKeyType mandatedType)
    {
        this.mandatedType = mandatedType;
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
        if (params != null)
        {
            throw new InvalidAlgorithmParameterException(
                    "no parameters accepted for XDH; got "
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
            if (!(key instanceof JOXECPrivateKey))
            {
                throw new InvalidKeyException(
                        "XDH init: expected a Jostle-provider X25519/X448 private key, got "
                                + (key == null ? "null" : key.getClass().getName()));
            }

            JOXECPrivateKey privateKey = (JOXECPrivateKey) key;
            OSSLKeyType type = privateKey.getSpec().getType();
            if (type != OSSLKeyType.X25519 && type != OSSLKeyType.X448)
            {
                throw new InvalidKeyException(
                        "XDH init: expected X25519 or X448 key spec, got " + type.getAlgorithmName());
            }
            if (mandatedType != null && mandatedType != type)
            {
                throw new InvalidKeyException(
                        "XDH init: this transformation is pinned to "
                                + mandatedType.getTypeName()
                                + " but key is " + type.getTypeName());
            }

            pinnedPriv = privateKey;
            activeType = type;
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
                throw new InvalidKeyException(
                        "XDH doPhase: expected a Jostle-provider X25519/X448 public key, got "
                                + (key == null ? "null" : key.getClass().getName()));
            }

            JOXECPublicKey peer = (JOXECPublicKey) key;
            OSSLKeyType peerType = peer.getSpec().getType();
            if (peerType != activeType)
            {
                throw new InvalidKeyException(
                        "XDH doPhase: peer curve " + peerType.getTypeName()
                                + " does not match local curve " + activeType.getTypeName());
            }

            try
            {
                ecServiceNI.kexSetPeer(ref.getReference(),
                        peer.getSpec().getReference(),
                        randSource);
            }
            catch (RuntimeException e)
            {
                throw new InvalidKeyException(
                        "XDH doPhase: peer key rejected", e);
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
                        "XDH: must call doPhase before generateSecret");
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
                throw new IllegalStateException(
                        "XDH: must call doPhase before generateSecret");
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
