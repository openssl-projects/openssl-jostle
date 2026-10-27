/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.slhdsa;

import java.security.AlgorithmParameters;
import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.disposal.NativeDisposer;
import org.openssl.jostle.disposal.NativeReference;
import org.openssl.jostle.jcajce.interfaces.SLHDSAKey;
import org.openssl.jostle.jcajce.interfaces.SLHDSAPrivateKey;
import org.openssl.jostle.jcajce.interfaces.SLHDSAPublicKey;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.spec.ContextParameterSpec;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.SLHDSAParameterSpec;
import org.openssl.jostle.rand.DefaultRandSource;
import org.openssl.jostle.rand.RandSource;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;


public class SLHDSASignatureSpi extends SignatureSpi
{

    public enum MessageEncoding
    {
        // Passed by ordinal
        NONE,
        PURE
    }

    public enum Deterministic
    {
        // Passed by ordinal
        NON_DETERMINISTIC,
        DETERMINISTIC
    }


    private final OSSLKeyType forcedType;
    private SLHDSARef ref = null;
    private SLHDSAKey lastKey = null;

    private AlgorithmParameterSpec algorithmParameterSpec = null;
    private boolean updateCalled = false;
    private MessageEncoding messageEncoding = MessageEncoding.PURE;
    private Deterministic deterministic = Deterministic.NON_DETERMINISTIC;
    private RandSource randSource = DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom());

    // Instance field, not a NISelector static (NISelector for JSL,
    // FIPSNISelector for JSLFIPS).
    private final SLHDSAServiceNI slhdsaServiceNI;

    // Bound to the same interface library as slhdsaServiceNI: translates a foreign key and rejects one made by
    // another Jostle provider instance.
    private final SLHDSAKeyFactorySpi keyFactory;

    public SLHDSASignatureSpi(OSSLKeyType forcedType, MessageEncoding messageEncoding, Deterministic deterministic)
    {
        this(NISelector.SLHDSAServiceNI, new SLHDSAKeyFactorySpi(OSSLKeyType.NONE), forcedType, messageEncoding,
                deterministic);
    }

    public SLHDSASignatureSpi(SLHDSAServiceNI slhdsaServiceNI, SLHDSAKeyFactorySpi keyFactory, OSSLKeyType forcedType,
                              MessageEncoding messageEncoding, Deterministic deterministic)
    {
        this.slhdsaServiceNI = slhdsaServiceNI;
        this.keyFactory = keyFactory;
        this.forcedType = forcedType;
        algorithmParameterSpec = ContextParameterSpec.EMPTY_CONTEXT_SPEC;
        this.messageEncoding = messageEncoding;
        this.deterministic = deterministic;
    }

    public SLHDSASignatureSpi()
    {
        this(OSSLKeyType.NONE, MessageEncoding.PURE, Deterministic.NON_DETERMINISTIC);
    }

    public SLHDSASignatureSpi(MessageEncoding encoding, Deterministic deterministic)
    {
        this(OSSLKeyType.NONE, encoding, deterministic);
    }

    public SLHDSASignatureSpi(OSSLKeyType keyType)
    {
        this(keyType, MessageEncoding.PURE, Deterministic.NON_DETERMINISTIC);
    }


    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException
    {
        SLHDSAPublicKey key = importPublicKey(publicKey);
        synchronized (this)
        {
            updateCalled = false;

            if (forcedType != OSSLKeyType.NONE && forcedType != key.getSpec().getType())
            {
                throw new InvalidKeyException("required " + SLHDSAParameterSpec.getSpecForOSSLType(forcedType).getName()
                        + " key type but got "
                        + SLHDSAParameterSpec.getSpecForOSSLType(key.getSpec().getType()).getName());
            }

            // Assigned only after the type check, so a refused init leaves the previous key for reInit.
            lastKey = key;

            if (ref == null)
            {
                ref = new SLHDSARef(slhdsaServiceNI, slhdsaServiceNI.allocateSigner(), key.getAlgorithm());
            }

            byte[] context = null;
            int contextLen = 0;

            if (algorithmParameterSpec instanceof ContextParameterSpec)
            {
                context = ((ContextParameterSpec) algorithmParameterSpec).getContext();
                contextLen = context.length;
            }

            try
            {
                slhdsaServiceNI.initVerify(ref.getReference(), key.getSpec().getReference(), context, contextLen,
                        messageEncoding.ordinal(), deterministic.ordinal());
            }
            catch (IllegalArgumentException e)
            {
                // The JCA init contract is InvalidKeyException, which also triggers provider fallback.
                throw new InvalidKeyException(e.getMessage(), e);
            }
        }
    }

    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException
    {
        engineInitSign(privateKey, null);
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey, SecureRandom random) throws InvalidKeyException
    {
        this.randSource = DefaultRandSource.replaceWith(this.randSource, random);
        SLHDSAPrivateKey key = importPrivateKey(privateKey);
        synchronized (this)
        {
            updateCalled = false;

            if (forcedType != OSSLKeyType.NONE && forcedType != key.getSpec().getType())
            {
                throw new InvalidKeyException("required " + SLHDSAParameterSpec.getSpecForOSSLType(forcedType).getName()
                        + " key type but got "
                        + SLHDSAParameterSpec.getSpecForOSSLType(key.getSpec().getType()).getName());
            }

            // Assigned only after the type check (see engineInitVerify).
            lastKey = key;

            if (ref == null)
            {
                ref = new SLHDSARef(slhdsaServiceNI, slhdsaServiceNI.allocateSigner(), key.getAlgorithm());
            }

            byte[] context = null;
            int contextLen = 0;

            if (algorithmParameterSpec instanceof ContextParameterSpec)
            {
                context = ((ContextParameterSpec) algorithmParameterSpec).getContext();
                contextLen = context.length;
            }

            try
            {
                slhdsaServiceNI.initSign(
                        ref.getReference(),
                        key.getSpec().getReference(),
                        context, contextLen, messageEncoding.ordinal(), deterministic.ordinal(),
                        randSource);
            }
            catch (IllegalArgumentException e)
            {
                // See engineInitVerify.
                throw new InvalidKeyException(e.getMessage(), e);
            }
        }
    }

    /**
     * A Jostle SLH-DSA public key of this provider instance passes; any other SLH-DSA key is re-encoded and decoded
     * through the bound KeyFactory, so the native key is ours.
     */
    private SLHDSAPublicKey importPublicKey(PublicKey publicKey) throws InvalidKeyException
    {
        if (publicKey instanceof SLHDSAPublicKey)
        {
            SLHDSAPublicKey joKey = (SLHDSAPublicKey) publicKey;
            if (!joKey.getSpec().usableBy(keyFactory.ownProviderInstance()))
            {
                throw new InvalidKeyException(
                        "public key was created by a different Jostle provider instance; "
                                + "encode it with getEncoded() and decode it through this "
                                + "provider's KeyFactory");
            }
            return joKey;
        }
        Key translated = keyFactory.engineTranslateKey(publicKey);
        if (translated instanceof SLHDSAPublicKey)
        {
            return (SLHDSAPublicKey) translated;
        }
        throw new InvalidKeyException("expected only SLHDSAPublicKey");
    }

    /** Private-key counterpart to {@link #importPublicKey}. */
    private SLHDSAPrivateKey importPrivateKey(PrivateKey privateKey) throws InvalidKeyException
    {
        if (privateKey instanceof SLHDSAPrivateKey)
        {
            // Both halves: the library check is the only one with teeth when two hand-wired SPIs are unbound.
            SLHDSAPrivateKey joKey = (SLHDSAPrivateKey) privateKey;
            if (joKey.getSpec().getSpecNI() != keyFactory.ownSpecNI()
                    || !joKey.getSpec().usableBy(keyFactory.ownProviderInstance()))
            {
                throw new InvalidKeyException(
                        "private key was created by a different Jostle provider instance; encode it with "
                                + "getEncoded() and decode it through this provider's KeyFactory");
            }
            return joKey;
        }
        Key translated = keyFactory.engineTranslateKey(privateKey);
        if (translated instanceof SLHDSAPrivateKey)
        {
            return (SLHDSAPrivateKey) translated;
        }
        throw new InvalidKeyException("expected only SLHDSAPrivateKey");
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
            updateCalled = true;
            try
            {
                slhdsaServiceNI.update(ref.getReference(), b, off, len);
            }
            catch (OpenSSLException | IllegalArgumentException e)
            {
                // Signature declares SignatureException for refused input; IllegalStateException stays raw.
                throw new SignatureException(e.getMessage(), e);
            }
        }
    }

    @Override
    protected byte[] engineSign() throws SignatureException
    {
        synchronized (this)
        {
            try
            {
                int len = slhdsaServiceNI.signatureLength(ref.getReference(),
                        lastKey != null ? lastKey.getSpec().getType() : null, randSource);
                byte[] sig = new byte[len];
                int written = slhdsaServiceNI.sign(ref.getReference(), sig, 0, randSource);
                if (written != sig.length)
                {
                    throw new SignatureException("signature length mismatch");
                }
                return sig;
            }
            catch (OpenSSLException | IllegalArgumentException e)
            {
                // Signature declares SignatureException for a failed signing operation.
                throw new SignatureException(e.getMessage(), e);
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
            try
            {
                int code = slhdsaServiceNI.verify(ref.getReference(), sigBytes, sigBytes != null ? sigBytes.length : 0);

                return code == ErrorCode.JO_SUCCESS.getCode();
            }
            catch (OpenSSLException | IllegalArgumentException e)
            {
                // Signature declares SignatureException for a failed verification operation.
                throw new SignatureException(e.getMessage(), e);
            }
            finally
            {
                reInit();
            }
        }
    }

    @Override
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException
    {
        throw new UnsupportedOperationException();
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException
    {
        if (updateCalled)
        {
            throw new ProviderException("cannot call setParameter in the middle of update");
        }

        if (params == null)
        {
            algorithmParameterSpec = ContextParameterSpec.EMPTY_CONTEXT_SPEC;
            reInit();
            return;
        }

        if (params instanceof ContextParameterSpec)
        {
            algorithmParameterSpec = params;
            reInit();
            return;
        }
        throw new InvalidAlgorithmParameterException("unknown AlgorithmParameterSpec");
    }

    private void reInit()
    {

        synchronized (this)
        {
            try
            {
                if (lastKey instanceof SLHDSAPublicKey)
                {
                    engineInitVerify((PublicKey) lastKey);
                }
                else
                {
                    if (lastKey instanceof SLHDSAPrivateKey)
                    {
                        engineInitSign((PrivateKey) lastKey);
                    }
                    else
                    {
                        if (lastKey != null)
                        {
                            throw new InvalidKeyException("last key is unexpected type: " + lastKey.getClass());
                        }
                    }
                }

                // Intentional, does nothing if no key present.

            }
            catch (Exception e)
            {
                throw new ProviderException("unable to reinitialize signature engine", e);
            }
        }
    }


    @Override
    protected Object engineGetParameter(String param) throws InvalidParameterException
    {
        throw new UnsupportedOperationException();
    }


    protected static class Disposer
            extends NativeDisposer
    {
        private final SLHDSAServiceNI slhdsaServiceNI;

        Disposer(SLHDSAServiceNI slhdsaServiceNI, long ref)
        {
            super(ref);
            this.slhdsaServiceNI = slhdsaServiceNI;
        }

        @Override
        protected void dispose(long reference)
        {
            slhdsaServiceNI.disposeSigner(reference);
        }
    }

    protected static class SLHDSARef extends NativeReference
    {

        protected SLHDSARef(SLHDSAServiceNI slhdsaServiceNI, long reference, String name)
        {
            // The action is built from CONSTRUCTOR PARAMETERS and handed to
            // super(): NativeReference's constructor registers with the
            // disposal daemon, which captures getDisposeAction() eagerly -
            // before any field of this subclass has been assigned. Reading an
            // instance field here would capture null and NPE on the disposal
            // thread, leaking the native ctx. See CLAUDE.md.
            super(reference, name, new SLHDSASignatureSpi.Disposer(slhdsaServiceNI, reference));
        }

    }


    @Override
    public String toString()
    {
        return "SLHDSASignature(" + (ref != null ? ref.getReference() : "null") + ")" + (lastKey != null ? "[" + lastKey.toString() + "]" : "[]");
    }

    /**
     * No parameters. Matching SunRsaSign, SunEC, SUN and BouncyCastle, which
     * all answer null here; the inherited SignatureSpi default throws, and a
     * caller reading it back to build an AlgorithmIdentifier then fails on an
     * unchecked exception.
     */
    @Override
    protected AlgorithmParameters engineGetParameters()
    {
        return null;
    }
}
