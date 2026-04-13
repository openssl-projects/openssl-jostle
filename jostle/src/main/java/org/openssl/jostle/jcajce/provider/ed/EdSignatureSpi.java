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

package org.openssl.jostle.jcajce.provider.ed;

import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.disposal.NativeDisposer;
import org.openssl.jostle.disposal.NativeReference;
import org.openssl.jostle.jcajce.interfaces.EdDSAKey;
import org.openssl.jostle.jcajce.interfaces.EdDSAPrivateKey;
import org.openssl.jostle.jcajce.interfaces.EdDSAPublicKey;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.ContextParameterSpec;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.util.SpecUtil;
import org.openssl.jostle.rand.DefaultRandSource;
import org.openssl.jostle.rand.RandSource;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public class EdSignatureSpi extends SignatureSpi
{

    private static final EDServiceNI edServiceNI = NISelector.EDServiceNI;

    private final OSSLKeyType forcedType;
    private EdDsaRef ref;
    private RandSource randSource = DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom());
    private AlgorithmParameterSpec algorithmParameterSpec = null;
    private EdDSAKey lastKey = null;
    private boolean updateCalled = false;

    public static final int PH = 1;
    public static final int CTX = 2;


    public EdSignatureSpi(OSSLKeyType forcedType)
    {
        this.forcedType = forcedType;
        algorithmParameterSpec = ContextParameterSpec.EMPTY_CONTEXT_SPEC;
    }


    private boolean matchForcedType(OSSLKeyType keyType)
    {
        if (forcedType == OSSLKeyType.NONE)
        {
            return true;
        }
        switch (forcedType)
        {
            case Ed25519ph:
            case Ed25519ctx:
            case ED25519:
                return keyType == OSSLKeyType.ED25519;
            case ED448ph:
            case ED448:
                return keyType == OSSLKeyType.ED448;
            default:

        }
        return false;
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException
    {

        synchronized (this)
        {
            if ((publicKey instanceof EdDSAPublicKey))
            {

                updateCalled = false;


                JOEdPublicKey key = (JOEdPublicKey) publicKey;
                lastKey = key;

                if (!matchForcedType(key.getType()))
                {
                    throw new InvalidKeyException("required " + forcedType.name() + " key type but got " + key.getSpec().getType());
                }

                if (ref == null)
                {
                    ref = new EdDsaRef(edServiceNI.allocateSigner(), publicKey.getAlgorithm());
                }

                byte[] context = null;
                int contextLen = 0;

                if (algorithmParameterSpec instanceof ContextParameterSpec)
                {
                    if (forcedType != OSSLKeyType.Ed25519ctx)
                    {
                        throw new InvalidKeyException(forcedType.name() + " does not accept a context parameter");
                    }

                    context = ((ContextParameterSpec) algorithmParameterSpec).getContext();
                    contextLen = context.length;
                }

                String name = forcedType != OSSLKeyType.NONE ? forcedType.name() : key.getType().getTypeName();

                edServiceNI.initVerify(ref.getReference(), key.getSpec().getReference(), name, context, contextLen);
                return;
            }
            throw new InvalidKeyException("expected only EdDSAPublicKey");
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

        if (privateKey instanceof EdDSAPrivateKey)
        {
            synchronized (this)
            {

                JOEdPrivateKey key = (JOEdPrivateKey) privateKey;
                lastKey = key;
                updateCalled = false;

                if (!matchForcedType(key.getType()))
                {
                    throw new InvalidKeyException("required " + forcedType.name() + " key type but got " + key.getSpec().getType());
                }

                if (ref == null)
                {
                    ref = new EdDsaRef(edServiceNI.allocateSigner(), privateKey.getAlgorithm());
                }

                byte[] context = null;
                int contextLen = 0;

                if (algorithmParameterSpec instanceof ContextParameterSpec)
                {
                    if (forcedType != OSSLKeyType.Ed25519ctx)
                    {
                        throw new InvalidKeyException(forcedType.name() + " does not accept a context parameter");
                    }

                    context = ((ContextParameterSpec) algorithmParameterSpec).getContext();
                    contextLen = context.length;
                }

                String name = forcedType != OSSLKeyType.NONE ? forcedType.name() : key.getType().getTypeName();

                edServiceNI.initSign(
                        ref.getReference(),
                        key.getSpec().getReference(), name, context, contextLen, randSource);
                return;
            }
        }
        throw new InvalidKeyException("expected only EdDSAPrivateKey");
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException
    {
        engineUpdate(new byte[]{b}, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException
    {
        updateCalled = true;
        edServiceNI.update(ref.getReference(), b, off, len);
    }

    @Override
    protected byte[] engineSign() throws SignatureException
    {
        byte[] sig = null;
        try
        {
            long len = edServiceNI.sign(ref.getReference(), null, 0, randSource);
            sig = new byte[(int) len];
            edServiceNI.sign(ref.getReference(), sig, 0, randSource);
            return sig;
        }
        finally
        {
            reInit();
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException
    {
        try
        {
            int code = edServiceNI.verify(ref.getReference(), sigBytes, sigBytes != null ? sigBytes.length : 0);
            return code == ErrorCode.JO_SUCCESS.getCode();
        }
        finally
        {
            reInit();
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

        byte[] context = SpecUtil.getContextFrom(params);
        if (context != null)
        {
            algorithmParameterSpec = new ContextParameterSpec(context);
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
                if (lastKey instanceof EdDSAPublicKey)
                {
                    engineInitVerify((PublicKey) lastKey);
                }
                else
                {
                    if (lastKey instanceof EdDSAPrivateKey)
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
        Disposer(long ref)
        {
            super(ref);
        }

        @Override
        protected void dispose(long reference)
        {
            edServiceNI.disposeSigner(reference);
        }
    }

    protected static class EdDsaRef extends NativeReference
    {

        protected EdDsaRef(long reference, String name)
        {
            super(reference, name);
        }

        @Override
        protected Runnable createAction()
        {
            return new EdSignatureSpi.Disposer(reference);
        }
    }


    @Override
    public String toString()
    {
        return "EdDSASignature(" + ref.getReference() + ")" + (lastKey != null ? "[" + lastKey.toString() + "]" : "[]");
    }


}
