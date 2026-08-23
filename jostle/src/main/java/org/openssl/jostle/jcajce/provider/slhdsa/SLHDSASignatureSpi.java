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

import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.disposal.NativeDisposer;
import org.openssl.jostle.disposal.NativeReference;
import org.openssl.jostle.jcajce.provider.AsymmetricKeyImpl;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.cache.NativeLengthCache;
import org.openssl.jostle.jcajce.spec.ContextParameterSpec;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.SpecNI;
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


    // OpenSSL-probed signature lengths, memoized once per parameter set (see NativeLengthCache).
    private static final NativeLengthCache<OSSLKeyType> signatureLengths = new NativeLengthCache<OSSLKeyType>();

    private final OSSLKeyType forcedType;
    private SLHDSARef ref = null;
    private AsymmetricKeyImpl lastKey = null;

    private AlgorithmParameterSpec algorithmParameterSpec = null;
    private boolean updateCalled = false;
    private MessageEncoding messageEncoding = MessageEncoding.PURE;
    private Deterministic deterministic = Deterministic.NON_DETERMINISTIC;
    private RandSource randSource = DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom());

    // Instance field, not a NISelector static (NISelector for JSL,
    // FIPSNISelector for JSLFIPS).
    private final SLHDSAServiceNI slhdsaServiceNI;

    // The SpecNI this SPI is bound to. A private key whose spec came from a
    // different one was made by the other Jostle provider and must be rejected.
    private final SpecNI specNI;

    public SLHDSASignatureSpi(OSSLKeyType forcedType, MessageEncoding messageEncoding, Deterministic deterministic)
    {
        this(NISelector.SLHDSAServiceNI, NISelector.SpecNI, forcedType, messageEncoding, deterministic);
    }

    public SLHDSASignatureSpi(SLHDSAServiceNI slhdsaServiceNI, SpecNI specNI, OSSLKeyType forcedType,
                              MessageEncoding messageEncoding, Deterministic deterministic)
    {
        this.slhdsaServiceNI = slhdsaServiceNI;
        this.specNI = specNI;
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
        if (publicKey instanceof JOSLHDSAPublicKey)
        {
            synchronized (this)
            {
                updateCalled = false;
                JOSLHDSAPublicKey key = (JOSLHDSAPublicKey) publicKey;
                lastKey = key;

                if (forcedType != OSSLKeyType.NONE && forcedType != key.getSpec().getType())
                {
                    throw new InvalidKeyException("required " + SLHDSAParameterSpec.getSpecForOSSLType(forcedType).getName() + " key type but got " + SLHDSAParameterSpec.getSpecForOSSLType(key.getType()).getName());
                }

                if (ref == null)
                {
                    ref = new SLHDSARef(slhdsaServiceNI, slhdsaServiceNI.allocateSigner(), publicKey.getAlgorithm());
                }

                byte[] context = null;
                int contextLen = 0;

                if (algorithmParameterSpec instanceof ContextParameterSpec)
                {
                    context = ((ContextParameterSpec) algorithmParameterSpec).getContext();
                    contextLen = context.length;
                }

                slhdsaServiceNI.initVerify(ref.getReference(), key.getSpec().getReference(), context, contextLen, messageEncoding.ordinal(), deterministic.ordinal());
                return;
            }
        }
        throw new InvalidKeyException("expected only SLHDSAPublicKey");
    }

    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException
    {
        engineInitSign(privateKey, null);
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey, SecureRandom random) throws InvalidKeyException
    {
        this.randSource = DefaultRandSource.replaceWith(this.randSource, random);
        if (privateKey instanceof JOSLHDSAPrivateKey)
        {
            synchronized (this)
            {

                JOSLHDSAPrivateKey key = (JOSLHDSAPrivateKey) privateKey;
                // Provider isolation: a key is bound to the interface library -
                // and OSSL_LIB_CTX - that created it, so a JSL private key must
                // not be driven through the JSLFIPS NI or vice versa. Same
                // check and message as ECKeyImport / RSAKeyImport. PUBLIC keys
                // deliberately cross freely; see java-spi.md.
                if (key.getSpec().getSpecNI() != specNI)
                {
                    throw new InvalidKeyException(
                            "private key was created by a different Jostle provider; encode it with getEncoded() and decode it through this provider's KeyFactory");
                }
                lastKey = key;
                updateCalled = false;

                if (forcedType != OSSLKeyType.NONE && forcedType != key.getSpec().getType())
                {
                    throw new InvalidKeyException("required " + SLHDSAParameterSpec.getSpecForOSSLType(forcedType).getName() + " key type but got " + SLHDSAParameterSpec.getSpecForOSSLType(key.getType()).getName());
                }

                if (ref == null)
                {
                    ref = new SLHDSARef(slhdsaServiceNI, slhdsaServiceNI.allocateSigner(), privateKey.getAlgorithm());
                }

                byte[] context = null;
                int contextLen = 0;

                if (algorithmParameterSpec instanceof ContextParameterSpec)
                {
                    context = ((ContextParameterSpec) algorithmParameterSpec).getContext();
                    contextLen = context.length;
                }

                slhdsaServiceNI.initSign(
                        ref.getReference(),
                        key.getSpec().getReference(),
                        context, contextLen, messageEncoding.ordinal(), deterministic.ordinal(),
                        randSource);
                return;
            }
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
            slhdsaServiceNI.update(ref.getReference(), b, off, len);
        }
    }

    @Override
    protected byte[] engineSign() throws SignatureException
    {
        synchronized (this)
        {
            byte[] sig = null;
            try
            {
                int len = NativeLengthCache.UNKNOWN;
                if (lastKey != null)
                {
                    len = signatureLengths.get(lastKey.getType());
                }
                if (len == NativeLengthCache.UNKNOWN)
                {
                    len = (int) slhdsaServiceNI.sign(ref.getReference(), null, 0, randSource);
                    if (lastKey != null)
                    {
                        // Memoize OpenSSL's reported length for this parameter set.
                        signatureLengths.cache(lastKey.getType(), len);
                    }
                }
                sig = new byte[len];
                long written = slhdsaServiceNI.sign(ref.getReference(), sig, 0, randSource);
                if (written != sig.length)
                {
                    throw new SignatureException("signature length mismatch");
                }
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
            try
            {
                int code = slhdsaServiceNI.verify(ref.getReference(), sigBytes, sigBytes != null ? sigBytes.length : 0);

                return code == ErrorCode.JO_SUCCESS.getCode();
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
                if (lastKey instanceof JOSLHDSAPublicKey)
                {
                    engineInitVerify((PublicKey) lastKey);
                }
                else
                {
                    if (lastKey instanceof JOSLHDSAPrivateKey)
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
}
