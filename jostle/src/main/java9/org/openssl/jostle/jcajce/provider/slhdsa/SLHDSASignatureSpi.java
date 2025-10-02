package org.openssl.jostle.jcajce.provider.slhdsa;

import org.openssl.jostle.disposal.NativeDisposer;
import org.openssl.jostle.disposal.NativeReference;
import org.openssl.jostle.jcajce.provider.AsymmetricKeyImpl;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.ContextParameterSpec;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.SLHDSAParameterSpec;

import java.lang.ref.Reference;
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
    private AsymmetricKeyImpl lastKey = null;

    private AlgorithmParameterSpec algorithmParameterSpec = null;
    private boolean updateCalled = false;
    private MessageEncoding messageEncoding = MessageEncoding.PURE;
    private Deterministic deterministic = Deterministic.NON_DETERMINISTIC;


    public SLHDSASignatureSpi(OSSLKeyType forcedType, MessageEncoding messageEncoding, Deterministic deterministic)
    {
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
            try
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
                    ref = new SLHDSARef(
                            NISelector.SLHDSAServiceNI.handleErrors(
                                    NISelector.SLHDSAServiceNI.allocateSigner()), publicKey.getAlgorithm());
                }

                byte[] context = null;
                int contextLen = 0;

                if (algorithmParameterSpec instanceof ContextParameterSpec)
                {
                    context = ((ContextParameterSpec) algorithmParameterSpec).getContext();
                    contextLen = context.length;
                }

                NISelector.SLHDSAServiceNI.handleErrors(NISelector.SLHDSAServiceNI.initVerify(ref.getReference(), key.getSpec().getReference(), context, contextLen, messageEncoding.ordinal(), deterministic.ordinal()));
                return;
            } finally
            {
                Reference.reachabilityFence(this);
            }
        }
        throw new InvalidKeyException("expected only SLHDSAPublicKey");
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException
    {
        if (privateKey instanceof JOSLHDSAPrivateKey)
        {
            try
            {

                JOSLHDSAPrivateKey key = (JOSLHDSAPrivateKey) privateKey;
                lastKey = key;
                updateCalled = false;

                if (forcedType != OSSLKeyType.NONE && forcedType != key.getSpec().getType())
                {
                    throw new InvalidKeyException("required " + SLHDSAParameterSpec.getSpecForOSSLType(forcedType).getName() + " key type but got " + SLHDSAParameterSpec.getSpecForOSSLType(key.getType()).getName());
                }

                if (ref == null)
                {
                    ref = new SLHDSARef(
                            NISelector.SLHDSAServiceNI.handleErrors(
                                    NISelector.SLHDSAServiceNI.allocateSigner()), privateKey.getAlgorithm());
                }

                byte[] context = null;
                int contextLen = 0;

                if (algorithmParameterSpec instanceof ContextParameterSpec)
                {
                    context = ((ContextParameterSpec) algorithmParameterSpec).getContext();
                    contextLen = context.length;
                }

                NISelector.SLHDSAServiceNI.handleErrors(NISelector.SLHDSAServiceNI.initSign(
                        ref.getReference(),
                        key.getSpec().getReference(),
                        context, contextLen, messageEncoding.ordinal(), deterministic.ordinal()));
                return;
            } finally {
                Reference.reachabilityFence(this);
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
        try
        {
            updateCalled = true;
            NISelector.SLHDSAServiceNI.handleErrors(NISelector.SLHDSAServiceNI.update(ref.getReference(), b, off, len));
        } finally
        {
            Reference.reachabilityFence(this);
        }
    }

    @Override
    protected byte[] engineSign() throws SignatureException
    {
        try
        {
            byte[] sig = null;
            try
            {
                long len = NISelector.SLHDSAServiceNI.handleErrors(NISelector.SLHDSAServiceNI.sign(ref.getReference(), null, 0));
                sig = new byte[(int) len];
                NISelector.SLHDSAServiceNI.handleErrors(NISelector.SLHDSAServiceNI.sign(ref.getReference(), sig, 0));
                return sig;
            } finally
            {
                reInit();
            }
        } finally {
            Reference.reachabilityFence(this);
        }
    }


    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException
    {
        try
        {
            try
            {
                int code = NISelector.SLHDSAServiceNI.verify(ref.getReference(), sigBytes, sigBytes != null ? sigBytes.length : 0);

                if (code < ErrorCode.JO_FAIL.getCode())
                {
                    // Some other issue
                    NISelector.SLHDSAServiceNI.handleErrors(code);
                }

                return code == ErrorCode.JO_SUCCESS.getCode();
            } finally
            {
                reInit();
            }
        } finally {
            Reference.reachabilityFence(this);
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

       try
        {
            try
            {
                if (lastKey instanceof JOSLHDSAPublicKey)
                {
                    engineInitVerify((PublicKey) lastKey);
                } else if (lastKey instanceof JOSLHDSAPrivateKey)
                {
                    engineInitSign((PrivateKey) lastKey);
                } else if (lastKey != null)
                {
                    throw new InvalidKeyException("last key is unexpected type: " + lastKey.getClass());
                }

                // Intentional, does nothing if no key present.

            } catch (Exception e)
            {
                throw new ProviderException("unable to reinitialize signature engine", e);
            }
        } finally
       {
           Reference.reachabilityFence(this);
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
            NISelector.SLHDSAServiceNI.disposeSigner(reference);
        }
    }

    protected static class SLHDSARef extends NativeReference
    {

        protected SLHDSARef(long reference, String name)
        {
            super(reference, name);
        }

        @Override
        protected Runnable createAction()
        {
            return new Disposer(reference);
        }
    }

    
    @Override
    public String toString()
    {
        return "SLHDSASignature(" + ref.getReference() + ")" + (lastKey != null ? "[" + lastKey.toString() + "]" : "[]");
    }
}
