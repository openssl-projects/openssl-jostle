package org.openssl.jostle.jcajce.provider.mldsa;

import org.openssl.jostle.disposal.NativeDisposer;
import org.openssl.jostle.disposal.NativeReference;
import org.openssl.jostle.jcajce.interfaces.MLDSAKey;
import org.openssl.jostle.jcajce.interfaces.MLDSAPrivateKey;
import org.openssl.jostle.jcajce.interfaces.MLDSAPublicKey;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.ContextParameterSpec;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.util.SpecUtil;

import java.lang.ref.Reference;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;


public class MLDSASignatureSpi extends SignatureSpi
{

    public enum MuHandling
    {
        INTERNAL, EXTERNAL_MU, CALCULATE_MU
    }

    private final OSSLKeyType forcedType;
    private MLDSARef ref = null;
    private MLDSAKey lastKey = null;

    private AlgorithmParameterSpec algorithmParameterSpec = null;
    private boolean updateCalled = false;
    private MuHandling muHandling = MuHandling.INTERNAL;

    public MLDSASignatureSpi(OSSLKeyType forcedType, MuHandling forcedMu)
    {
        this.forcedType = forcedType;
        algorithmParameterSpec = ContextParameterSpec.EMPTY_CONTEXT_SPEC;
        muHandling = forcedMu;
    }


    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException
    {
        if (publicKey instanceof MLDSAPublicKey)
        {
            try
            {
                updateCalled = false;
                MLDSAPublicKey key = (MLDSAPublicKey) publicKey;
                lastKey = key;

                if (forcedType != OSSLKeyType.NONE && forcedType != key.getSpec().getType())
                {
                    throw new InvalidKeyException("required " + forcedType.name() + " key type but got " + key.getSpec().getType());
                }

                if (ref == null)
                {
                    ref = new MLDSARef(
                            NISelector.MLDSAServiceNI.handleErrors(
                                    NISelector.MLDSAServiceNI.allocateSigner()), publicKey.getAlgorithm());
                }

                byte[] context = null;
                int contextLen = 0;

                if (algorithmParameterSpec instanceof ContextParameterSpec)
                {
                    context = ((ContextParameterSpec) algorithmParameterSpec).getContext();
                    contextLen = context.length;
                }

                NISelector.MLDSAServiceNI.handleErrors(NISelector.MLDSAServiceNI.initVerify(ref.getReference(), key.getSpec().getReference(), context, contextLen, muHandling.ordinal()));
                return;
            } finally
            {
                Reference.reachabilityFence(this);
            }
        }
        throw new InvalidKeyException("expected only MLDSAPublicKey");
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException
    {
        if (privateKey instanceof MLDSAPrivateKey)
        {
            try
            {

                MLDSAPrivateKey key = (MLDSAPrivateKey) privateKey;
                lastKey = key;
                updateCalled = false;

                if (forcedType != OSSLKeyType.NONE && forcedType != key.getSpec().getType())
                {
                    throw new InvalidKeyException("required " + forcedType.name() + " key type but got " + key.getSpec().getType());
                }

                if (ref == null)
                {
                    ref = new MLDSARef(
                            NISelector.MLDSAServiceNI.handleErrors(
                                    NISelector.MLDSAServiceNI.allocateSigner()), privateKey.getAlgorithm());
                }

                byte[] context = null;
                int contextLen = 0;

                if (algorithmParameterSpec instanceof ContextParameterSpec)
                {
                    context = ((ContextParameterSpec) algorithmParameterSpec).getContext();
                    contextLen = context.length;
                }

                NISelector.MLDSAServiceNI.handleErrors(NISelector.MLDSAServiceNI.initSign(
                        ref.getReference(),
                        key.getSpec().getReference(),
                        context, contextLen, muHandling.ordinal()));
                return;
            } finally
            {
                Reference.reachabilityFence(this);
            }
        }
        throw new InvalidKeyException("expected only MLDSAPrivateKey");
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
            NISelector.MLDSAServiceNI.handleErrors(NISelector.MLDSAServiceNI.update(ref.getReference(), b, off, len));
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
                long len = NISelector.MLDSAServiceNI.handleErrors(NISelector.MLDSAServiceNI.sign(ref.getReference(), null, 0));
                sig = new byte[(int) len];
                NISelector.MLDSAServiceNI.handleErrors(NISelector.MLDSAServiceNI.sign(ref.getReference(), sig, 0));
                return sig;
            } finally
            {
                reInit();
            }
        } finally
        {
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
                int code = NISelector.MLDSAServiceNI.verify(ref.getReference(), sigBytes, sigBytes != null ? sigBytes.length : 0);

                if (code < ErrorCode.JO_FAIL.getCode())
                {
                    // Some other issue
                    NISelector.MLDSAServiceNI.handleErrors(code);
                }

                return code == ErrorCode.JO_SUCCESS.getCode();
            } finally
            {
                reInit();
            }
        } finally
        {
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
                if (lastKey instanceof MLDSAPublicKey)
                {
                    engineInitVerify((PublicKey) lastKey);
                } else if (lastKey instanceof MLDSAPrivateKey)
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
            NISelector.MLDSAServiceNI.disposeSigner(reference);
        }
    }

    protected static class MLDSARef extends NativeReference
    {

        protected MLDSARef(long reference, String name)
        {
            super(reference, name);
        }

        @Override
        protected Runnable createAction()
        {
            return new MLDSASignatureSpi.Disposer(reference);
        }
    }


    @Override
    public String toString()
    {
        return "MLDSASignature(" + ref.getReference() + ")" + (lastKey != null ? "[" + lastKey.toString() + "]" : "[]");
    }
}
