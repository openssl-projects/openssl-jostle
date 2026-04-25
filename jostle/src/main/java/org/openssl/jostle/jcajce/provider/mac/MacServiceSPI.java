/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.mac;

import org.openssl.jostle.disposal.NativeDisposer;
import org.openssl.jostle.disposal.NativeReference;
import org.openssl.jostle.jcajce.provider.NISelector;

import javax.crypto.MacSpi;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

public class MacServiceSPI extends MacSpi
{
    private static final MacServiceNI macServiceNI = NISelector.MacServiceNI;

    private final MacReference ref;

    public MacServiceSPI(String macName, String function)
    {
        this.ref = new MacReference(macServiceNI.allocateMac(macName, function), function);
    }

    @Override
    protected int engineGetMacLength()
    {
        synchronized (this)
        {
            return macServiceNI.getMacLength(ref.getReference());
        }
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params)
            throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        if (params != null)
        {
            throw new InvalidAlgorithmParameterException("params not supported");
        }
        if (key == null)
        {
            throw new InvalidKeyException("key is null");
        }

        if (!(key instanceof SecretKey))
        {
            throw new InvalidKeyException("unsupported key type: " + key.getClass().getName());
        }

        byte[] keyBytes = key.getEncoded();
        if (keyBytes == null)
        {
            throw new InvalidKeyException("key encoding is null");
        }

        synchronized (this)
        {
            macServiceNI.engineInit(ref.getReference(), keyBytes);
        }
    }

    @Override
    protected void engineUpdate(byte input)
    {
        synchronized (this)
        {
            macServiceNI.engineUpdate(ref.getReference(), input);
        }
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len)
    {
        synchronized (this)
        {
            macServiceNI.engineUpdate(ref.getReference(), input, offset, len);
        }
    }

    @Override
    protected byte[] engineDoFinal()
    {
        synchronized (this)
        {
            byte[] out = new byte[engineGetMacLength()];
            int written = macServiceNI.doFinal(ref.getReference(), out, 0);
            macServiceNI.reset(ref.getReference());
            if (written == out.length)
            {
                return out;
            }

            byte[] exact = new byte[written];
            System.arraycopy(out, 0, exact, 0, written);
            return exact;
        }
    }

    @Override
    protected void engineReset()
    {
        synchronized (this)
        {
            macServiceNI.reset(ref.getReference());
        }
    }

    private byte[] extractKeyBytes(Key key) throws InvalidKeyException
    {
        if (!(key instanceof SecretKey))
        {
            throw new InvalidKeyException("unsupported key type: " + key.getClass().getName());
        }

        byte[] encoded = key.getEncoded();
        if (encoded == null)
        {
            throw new InvalidKeyException("key encoding is null");
        }

        return encoded;
    }

    private static class Disposer extends NativeDisposer
    {
        Disposer(long ref)
        {
            super(ref);
        }

        @Override
        protected void dispose(long reference)
        {
            macServiceNI.dispose(reference);
        }
    }

    private static class MacReference extends NativeReference
    {
        public MacReference(long reference, String name)
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
