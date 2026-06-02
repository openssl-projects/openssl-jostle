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
import org.openssl.jostle.jcajce.provider.cache.NativeLengthCache;

import javax.crypto.MacSpi;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.ProviderException;
import java.security.spec.AlgorithmParameterSpec;

public class MacServiceSPI extends MacSpi
{
    private static final MacServiceNI macServiceNI = NISelector.MacServiceNI;

    // OpenSSL-probed MAC lengths, memoized once per (macName, function) (see NativeLengthCache).
    private static final NativeLengthCache<String> macLengths = new NativeLengthCache<String>();

    private final MacReference ref;
    private final String cacheKey;

    public MacServiceSPI(String macName, String function)
    {
        // Composite cache key: a space cannot appear in a real mac/digest/cipher
        // name (e.g. "HMAC", "SHA2-256", "aes-cbc"), so it is unambiguous.
        this.cacheKey = macName + ' ' + function;
        this.ref = new MacReference(macServiceNI.allocateMac(macName, function), function);
    }

    /**
     * MAC output length for this (macName, function), memoized cross-instance.
     * On a cache miss we ask OpenSSL via the keyless native metadata query
     * (digest output size for HMAC, cipher block size for CMAC) — it answers
     * before init, so getMacLength works on a freshly-constructed SPI — and
     * record whatever OpenSSL reported. OpenSSL stays the source of truth; the
     * cache only saves the repeat native round-trip. Callers must hold the
     * monitor (the native ref is dereferenced).
     */
    private int macLength()
    {
        int len = macLengths.get(cacheKey);
        if (len == NativeLengthCache.UNKNOWN)
        {
            len = macServiceNI.macLengthMeta(ref.getReference());
            macLengths.cache(cacheKey, len);
        }
        return len;
    }

    @Override
    protected int engineGetMacLength()
    {
        synchronized (this)
        {
            return macLength();
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
            byte[] out = new byte[macLength()];
            int written = macServiceNI.doFinal(ref.getReference(), out, 0);
            macServiceNI.reset(ref.getReference());
            if (written == out.length)
            {
                return out;
            }

            throw new ProviderException("MAC length mismatch");
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
