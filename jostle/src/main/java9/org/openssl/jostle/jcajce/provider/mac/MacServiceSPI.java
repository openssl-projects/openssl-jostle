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
import org.openssl.jostle.jcajce.util.DigestUtil;

import javax.crypto.MacSpi;
import javax.crypto.SecretKey;
import java.lang.ref.Reference;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

public class MacServiceSPI extends MacSpi implements Cloneable
{
    private static final MacServiceNI macServiceNI = NISelector.MacServiceNI;

    private final String macName;
    private final String canonicalDigestName;
    private final MacReference ref;

    public MacServiceSPI(String macName, String digestName)
    {
        this(macName, DigestUtil.getCanonicalDigestName(digestName), true);
    }

    private MacServiceSPI(String macName, String canonicalDigestName, boolean allocate)
    {
        this(macName, canonicalDigestName, allocate ? macServiceNI.allocateMac(macName, canonicalDigestName) : 0L);
    }

    private MacServiceSPI(String macName, String canonicalDigestName, long reference)
    {
        this.macName = macName;
        this.canonicalDigestName = canonicalDigestName;
        this.ref = new MacReference(reference, canonicalDigestName);
    }

    @Override
    protected int engineGetMacLength()
    {
        try
        {
            return macServiceNI.getMacLength(ref.getReference());
        }
        finally
        {
            Reference.reachabilityFence(this);
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

        byte[] keyBytes = extractKeyBytes(key);
        try
        {
            macServiceNI.engineInit(ref.getReference(), keyBytes);
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }

    @Override
    protected void engineUpdate(byte input)
    {
        try
        {
            macServiceNI.engineUpdate(ref.getReference(), input);
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len)
    {
        try
        {
            macServiceNI.engineUpdate(ref.getReference(), input, offset, len);
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }

    @Override
    protected byte[] engineDoFinal()
    {
        try
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
        finally
        {
            Reference.reachabilityFence(this);
        }
    }

    @Override
    protected void engineReset()
    {
        try
        {
            macServiceNI.reset(ref.getReference());
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }

    @Override
    public Object clone() throws CloneNotSupportedException
    {
        try
        {
            long newRef = macServiceNI.copy(ref.getReference());
            if (newRef == 0)
            {
                throw new CloneNotSupportedException("native copy failed");
            }
            return new MacServiceSPI(macName, canonicalDigestName, newRef);
        } finally
        {
            Reference.reachabilityFence(this);
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
