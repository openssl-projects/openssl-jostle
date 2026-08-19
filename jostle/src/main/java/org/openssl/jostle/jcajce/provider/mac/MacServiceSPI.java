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
import org.openssl.jostle.util.Arrays;

import javax.crypto.MacSpi;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.ProviderException;
import java.security.spec.AlgorithmParameterSpec;

public class MacServiceSPI extends MacSpi implements Cloneable
{
    // Instance field, not a NISelector static: the SPI is bound to whichever
    // NI backend its provider passes in - NISelector.MacServiceNI for JSL,
    // FIPSNISelector.MacServiceNI (the FIPS interface library) for JSLFIPS.
    private final MacServiceNI macServiceNI;

    // OpenSSL-probed MAC lengths, memoized once per (macName, function) (see NativeLengthCache).
    private static final NativeLengthCache<String> macLengths = new NativeLengthCache<String>();

    private final MacReference ref;
    private final String cacheKey;

    public MacServiceSPI(String macName, String function)
    {
        this(NISelector.MacServiceNI, macName, function);
    }

    //
    // Clone path: adopt an already-copied native handle. cacheKey is carried
    // verbatim so the clone shares the memoized MAC length of its source.
    //
    private MacServiceSPI(MacServiceNI macServiceNI, String cacheKey, MacReference ref)
    {
        this.macServiceNI = macServiceNI;
        this.cacheKey = cacheKey;
        this.ref = ref;
    }

    public MacServiceSPI(MacServiceNI macServiceNI, String macName, String function)
    {
        this.macServiceNI = macServiceNI;
        // Composite cache key: a space cannot appear in a real mac/digest/cipher
        // name (e.g. "HMAC", "SHA2-256", "aes-cbc"), so it is unambiguous.
        this.cacheKey = macName + ' ' + function;
        this.ref = new MacReference(macServiceNI, macServiceNI.allocateMac(macName, function), function);
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
            try
            {
                macServiceNI.engineInit(ref.getReference(), keyBytes);
            }
            finally
            {
                // Scrub the plaintext key once OpenSSL has copied it into the
                // EVP_MAC ctx (java-spi.md "Zeroize the byte[] from
                // key.getEncoded()"). keyBytes is a fresh SecretKeySpec copy and
                // is non-null (guarded above), so clearing it cannot corrupt the
                // caller's key. Matters most for Poly1305's one-time key.
                Arrays.clear(keyBytes);
            }
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
            int written;
            // reset must run even if doFinal throws: a failed EVP_MAC_final
            // leaves the ctx finalized, and skipping the re-init would let the
            // next update absorb into finalized state (wrong-but-consistent).
            try
            {
                written = macServiceNI.doFinal(ref.getReference(), out, 0);
            }
            finally
            {
                macServiceNI.reset(ref.getReference());
            }
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

    //
    // Mac.clone() routes here (the JCA Delegate calls Object.clone() on the SPI
    // when it is Cloneable). A shallow Object.clone() would share the single
    // native EVP_MAC_CTX between the original and the copy — a double-free and
    // cross-talk hazard — so we deep-copy the native state via EVP_MAC_CTX_dup
    // and hand the clone its own MacReference/Disposer. The provider's dupctx
    // copies the running state and re-allocates the key into secure memory, so
    // the clone continues the same MAC rather than starting fresh.
    //
    @Override
    public Object clone() throws CloneNotSupportedException
    {
        synchronized (this)
        {
            try
            {
                long clonedRef = macServiceNI.copyMac(ref.getReference());
                return new MacServiceSPI(macServiceNI, cacheKey,
                        new MacReference(macServiceNI, clonedRef, cacheKey));
            }
            catch (RuntimeException e)
            {
                // A native copy failure surfaces from copyMac as an unchecked
                // exception; honour the declared clone() contract by reporting
                // it as CloneNotSupportedException with the failure as cause.
                CloneNotSupportedException cnse =
                        new CloneNotSupportedException("unable to clone mac");
                cnse.initCause(e);
                throw cnse;
            }
        }
    }

    private static class Disposer extends NativeDisposer
    {
        // The NI that allocated the context frees it - a FIPS-allocated
        // MAC must be disposed through the FIPS interface library.
        private final MacServiceNI macServiceNI;

        Disposer(MacServiceNI macServiceNI, long ref)
        {
            super(ref);
            this.macServiceNI = macServiceNI;
        }

        @Override
        protected void dispose(long reference)
        {
            macServiceNI.dispose(reference);
        }
    }

    private static class MacReference extends NativeReference
    {

        public MacReference(MacServiceNI macServiceNI, long reference, String name)
        {
            super(reference, name, new Disposer(macServiceNI, reference));
        }

    }
}
