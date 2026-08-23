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
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.lang.ref.Reference;
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

    // The one registered MAC that takes a nonce. Named here for the same reason
    // the native init_mac_ctx dispatches on it: which parameter specs a
    // registration accepts is a JCE-surface fact, not a value OpenSSL reports.
    private static final String GMAC = "GMAC";

    private final MacReference ref;
    private final String cacheKey;
    private final String macName;

    public MacServiceSPI(String macName, String function)
    {
        this(NISelector.MacServiceNI, macName, function);
    }

    //
    // Clone path: adopt an already-copied native handle. cacheKey is carried
    // verbatim so the clone shares the memoized MAC length of its source.
    //
    private MacServiceSPI(MacServiceNI macServiceNI, String macName, String cacheKey, MacReference ref)
    {
        this.macServiceNI = macServiceNI;
        this.macName = macName;
        this.cacheKey = cacheKey;
        this.ref = ref;
    }

    public MacServiceSPI(MacServiceNI macServiceNI, String macName, String function)
    {
        this.macServiceNI = macServiceNI;
        this.macName = macName;
        // Composite cache key: a space cannot appear in a real mac/digest/cipher
        // name (e.g. "HMAC", "SHA2-256", "aes-cbc"), so it is unambiguous.
        this.cacheKey = macName + ' ' + function;
        this.ref = new MacReference(macServiceNI, macServiceNI.allocateMac(macName, function), function);
    }

    /**
     * The IV for this init, or null when this MAC takes none.
     *
     * <p>GMAC inherits GCM's variable-length nonce — 1, 8, 11, 12, 13, 16 and 32
     * bytes are all accepted by mainline and by both FIPS modules, and only 0 is
     * refused, by the provider itself — so no length check happens here.
     *
     * <p>{@code GCMParameterSpec} is accepted for BouncyCastle parity (BC's
     * AES-GMAC takes it, and RFC 9044 CMS callers construct one), but only at
     * the full tag length. OpenSSL's GMAC has no {@code size} in
     * {@code EVP_MAC_CTX_settable_params}, so a shorter tag cannot be honoured;
     * refusing is the fail-loud answer, where accepting would hand the caller a
     * 16-byte tag it did not ask for. The comparison value is queried from
     * OpenSSL, never transcribed.
     */
    private byte[] resolveIv(AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException
    {
        if (!GMAC.equals(macName))
        {
            if (params != null)
            {
                throw new InvalidAlgorithmParameterException("params not supported");
            }
            return null;
        }

        if (params == null)
        {
            throw new InvalidAlgorithmParameterException(
                    macName + " requires an IvParameterSpec or GCMParameterSpec carrying the nonce");
        }

        if (params instanceof IvParameterSpec)
        {
            return ((IvParameterSpec) params).getIV();
        }

        if (params instanceof GCMParameterSpec)
        {
            GCMParameterSpec gcmSpec = (GCMParameterSpec) params;
            int tagBits = engineGetMacLength() * 8;
            if (gcmSpec.getTLen() != tagBits)
            {
                throw new InvalidAlgorithmParameterException(
                        macName + " tag length is fixed at " + tagBits + " bits, got " + gcmSpec.getTLen());
            }
            return gcmSpec.getIV();
        }

        throw new InvalidAlgorithmParameterException(
                "expected IvParameterSpec or GCMParameterSpec, got " + params.getClass().getName());
    }

    /**
     * MAC output length for this (macName, function), memoized cross-instance.
     * On a cache miss we ask OpenSSL via the keyless native metadata query
     * (digest output size for HMAC, cipher block size for CMAC) — it answers
     * before init, so getMacLength works on a freshly-constructed SPI — and
     * record whatever OpenSSL reported. OpenSSL stays the source of truth; the
     * cache only saves the repeat native round-trip. The native ref is
     * dereferenced, so callers must keep {@code this} reachable (the callers
     * here run inside the reachabilityFence try/finally).
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
        try
        {
            return macLength();
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
        // Spec first: java-spi.md requires getEncoded() to come AFTER any
        // validation that can throw, so a rejected init never leaves an
        // uncleared copy of the key on the heap.
        byte[] iv = resolveIv(params);

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

        try
        {
            macServiceNI.engineInit(ref.getReference(), keyBytes, iv);
        }
        finally
        {
            // Scrub the plaintext key once OpenSSL has copied it into the
            // EVP_MAC ctx (java-spi.md "Zeroize the byte[] from
            // key.getEncoded()"). keyBytes is a fresh SecretKeySpec copy and is
            // non-null (guarded above). Matters most for Poly1305's one-time key.
            Arrays.clear(keyBytes);
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

    //
    // Mac.clone() routes here. See the Java 8 baseline copy for the rationale;
    // this override keeps the SPI reachable across the native copy with
    // Reference.reachabilityFence instead of synchronized(this).
    //
    @Override
    public Object clone() throws CloneNotSupportedException
    {
        try
        {
            long clonedRef = macServiceNI.copyMac(ref.getReference());
            return new MacServiceSPI(macServiceNI, macName, cacheKey,
                    new MacReference(macServiceNI, clonedRef, cacheKey));
        }
        catch (RuntimeException e)
        {
            CloneNotSupportedException cnse =
                    new CloneNotSupportedException("unable to clone mac");
            cnse.initCause(e);
            throw cnse;
        }
        finally
        {
            Reference.reachabilityFence(this);
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
