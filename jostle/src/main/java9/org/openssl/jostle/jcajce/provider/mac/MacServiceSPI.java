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
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.spec.KMACParameterSpec;
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

/**
 * Shared SPI for every registered Mac.
 *
 * <p>AESGMAC gives one tag per init, as BouncyCastle's does: after {@code doFinal} or {@code reset} the instance
 * refuses until a new init, and an init repeating the previous key and nonce is refused. Every other MAC returns to
 * its initialised state after {@code doFinal}, as the JCA contract specifies.
 */
public class MacServiceSPI extends MacSpi implements Cloneable
{
    // Instance field, not a NISelector static: the SPI is bound to whichever
    // NI backend its provider passes in - NISelector.MacServiceNI for JSL,
    // FIPSNISelector.MacServiceNI (the FIPS interface library) for JSLFIPS.
    private final MacServiceNI macServiceNI;

    // The one registered MAC that takes a nonce. Named here for the same reason
    // the native init_mac_ctx dispatches on it: which parameter specs a
    // registration accepts is a JCE-surface fact, not a value OpenSSL reports.
    private static final String GMAC = "GMAC";

    // The two variable-length MACs, named for the same reason GMAC is: which
    // parameter specs a registration accepts is a JCE-surface fact, not
    // something OpenSSL reports. These are the OpenSSL EVP_MAC names, not the
    // JCE service names (KMAC128 / KMAC256).
    private static final String KMAC_128 = "KMAC-128";
    private static final String KMAC_256 = "KMAC-256";

    private static boolean isKmac(String name)
    {
        return KMAC_128.equals(name) || KMAC_256.equals(name);
    }

    // A spent GMAC context answers not-initialised; BouncyCastle's GMAC refuses with IllegalStateException.
    private void refuseIfSpent(int code)
    {
        if (code == ErrorCode.JO_NOT_INITIALIZED.getCode() && GMAC.equals(macName))
        {
            throw new IllegalStateException("GMAC needs a new init with a new nonce");
        }
    }

    private final MacReference ref;
    private final String cacheKey;
    private final String macName;

    // KMAC's parameters from the last accepted init; a KMAC output length belongs to the instance. Each init
    // replaces them only once the native init accepts it, and a refused native init clears them, as native does.
    private byte[] custom;
    private int requestedLen;

    // True after an init the native layer accepted, false after one it refused.
    private boolean initialised;

    // One init's parameters, committed to the fields only once the native init accepts them.
    private static final class InitParams
    {
        private final byte[] iv;
        private final byte[] custom;
        private final int requestedLen;

        InitParams(byte[] iv, byte[] custom, int requestedLen)
        {
            this.iv = iv;
            this.custom = custom;
            this.requestedLen = requestedLen;
        }
    }

    public MacServiceSPI(String macName, String function)
    {
        this(NISelector.MacServiceNI, macName, function);
    }

    //
    // Clone path: adopt an already-copied native handle. cacheKey is carried
    // verbatim so the clone shares the memoized MAC length of its source.
    //
    private MacServiceSPI(MacServiceNI macServiceNI, String macName, String cacheKey, MacReference ref,
                          byte[] custom, int requestedLen, boolean initialised)
    {
        this.macServiceNI = macServiceNI;
        this.macName = macName;
        this.cacheKey = cacheKey;
        this.ref = ref;
        // The native copy carries S and the output length too, so the clone
        // must agree with it - a clone that reported the default length while
        // its native ctx produced the requested one would size engineDoFinal's
        // buffer wrongly.
        this.custom = Arrays.clone(custom);
        this.requestedLen = requestedLen;
        this.initialised = initialised;
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
     * Validate this init's parameter spec and return its IV and KMAC parameters, changing no field.
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
     *
     * <p>KMAC takes no IV; its spec instead carries the customisation string
     * {@code S} and the output length {@code L}, both optional. Omitting the
     * spec gives SP 800-185's defaults — an empty {@code S} and the
     * algorithm's own length — which is also what BouncyCastle's KMAC does
     * with a null spec, so the two agree by default as well as by parameter.
     */
    private InitParams resolveParams(AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException
    {
        if (isKmac(macName))
        {
            byte[] s = null;
            int bits = 0;

            if (params != null)
            {
                if (!(params instanceof KMACParameterSpec))
                {
                    throw new InvalidAlgorithmParameterException(
                            "expected KMACParameterSpec, got " + params.getClass().getName());
                }
                KMACParameterSpec kmacSpec = (KMACParameterSpec) params;
                // Already validated by the spec's constructor: positive and a
                // multiple of 8. That matters here because a zero would reach
                // native as the "unspecified" sentinel rather than as a
                // request, silently giving the default length instead.
                s = kmacSpec.getCustomizationString();
                bits = kmacSpec.getMacSizeInBits();
            }

            return new InitParams(null, s, bits / 8);
        }

        if (!GMAC.equals(macName))
        {
            if (params != null)
            {
                throw new InvalidAlgorithmParameterException("params not supported");
            }
            return new InitParams(null, null, 0);
        }

        if (params == null)
        {
            throw new InvalidAlgorithmParameterException(
                    macName + " requires an IvParameterSpec or GCMParameterSpec carrying the nonce");
        }

        if (params instanceof IvParameterSpec)
        {
            return new InitParams(((IvParameterSpec) params).getIV(), null, 0);
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
            return new InitParams(gcmSpec.getIV(), null, 0);
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
        return macServiceNI.macLength(ref.getReference(), cacheKey);
    }

    /**
     * The output length this instance will actually produce: the caller's
     * requested KMAC length when one was given, otherwise the algorithm's own
     * default as reported by OpenSSL.
     *
     * <p>Kept distinct from {@link #macLength()} because that cache is keyed by
     * algorithm, while a KMAC output length belongs to the instance — two
     * KMAC128 instances can legitimately disagree.
     */
    private int outputLength()
    {
        return requestedLen != 0 ? requestedLen : macLength();
    }

    @Override
    protected int engineGetMacLength()
    {
        try
        {
            return outputLength();
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
        InitParams p = resolveParams(params);

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

        boolean accepted = false;
        boolean kept = false;
        try
        {
            int rc = macServiceNI.ni_init(ref.getReference(), keyBytes, p.iv, p.custom, p.requestedLen);
            // A reused GMAC nonce is refused before native changes anything, so this instance keeps its state too.
            kept = rc == ErrorCode.JO_MAC_NONCE_REUSED.getCode();
            macServiceNI.handleInitErrors(rc);
            accepted = true;
        }
        catch (OpenSSLException e)
        {
            // An input the library refuses (the FIPS MAC key-length checks among
            // them) reaches here unchecked; init declares InvalidKeyException.
            throw new InvalidKeyException(e.getMessage(), e);
        }
        finally
        {
            // keyBytes is a fresh copy, so clearing it cannot change the caller's key.
            Arrays.clear(keyBytes);
            if (!kept)
            {
                custom = accepted ? p.custom : null;
                requestedLen = accepted ? p.requestedLen : 0;
                initialised = accepted;
            }
            Reference.reachabilityFence(this);
        }
    }

    @Override
    protected void engineUpdate(byte input)
    {
        try
        {
            int rc = macServiceNI.ni_updateByte(ref.getReference(), input);
        refuseIfSpent(rc);
        macServiceNI.handleErrors(rc);
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
            int rc = macServiceNI.ni_updateBytes(ref.getReference(), input, offset, len);
        refuseIfSpent(rc);
        macServiceNI.handleErrors(rc);
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
            byte[] out = new byte[outputLength()];
            int written;
            // reset must run even if doFinal throws: a failed EVP_MAC_final
            // leaves the ctx finalized, and skipping the re-init would let the
            // next update absorb into finalized state (wrong-but-consistent).
            try
            {
                int rc = macServiceNI.ni_doFinal(ref.getReference(), out, 0);
            refuseIfSpent(rc);
            written = (int) macServiceNI.handleErrors(rc);
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
            // Nothing to reset before an accepted init; BC and SunJCE accept the call too.
            if (initialised)
            {
                macServiceNI.reset(ref.getReference());
            }
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
                    new MacReference(macServiceNI, clonedRef, cacheKey), custom, requestedLen,
                    initialised);
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
