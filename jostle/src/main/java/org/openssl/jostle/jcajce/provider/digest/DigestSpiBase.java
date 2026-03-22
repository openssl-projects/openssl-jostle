/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.digest;

import org.openssl.jostle.disposal.NativeDisposer;
import org.openssl.jostle.disposal.NativeReference;
import org.openssl.jostle.jcajce.util.DigestUtil;

import java.security.DigestException;
import java.security.MessageDigestSpi;
import java.nio.ByteBuffer;

/**
 * Common MessageDigest SPI that bridges to native OpenSSL via {@link DigestNI}.
 * <p>
 * Responsibilities:
 * - Resolve canonical algorithm names for native selection
 * - Lazily create a native context (ensureRef) and manage its lifecycle
 * - Delegate update/final/reset/length to {@link DigestNI} with error mapping
 * - Dispose native resources via {@link NativeReference}
 * <p>
 * Extensibility: concrete subclasses (e.g. SHA256Spi) supply only the
 * algorithm name; buffer handling and native plumbing are centralized here.
 */
abstract class DigestSpiBase extends MessageDigestSpi
{
    private final String canonicalAlgName;
    private OSSLRefWrapper refWrapper;
    private int digestLen = -1;

    protected DigestSpiBase(String algorithm)
    {
        this.canonicalAlgName = DigestUtil.getCanonicalDigestName(algorithm);
    }

    /**
     * Lazily create and memoize the native context for this SPI instance.
     * Throws {@link IllegalStateException} if the native side fails to create
     * a context for the canonical algorithm name.
     */
    private void ensureRef()
    {
        synchronized (this)
        {
            if (refWrapper == null)
            {
                long ref = DigestNISelector.DigestNI.makeInstance(canonicalAlgName);
                if (ref == 0)
                {
                    throw new IllegalStateException("Unable to create digest context for " + canonicalAlgName);
                }
                refWrapper = new OSSLRefWrapper(ref, canonicalAlgName);
            }
        }
    }

    @Override
    protected void engineUpdate(byte input)
    {
        ensureRef();
        byte[] one = new byte[]{input};
        int code = DigestNISelector.DigestNI.update(refWrapper.getReference(), one, 0, 1);
        DigestNI.handleUpdateCodes(code);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len)
    {
        ensureRef();
        int code = DigestNISelector.DigestNI.update(refWrapper.getReference(), input, offset, len);
        DigestNI.handleUpdateCodes(code);
    }

    @Override
    protected void engineUpdate(ByteBuffer input)
    {
        ensureRef();
        if (input == null)
        {
            throw new IllegalArgumentException("input is null");
        }
        int remaining = input.remaining();
        if (remaining == 0)
        {
            return; // nothing to do
        }
        if (input.hasArray())
        {
            byte[] arr = input.array();
            int off = input.arrayOffset() + input.position();
            int code = DigestNISelector.DigestNI.update(refWrapper.getReference(), arr, off, remaining);
            DigestNI.handleUpdateCodes(code);
            input.position(input.position() + remaining);
            return;
        }
        // Direct or readonly buffer: copy in reasonable chunks
        final int CHUNK = Math.min(remaining, 1 << 15); // 32KB chunks
        byte[] tmp = new byte[CHUNK];
        int pos = input.position();
        while (input.hasRemaining())
        {
            int toRead = Math.min(input.remaining(), CHUNK);
            input.get(tmp, 0, toRead);
            int code = DigestNISelector.DigestNI.update(refWrapper.getReference(), tmp, 0, toRead);
            DigestNI.handleUpdateCodes(code);
        }
        // position already advanced by get()
    }

    @Override
    protected byte[] engineDigest()
    {
        ensureRef();
        int dl = engineGetDigestLength();
        byte[] out = new byte[dl];
        int written = DigestNISelector.DigestNI.doFinal(refWrapper.getReference(), out, 0);
        DigestNI.handleFinalCodes(written);
        // reset for next use per JCA contract
        DigestNISelector.DigestNI.reset(refWrapper.getReference());
        if (written == dl)
        {
            return out;
        }
        byte[] exact = new byte[written];
        System.arraycopy(out, 0, exact, 0, written);
        return exact;
    }

    @Override
    protected int engineDigest(byte[] buf, int offset, int len) throws DigestException
    {
        ensureRef();
        int dl = engineGetDigestLength();
        if (len < dl)
        {
            throw new DigestException("output buffer too small for digest length " + dl);
        }
        int written = DigestNISelector.DigestNI.doFinal(refWrapper.getReference(), buf, offset);
        try
        {
            DigestNI.handleFinalCodes(written);
        }
        catch (IllegalArgumentException | IllegalStateException e)
        {
            throw new DigestException(e.getMessage());
        }
        finally
        {
            DigestNISelector.DigestNI.reset(refWrapper.getReference());
        }
        return written;
    }

    @Override
    protected void engineReset()
    {
        ensureRef();
        DigestNISelector.DigestNI.reset(refWrapper.getReference());
    }

    @Override
    public Object clone() throws CloneNotSupportedException
    {
        ensureRef();
        try
        {
            DigestSpiBase cloned = (DigestSpiBase) super.clone();
            long newRef = DigestNISelector.DigestNI.copy(this.refWrapper.getReference());
            if (newRef == 0)
            {
                throw new CloneNotSupportedException("native copy failed");
            }
            cloned.refWrapper = new OSSLRefWrapper(newRef, this.canonicalAlgName);
            cloned.digestLen = this.digestLen;
            return cloned;
        }
        catch (CloneNotSupportedException e)
        {
            throw e;
        }
        catch (Throwable t)
        {
            throw new CloneNotSupportedException(t.getMessage());
        }
    }

    @Override
    protected int engineGetDigestLength()
    {
        ensureRef();
        if (digestLen < 0)
        {
            digestLen = DigestNISelector.DigestNI.getDigestLength(refWrapper.getReference());
        }
        return digestLen;
    }

    /**
     * Disposal action that frees the native digest context via {@link DigestNI#dispose(long)}.
     */
    protected static class Disposer extends NativeDisposer
    {
        Disposer(long ref)
        {
            super(ref);
        }

        @Override
        protected void dispose(long reference)
        {
            DigestNISelector.DigestNI.dispose(reference);
        }
    }

    /**
     * Native reference wrapper that ties a digest context reference and name to
     * a disposer action for safe cleanup by the GC.
     */
    protected static class OSSLRefWrapper extends NativeReference
    {
        public OSSLRefWrapper(long reference, String name)
        {
            super(reference, name);
        }

        @Override
        public Runnable createAction()
        {
            return new Disposer(reference);
        }
    }
}
