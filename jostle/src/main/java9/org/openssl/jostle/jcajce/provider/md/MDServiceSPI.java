/*
 *
 *   Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *   Licensed under the Apache License 2.0 (the "License"). You may not use
 *   this file except in compliance with the License.  You can obtain a copy
 *   in the file LICENSE in the source distribution or at
 *   https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.md;

import org.openssl.jostle.disposal.NativeDisposer;
import org.openssl.jostle.disposal.NativeReference;
import org.openssl.jostle.jcajce.provider.NISelector;

import java.lang.ref.Reference;
import java.security.DigestException;
import java.security.MessageDigestSpi;

public class MDServiceSPI extends MessageDigestSpi implements Cloneable
{
    private static final MDServiceNI mdServiceNI = NISelector.MDServiceNI;

    private final MDReference ref;
    private final String algorithm;

    public MDServiceSPI(String algorithm)
    {

        //
        // algoritm name must be something that OpenSSL can resolve
        //
        this.algorithm = algorithm;
        this.ref = new MDReference(mdServiceNI.allocateDigest(algorithm, 0), algorithm);
    }

    public MDServiceSPI(String algorithm, int xofLen)
    {
        //
        // algoritm name must be something that OpenSSL can resolve
        //
        this.algorithm = algorithm;
        this.ref = new MDReference(mdServiceNI.allocateDigest(algorithm, xofLen), algorithm);
    }

    //
    // Wrapping constructor for clone(): adopts an already-allocated native
    // digest context (a copy produced by MDServiceNI.copyDigest). Distinct
    // from the (String, int xofLen) constructor, which *allocates* a fresh
    // context — this one takes ownership of an existing MDReference.
    //
    private MDServiceSPI(String algorithm, MDReference clonedRef)
    {
        this.algorithm = algorithm;
        this.ref = clonedRef;
    }


    @Override
    protected void engineUpdate(byte input)
    {
        try
        {
            mdServiceNI.engineUpdate(ref.getReference(), input);
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len)
    {
        try
        {
            mdServiceNI.engineUpdate(ref.getReference(), input, offset, len);
        } finally
        {
            Reference.reachabilityFence(this);
        }
    }

    @Override
    protected byte[] engineDigest()
    {

        try
        {
            byte[] out = new byte[mdServiceNI.getDigestOutputLen(ref.getReference())];
            mdServiceNI.digest(ref.getReference(), out, 0, out.length);
            mdServiceNI.reset(ref.getReference());
            return out;
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    @Override
    protected int engineDigest(byte[] buf, int offset, int len) throws DigestException
    {
        try
        {
            // Per the MessageDigestSpi contract, "buffer too small for the
            // digest output" must surface as DigestException rather than the
            // IllegalArgumentException the NI layer would otherwise throw.
            int needed = mdServiceNI.getDigestOutputLen(ref.getReference());
            if (len < needed)
            {
                throw new DigestException("output buffer too small (need " + needed + ", got " + len + ")");
            }
            int l = mdServiceNI.digest(ref.getReference(), buf, offset, len);
            mdServiceNI.reset(ref.getReference());
            return l;
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    @Override
    protected void engineReset()
    {
        try
        {
            mdServiceNI.reset(ref.getReference());
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    @Override
    protected int engineGetDigestLength()
    {
        try
        {
            return mdServiceNI.getDigestOutputLen(ref.getReference());
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    //
    // MessageDigest.clone() routes here (the JCA Delegate calls Object.clone()
    // on the SPI when it is Cloneable). A shallow Object.clone() would share
    // the single native EVP_MD_CTX between the original and the copy — a
    // double-free and cross-talk hazard — so we deep-copy the native state via
    // EVP_MD_CTX_copy_ex and hand the clone its own MDReference/Disposer.
    //
    @Override
    public Object clone() throws CloneNotSupportedException
    {
        try
        {
            long clonedRef = mdServiceNI.copyDigest(ref.getReference());
            return new MDServiceSPI(algorithm, new MDReference(clonedRef, algorithm));
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    private static class Disposer extends NativeDisposer
    {
        public Disposer(long reference)
        {
            super(reference);
        }

        @Override
        protected void dispose(long reference)
        {
            mdServiceNI.dispose(reference);
        }
    }

    private static class MDReference extends NativeReference
    {

        public MDReference(long reference, String name)
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
