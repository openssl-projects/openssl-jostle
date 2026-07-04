/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.spec;

import org.openssl.jostle.disposal.NativeDisposer;
import org.openssl.jostle.disposal.NativeReference;
import org.openssl.jostle.jcajce.provider.NISelector;


/**
 * A Key Spec that wraps an OpenSSL PKEY, anything using a PKEY must keep a reference to this or it's inheritors
 * or it will be collected independently and may result in use after free.
 */
public class PKEYKeySpec
{
    // Instance field, not a NISelector static: the spec is bound to whichever
    // NI backend created the PKEY - NISelector.SpecNI for JSL,
    // FIPSNISelector.SpecNI (the FIPS interface library) for JSLFIPS - so
    // name lookup and disposal go through the library that owns the key.
    protected final SpecNI specNI;
    protected final PKEYReference ref;
    protected final OSSLKeyType type;


    public PKEYKeySpec(long ref)
    {
        this(NISelector.SpecNI, ref);
    }

    public PKEYKeySpec(SpecNI specNI, long ref)
    {
        if (ref == 0)
        {
            throw new IllegalArgumentException("'ref' cannot be zero");
        }

        this.specNI = specNI;
        String name = specNI.getName(ref);
        if (name == null)
        {
            throw new IllegalArgumentException("unable to determine algorithm name for ref");
        }
        this.type = OSSLKeyType.forAlias(name);
        if (this.type == null)
        {
            throw new IllegalArgumentException("unknown algorithm: " + name);
        }
        this.ref = new PKEYReference(specNI, ref, type.name());
    }

    public PKEYKeySpec(long ref, OSSLKeyType type)
    {
        this(NISelector.SpecNI, ref, type);
    }

    public PKEYKeySpec(SpecNI specNI, long ref, OSSLKeyType type)
    {
        if (ref == 0)
        {
            throw new IllegalArgumentException("'ref' cannot be zero");
        }
        if (type == null)
        {
            throw new IllegalArgumentException("'type' cannot be null");
        }
        this.specNI = specNI;
        this.type = type;
        this.ref = new PKEYReference(specNI, ref, type.name());
    }


    protected static class Disposer
            extends NativeDisposer
    {
        // The NI that allocated the PKEY frees it - a FIPS-allocated key
        // must be disposed through the FIPS interface library.
        private final SpecNI specNI;

        Disposer(SpecNI specNI, long ref)
        {
            super(ref);
            this.specNI = specNI;
        }

        @Override
        protected void dispose(long reference)
        {
            specNI.dispose(reference);
        }
    }

    protected static class PKEYReference extends NativeReference
    {
        private final SpecNI specNI;

        public PKEYReference(SpecNI specNI, long reference, String name)
        {
            super(reference, name);
            this.specNI = specNI;
        }

        @Override
        protected Runnable createAction()
        {
            return new PKEYKeySpec.Disposer(specNI, reference);
        }
    }

    public long getReference()
    {
        return ref.getReference();
    }

    public OSSLKeyType getType()
    {
        return type;
    }

    /**
     * The NI backend that owns this PKEY - FIPS-aware consumers pass it on
     * so every operation on the key stays within the library that created it.
     */
    public SpecNI getSpecNI()
    {
        return specNI;
    }
}
