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
    protected final PKEYReference ref;
    protected final OSSLKeyType type;


    public PKEYKeySpec(long ref)
    {
        if (ref == 0)
        {
            throw new IllegalArgumentException("'ref' cannot be zero");
        }

        this.type = OSSLKeyType.forAlias(NISelector.SpecNI.getName(ref));//   OSSLKeyType.values()[NISelector.SpecNI.getTypeOrdinal(ref)];
        this.ref = new PKEYReference(ref, type.name());

    }

    public PKEYKeySpec(long ref, OSSLKeyType type)
    {
        this.type = type;
        this.ref = new PKEYReference(ref, type.name());
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
            NISelector.SpecNI.dispose(reference);
        }
    }

    protected static class PKEYReference extends NativeReference
    {

        public PKEYReference(long reference, String name)
        {
            super(reference, name);
        }

        @Override
        protected Runnable createAction()
        {
            return new PKEYKeySpec.Disposer(reference);
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

}
