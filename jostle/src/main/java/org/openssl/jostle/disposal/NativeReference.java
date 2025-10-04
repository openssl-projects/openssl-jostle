/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.disposal;

public abstract class NativeReference
        implements Disposable
{
    protected final long reference;
    protected final String label;


    public NativeReference(long reference, String name)
    {
        this.reference = reference;
        this.label = "Reference(" + name + ") 0x" + Long.toHexString(reference);
        DisposalDaemon.addDisposable(this);
    }


    public final Runnable getDisposeAction()
    {
        return createAction();
    }

    protected abstract Runnable createAction();


    public long getReference()
    {
        return reference;
    }

    public String toString()
    {
        return label;
    }
}
