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
    private final Runnable disposeAction;


    /**
     * @param reference     the native handle this reference guards.
     * @param name          label fragment for diagnostics.
     * @param disposeAction the action that frees the native handle. It MUST be
     *                      built by the concrete subclass from its constructor
     *                      parameters and passed in here — never captured from
     *                      an instance field. {@link DisposalDaemon#addDisposable}
     *                      calls {@link #getDisposeAction()} from within this
     *                      constructor (a deliberate registration point), so any
     *                      state the action needs must already be set. Reading a
     *                      subclass field at that moment yields its default (null)
     *                      because the subclass constructor body has not run yet.
     */
    public NativeReference(long reference, String name, Runnable disposeAction)
    {
        this.reference = reference;
        this.label = "Reference(" + name + ") 0x" + Long.toHexString(reference);
        this.disposeAction = disposeAction;
        DisposalDaemon.addDisposable(this);
    }


    public final Runnable getDisposeAction()
    {
        return disposeAction;
    }


    public final long getReference()
    {
        return reference;
    }

    public final String toString()
    {
        return label;
    }
}
