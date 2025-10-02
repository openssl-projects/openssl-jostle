/*
 *  Copyright 2005-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://www.openssl.org/source/license.html
 *
 */

package org.openssl.jostle.disposal;

public abstract class NativeDisposer
        implements Runnable
{
    private final long reference;
    private boolean called = false;

    public NativeDisposer(long reference)
    {
        this.reference = reference;
    }


    @Override
    public void run()
    {
        if (called)
        {
            return;
        }
        called = true;

        dispose(reference);
    }

    protected abstract void dispose(long reference);

}