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

import java.util.concurrent.atomic.AtomicBoolean;

public abstract class NativeDisposer
        implements Runnable
{
    private final long reference;
    private final AtomicBoolean called = new AtomicBoolean(false);

    public NativeDisposer(long reference)
    {
        this.reference = reference;
    }


    @Override
    public void run()
    {
        // An eager dispose() racing the daemon would otherwise free twice.
        if (!called.compareAndSet(false, true))
        {
            return;
        }

        dispose(reference);
    }

    protected abstract void dispose(long reference);

}