/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.rand;

/**
 * A caller's {@code SecureRandom} exception cannot cross the OpenSSL callback
 * frame — the JVM may terminate — so the RAND bridge records it here and
 * {@code baseErrorHandler} attaches it as the cause of the failure the caller
 * sees.
 *
 * <p>Public for the cross-package read, but this package is deliberately NOT
 * exported by {@code module-info}: an application able to call
 * {@link #record(Throwable)} could plant a cause into the next provider failure
 * on its thread.
 */
public final class UpCallFailure
{
    private static final ThreadLocal<Throwable> PENDING = new ThreadLocal<Throwable>();

    private UpCallFailure()
    {
    }

    /** Replaces any previous value: only the most recent up-call can be relevant. */
    public static void record(Throwable t)
    {
        PENDING.set(t);
    }

    /** Returns the pending throwable and clears it, so it cannot be consumed twice. */
    public static Throwable takeAndClear()
    {
        Throwable t = PENDING.get();
        if (t != null)
        {
            PENDING.remove();
        }
        return t;
    }
}
