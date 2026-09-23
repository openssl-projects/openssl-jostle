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

package org.openssl.jostle.test.disposal;

import java.util.function.BooleanSupplier;

/**
 * The one collection loop every disposal test uses, so the cap is one number.
 *
 * <p>The cap is fixed from a loaded measurement: K instances of every family on
 * JDK 8 and 25, both bridges, both modules, drained in one cycle, and the cap is
 * {@code max(300, 100 x measured)}.
 */
public final class DisposalDrain
{
    private DisposalDrain()
    {
    }

    /** Collection cycles before a drain is declared failed. */
    public static final int CAP = 300;

    /** Between cycles, so the daemon thread can run. */
    public static final long PAUSE_MS = 10;

    /**
     * Forces collections until {@code done} holds or the cap is reached.
     *
     * @return the cycles used; equal to {@link #CAP} when the condition never held
     */
    public static int drain(BooleanSupplier done) throws InterruptedException
    {
        int cycles = 0;
        while (cycles < CAP && !done.getAsBoolean())
        {
            cycles++;
            System.gc();
            Thread.sleep(PAUSE_MS);
        }
        return cycles;
    }
}
