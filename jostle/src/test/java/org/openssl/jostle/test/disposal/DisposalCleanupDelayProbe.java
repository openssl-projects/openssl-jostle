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

import org.openssl.jostle.disposal.DisposalDaemon;
import org.openssl.jostle.disposal.DisposalListener;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.security.MessageDigest;
import java.security.Security;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;

/**
 * Child process for the cleanup-delay cell. The delay is read once in the
 * daemon's static initialiser, so it can only be exercised in a JVM started with
 * the property already set.
 *
 * <p>Prints the NAME OF THE THREAD the disposal ran on. That is the
 * discriminator: the immediate path runs on the daemon thread, the delayed path
 * on the cleanup executor. Printing merely "disposed" would pass either way.
 */
public final class DisposalCleanupDelayProbe
{
    private DisposalCleanupDelayProbe()
    {
    }

    public static final String PREFIX = "DISPOSED_ON=";

    public static void main(String[] args) throws Exception
    {
        Security.addProvider(new JostleProvider());

        final AtomicReference<String> thread = new AtomicReference<String>();
        DisposalDaemon.addListener(new DisposalListener()
        {
            public void registered(long ref, String label)
            {
            }

            public void disposing(long ref)
            {
            }

            public void disposed(long ref)
            {
                thread.compareAndSet(null, Thread.currentThread().getName());
            }

            public void failed(long ref, Throwable t)
            {
            }
        });

        MessageDigest md = MessageDigest.getInstance("SHA-256", JostleProvider.PROVIDER_NAME);
        md.update(new byte[16]);
        md.digest();
        md = null;

        DisposalDrain.drain(new BooleanSupplier()
        {
            public boolean getAsBoolean()
            {
                return thread.get() != null;
            }
        });

        System.out.println(PREFIX + thread.get());
    }
}
