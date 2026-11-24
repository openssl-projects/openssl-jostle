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

package org.openssl.jostle.test.loader;

import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.test.JvmProbe;

/**
 * Constructs the provider and prints what the caller sees as {@code PROBE key=value} lines.
 * <p>
 * Not a test. {@code LoaderPropertyIntegrationTest} launches it in a fresh JVM, because the
 * loader reads os.name and os.arch once, at first load.
 */
public final class ProviderConstructionProbeMain
{
    private ProviderConstructionProbeMain()
    {
    }

    public static void main(String[] args)
    {
        try
        {
            new JostleProvider();
            JvmProbe.emit("constructed", "true");
        }
        catch (Throwable t)
        {
            JvmProbe.emit("constructed", "false");
            JvmProbe.emit("exceptionType", t.getClass().getName());
            JvmProbe.emit("exceptionMessage", String.valueOf(t.getMessage()));
        }
        JvmProbe.emit("loaderMessage", String.valueOf(Loader.getMessage()));
    }
}
