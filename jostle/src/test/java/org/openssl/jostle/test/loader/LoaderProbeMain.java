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
import org.openssl.jostle.test.JvmProbe;

import java.util.List;

/**
 * Prints the resolved {@link Loader} state as {@code PROBE key=value} lines on stdout.
 * <p>
 * Not a test. This is the entry point {@code LoaderPropertyIntegrationTest} launches in a
 * fresh JVM: every loader property is consumed once inside {@link Loader#loadImpl()} behind
 * the {@code loadAttempted} latch, so a property set after the class has initialised has no
 * effect and the only way to exercise one is to hand it to a JVM at start-up.
 * <p>
 * The class name deliberately avoids "Test" so no JUnit filter picks it up.
 */
public final class LoaderProbeMain
{
    private LoaderProbeMain()
    {
    }

    public static void main(String[] args)
    {
        //
        // Never throws - load() swallows Throwable and records the failure in
        // isLoadSuccessful()/getMessage(), which is exactly what the negative tests assert on.
        //
        Loader.load();

        emit("loadAttempted", String.valueOf(Loader.isLoadAttempted()));
        emit("loadSuccessful", String.valueOf(Loader.isLoadSuccessful()));
        emit("message", String.valueOf(Loader.getMessage()));
        emit("interfaceStrategy", String.valueOf(Loader.getInterfaceResolutionStrategy()));
        emit("interfaceType", String.valueOf(Loader.getInterfaceTypeName()));
        emit("isFFI", String.valueOf(Loader.isFFI()));
        emit("installDir", String.valueOf(Loader.getInstallDir()));
        emit("fixedInstallDir", String.valueOf(Loader.isFixedInstallDir()));

        List<String> libs = Loader.getLoadedLibs();
        emit("libCount", Integer.toString(libs.size()));
        for (int t = 0; t != libs.size(); t++)
        {
            emit("lib." + t, libs.get(t));
        }
    }

    private static void emit(String key, String value)
    {
        JvmProbe.emit(key, value);
    }
}
