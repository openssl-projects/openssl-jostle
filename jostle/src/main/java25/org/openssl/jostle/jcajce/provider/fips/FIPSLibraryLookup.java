/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.fips;

import org.openssl.jostle.Loader;

import java.lang.foreign.Arena;
import java.lang.foreign.SymbolLookup;
import java.nio.file.Paths;

/**
 * The single library-scoped SymbolLookup for the FIPS interface library.
 * Every FIPS FFI implementation resolves through this - NEVER the
 * process-global loaderLookup(): the FIPS library shares export names with
 * the base interface library, and the process-global lookup would resolve
 * those names by load order. The Loader extracts the FIPS FFI library
 * without System.load'ing it for the same reason; this lookup is what
 * actually opens it (once, cached for the JVM's lifetime).
 */
final class FIPSLibraryLookup
{
    private static SymbolLookup lookup;

    private FIPSLibraryLookup()
    {
    }

    static synchronized SymbolLookup get()
    {
        if (lookup == null)
        {
            String path = Loader.getFipsInterfaceLibPath();
            if (path == null)
            {
                throw new IllegalStateException(
                        "FIPS interface library is not available: " + Loader.getFipsMessage());
            }
            lookup = SymbolLookup.libraryLookup(Paths.get(path), Arena.global());
        }
        return lookup;
    }
}
