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
 * The single library-scoped SymbolLookup for the FIPS interface library, and
 * the symbol prefix its exports carry.
 * <p>
 * Every FIPS FFI implementation resolves through this - NEVER the
 * process-global loaderLookup(): the Loader extracts the FIPS FFI library
 * without System.load'ing it, and this lookup is what actually opens it (once,
 * cached for the JVM's lifetime).
 * <p>
 * <b>Why the prefix is a second, separate value.</b> Until 2026-08-23 the
 * library-scoped lookup was the ONLY thing keeping a FIPS FFI class off the
 * base library, because both libraries exported identical names. That made one
 * mistake - passing {@code loaderLookup()} - enough to run base-library crypto
 * with no symptom: it was demonstrated by rebinding {@code MLDSAServiceFIPSFFI}
 * and watching the entire FIPS suite stay green. The FIPS library's exports are
 * now renamed by the {@code interface/fips/ffi/<x>_fips_ffi.c} wrappers, and
 * the base FFI classes take the lookup and the prefix as INDEPENDENT
 * constructor parameters, so each single mistake is survivable or loud:
 * <ul>
 *   <li>wrong lookup, right prefix - only the FIPS library exports
 *       {@code JoFIPS_*}, so it still resolves correctly;</li>
 *   <li>right lookup, wrong prefix - the FIPS library has no unprefixed
 *       exports, so {@code orElseThrow()} fails at construction.</li>
 * </ul>
 * Bundling the two into one object (a name-rewriting SymbolLookup) would
 * restore the single point of failure and is the reason that shape was
 * rejected. Enforced by {@code FIPSLibraryLookupParityTest}.
 */
final class FIPSLibraryLookup
{
    /**
     * Prepended to every symbol the FIPS interface library exports. Must match
     * the {@code #define} blocks generated into {@code fips/ffi/*_fips_ffi.c}.
     */
    static final String SYMBOL_PREFIX = "JoFIPS_";

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
