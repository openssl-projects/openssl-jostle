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

package org.openssl.jostle.jcajce.provider.fips;

import org.openssl.jostle.FFI;
import org.openssl.jostle.Loader;

import java.lang.foreign.*;
import java.nio.file.Paths;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * FFI implementation of {@link OpenSSLFIPSNI}, backed by the FIPS interface
 * library (libinterface_fips_ffi).
 *
 * <p>Unlike the base FFI implementations, symbols are resolved through a
 * library-scoped SymbolLookup pinned to the extracted FIPS library - NEVER
 * the process-global loaderLookup(): the FIPS library shares export names
 * with the base interface library, and the process-global lookup would
 * resolve those names by load order. The Loader extracts the FIPS FFI
 * library without System.load'ing it for the same reason; the
 * libraryLookup here is what actually opens it.
 */
class OpenSSLFIPSFFI implements OpenSSLFIPSNI
{
    private static final Logger L = Logger.getLogger("OpenSSLFIPS");

    private static final Linker linker = Linker.nativeLinker();

    private final SymbolLookup lookup;

    OpenSSLFIPSFFI()
    {
        String path = Loader.getFipsInterfaceLibPath();
        if (path == null)
        {
            throw new IllegalStateException(
                    "FIPS interface library is not available: " + Loader.getFipsMessage());
        }
        lookup = SymbolLookup.libraryLookup(Paths.get(path), Arena.global());
    }

    @Override
    public int setOSSLFIPSModule(String moduleDir, String providerName, String configPath)
    {
        try (Arena arena = Arena.ofConfined())
        {
            var func = lookup.find("JoFips_set_openssl_module").orElseThrow();
            var handle = linker.downcallHandle(func, FunctionDescriptor.of(ValueLayout.JAVA_INT,
                    ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));

            var dir = moduleDir != null ? arena.allocateFrom(moduleDir) : MemorySegment.ofAddress(0);
            var name = providerName != null ? arena.allocateFrom(providerName) : MemorySegment.ofAddress(0);
            var cnf = configPath != null ? arena.allocateFrom(configPath) : MemorySegment.ofAddress(0);

            return (int) handle.invokeExact(dir, name, cnf);
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "ffi JoFips_set_openssl_module", t);
            throw new RuntimeException(t.getMessage(), t);
        }

    }

    @Override
    public String getOSSLErrors()
    {
        String result = null;
        try (Arena arena = Arena.ofConfined())
        {
            var func = lookup.find("get_ossl_errors").orElseThrow();
            var len = arena.allocate(ValueLayout.ADDRESS);
            var handle = linker.downcallHandle(func, FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));

            MemorySegment content = null;

            try
            {
                content = (MemorySegment) handle.invokeExact(len);
                content = content.reinterpret(len.get(ValueLayout.JAVA_LONG, 0));
                result = content.getString(0);
            }
            catch (RuntimeException e)
            {
                throw e;
            }
            catch (Throwable t)
            {
                throw new RuntimeException(t.getMessage(), t);
            }
            finally
            {
                if (content != null)
                {
                    FFI.insecureUnsafeFree(content);
                }
            }
        }
        return result;
    }
}
