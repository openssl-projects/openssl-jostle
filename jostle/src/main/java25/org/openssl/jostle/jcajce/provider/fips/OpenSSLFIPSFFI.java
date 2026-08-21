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

import java.lang.foreign.*;
import java.security.ProviderException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * FFI implementation of {@link OpenSSLFIPSNI}, backed by the FIPS interface
 * library (libinterface_fips_ffi).
 *
 * <p>Unlike the base FFI implementations, symbols are resolved through the
 * library-scoped {@link FIPSLibraryLookup} pinned to the extracted FIPS
 * library - never the process-global loaderLookup(); see that class for the
 * rationale.
 */
class OpenSSLFIPSFFI implements OpenSSLFIPSNI
{
    private static final Logger L = Logger.getLogger("OpenSSLFIPS");

    private static final Linker linker = Linker.nativeLinker();

    /**
     * Buffer for {@link #moduleVersion()}. The C side writes
     * "&lt;name&gt; &lt;version&gt;" and truncates to fit; 256 is far above
     * anything a provider reports ("OpenSSL FIPS Provider 3.5.7" is 27).
     */
    private static final int VERSION_BUFFER_BYTES = 256;

    private final SymbolLookup lookup;

    OpenSSLFIPSFFI()
    {
        lookup = FIPSLibraryLookup.get();
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
            // ProviderException (not a bare RuntimeException) so a failed FIPS
            // module init surfaces as the JCA-conventional type, consistent with
            // FIPSOpenSSL.initialise's JO_FIPS_* -> typed-exception mapping.
            throw new ProviderException(t.getMessage(), t);
        }

    }

    @Override
    public int canFetch(int opType, String name)
    {
        try (Arena arena = Arena.ofConfined())
        {
            var func = lookup.find("JoFips_can_fetch").orElseThrow();
            var handle = linker.downcallHandle(func, FunctionDescriptor.of(ValueLayout.JAVA_INT,
                    ValueLayout.JAVA_INT, ValueLayout.ADDRESS));

            var n = name != null ? arena.allocateFrom(name) : MemorySegment.ofAddress(0);

            return (int) handle.invokeExact(opType, n);
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "ffi JoFips_can_fetch", t);
            throw new ProviderException(t.getMessage(), t);
        }
    }

    @Override
    public String moduleVersion()
    {
        try (Arena arena = Arena.ofConfined())
        {
            var func = lookup.find("JoFips_module_version").orElseThrow();
            // Writes into a caller-supplied buffer rather than returning a
            // heap pointer, so there is nothing to free across the boundary.
            var handle = linker.downcallHandle(func, FunctionDescriptor.of(ValueLayout.JAVA_INT,
                    ValueLayout.ADDRESS, ValueLayout.JAVA_INT));

            var buf = arena.allocate(VERSION_BUFFER_BYTES);
            int written = (int) handle.invokeExact(buf, VERSION_BUFFER_BYTES);
            if (written <= 0)
            {
                return null;
            }
            return buf.getString(0);
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "ffi JoFips_module_version", t);
            throw new ProviderException(t.getMessage(), t);
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
