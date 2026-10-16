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

package org.openssl.jostle.jcajce.provider.xec;

import org.openssl.jostle.rand.EntropyUpcall;
import org.openssl.jostle.rand.RandSource;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * FFM binding for the {@code JoXEC_*} symbols exported by
 * {@code interface/nonfips/ffm/xec_ni_ffm.c}. Only key generation is XEC-specific;
 * key agreement reuses the {@code JoEC_*} kex symbols via
 * {@code ECServiceFFM} (the C kex is type-agnostic).
 */
// Symbol resolution is parameterised by a SymbolLookup so the same
// marshalling serves both interface libraries (see MDServiceFFM).
public class XECServiceFFM implements XECServiceNI
{
    private static final Logger L = Logger.getLogger("XEC_NI_FFM");
    private static final Linker linker = Linker.nativeLinker();

    private final MethodHandle generateKeyPairH;
    // Lookup-independent constants for the RandSource entropy upcall stub.
    private static final FunctionDescriptor entropyFd = EntropyUpcall.DESCRIPTOR;
    private static final MethodType entropyMt = EntropyUpcall.METHOD_TYPE;

    public XECServiceFFM()
    {
        this(SymbolLookup.loaderLookup());
    }

    public XECServiceFFM(SymbolLookup lookup)
    {
        this(lookup, "");
    }

    /**
     * @param lookup    the library to resolve against.
     * @param symPrefix prepended to every symbol name. Empty for the base
     *                  library; {@code "JoFIPS_"} for the FIPS one, whose
     *                  exports are renamed by the {@code <x>_fips_ffm.c}
     *                  wrappers. Deliberately SEPARATE from {@code lookup}:
     *                  two independent values mean either mistake alone
     *                  still resolves correctly or fails loudly, where a
     *                  single bundled value made a wrong lookup silently
     *                  run base-library crypto.
     */
    public XECServiceFFM(SymbolLookup lookup, String symPrefix)
    {
        // JoXEC_generateKeyPair(const char* name, size_t name_len, int32_t* err, void* rnd_src) -> key_spec*
        generateKeyPairH = linker.downcallHandle(
                lookup.find(symPrefix + "JoXEC_generateKeyPair").orElseThrow(),
                FunctionDescriptor.of(
                        ValueLayout.ADDRESS,    // returns key_spec*
                        ValueLayout.ADDRESS,    // name
                        ValueLayout.JAVA_LONG,  // name_len, UTF-8 bytes
                        ValueLayout.ADDRESS,    // err out
                        ValueLayout.ADDRESS));  // rnd_src upcall

    }

    private static MemorySegment entropyStub(Arena arena, RandSource src)
    {
        if (src == null)
        {
            return MemorySegment.NULL;
        }
        try
        {
            MethodHandle h = MethodHandles.lookup()
                    .findVirtual(RandSource.class, "getRandomSegment", entropyMt)
                    .bindTo(src);
            return linker.upcallStub(h, entropyFd, arena);
        }
        catch (Throwable t)
        {
            throw new RuntimeException("unable to create entropy upcall stub", t);
        }
    }

    /** A name as its UTF-8 bytes, or null; the C takes a NUL-terminated copy plus this count. */
    private static byte[] utf8(String name)
    {
        return name == null ? null : name.getBytes(StandardCharsets.UTF_8);
    }

    private static MemorySegment nameSeg(Arena a, byte[] utf8)
    {
        return utf8 == null ? MemorySegment.NULL
                : a.allocateFrom(ValueLayout.JAVA_BYTE, Arrays.copyOf(utf8, utf8.length + 1));
    }

    @Override
    public long ni_generateKeyPair(String name, int[] err, RandSource rndSource)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment errSeg = a.allocate(ValueLayout.JAVA_INT);
            byte[] nameBytes = utf8(name);
            MemorySegment ref = (MemorySegment) generateKeyPairH.invokeExact(
                    nameSeg(a, nameBytes), nameBytes == null ? 0L : (long) nameBytes.length, errSeg,
                    entropyStub(a, rndSource));
            err[0] = errSeg.get(ValueLayout.JAVA_INT, 0);
            return ref.address();
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFM XEC_generateKeyPair", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }
}
