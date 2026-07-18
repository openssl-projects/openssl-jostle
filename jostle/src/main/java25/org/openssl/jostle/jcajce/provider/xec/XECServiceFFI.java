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
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * FFI binding for the {@code JoXEC_*} symbols exported by
 * {@code interface/nonfips/ffi/xec_ni_ffi.c}. Only key generation is XEC-specific;
 * key agreement reuses the {@code JoEC_*} kex symbols via
 * {@code ECServiceFFI} (the C kex is type-agnostic).
 */
// Symbol resolution is parameterised by a SymbolLookup so the same
// marshalling serves both interface libraries (see MDServiceFFI).
public class XECServiceFFI implements XECServiceNI
{
    private static final Logger L = Logger.getLogger("XEC_NI_FFI");
    private static final Linker linker = Linker.nativeLinker();

    private final MethodHandle generateKeyPairH;
    // Lookup-independent constants for the RandSource entropy upcall stub.
    private static final FunctionDescriptor entropyFd = EntropyUpcall.DESCRIPTOR;
    private static final MethodType entropyMt = EntropyUpcall.METHOD_TYPE;

    public XECServiceFFI()
    {
        this(SymbolLookup.loaderLookup());
    }

    public XECServiceFFI(SymbolLookup lookup)
    {
        // JoXEC_generateKeyPair(const char* name, int32_t* err, void* rnd_src) -> key_spec*
        generateKeyPairH = linker.downcallHandle(
                lookup.find("JoXEC_generateKeyPair").orElseThrow(),
                FunctionDescriptor.of(
                        ValueLayout.ADDRESS,    // returns key_spec*
                        ValueLayout.ADDRESS,    // name
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

    /** Allocate a NUL-terminated UTF-8 C string in the arena, or NULL. */
    private static MemorySegment nativeString(Arena a, String s)
    {
        if (s == null)
        {
            return MemorySegment.NULL;
        }
        byte[] utf8 = s.getBytes(StandardCharsets.UTF_8);
        MemorySegment seg = a.allocate(utf8.length + 1);
        seg.asByteBuffer().put(utf8);
        seg.set(ValueLayout.JAVA_BYTE, utf8.length, (byte) 0);
        return seg;
    }

    @Override
    public long ni_generateKeyPair(String name, int[] err, RandSource rndSource)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment errSeg = a.allocate(ValueLayout.JAVA_INT);
            MemorySegment ref = (MemorySegment) generateKeyPairH.invokeExact(
                    nativeString(a, name), errSeg, entropyStub(a, rndSource));
            err[0] = errSeg.get(ValueLayout.JAVA_INT, 0);
            return ref.address();
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI XEC_generateKeyPair", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }
}
