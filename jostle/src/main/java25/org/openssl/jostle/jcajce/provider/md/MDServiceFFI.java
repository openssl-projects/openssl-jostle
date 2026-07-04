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

package org.openssl.jostle.jcajce.provider.md;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * FFI implementation of MDServiceNI. Symbol resolution is parameterised by a
 * SymbolLookup so the same marshalling serves both interface libraries: the
 * no-arg constructor uses the process-global loader lookup (the base
 * interface library, loaded via System.load), while the FIPS subclass passes
 * a library-scoped lookup pinned to the FIPS interface library - both export
 * the same C symbol names, so the lookup is what disambiguates them.
 */
public class MDServiceFFI implements MDServiceNI
{

    private static final Logger L = Logger.getLogger("MD_NI_FFI");
    private static final Linker linker = Linker.nativeLinker();

    private final MethodHandle allocateDigestFuncHandle;
    private final MethodHandle copyDigestFuncHandle;
    private final MethodHandle updateByteFuncHandle;
    private final MethodHandle updateBytesFuncHandle;
    private final MethodHandle disposeFuncHandle;
    private final MethodHandle digestLenFuncHandle;
    private final MethodHandle digestBytesFuncHandle;
    private final MethodHandle resetFuncHandle;


    public MDServiceFFI()
    {
        this(SymbolLookup.loaderLookup());
    }

    public MDServiceFFI(SymbolLookup lookup)
    {
        allocateDigestFuncHandle = linker.downcallHandle(lookup.find("MD_Allocate").orElseThrow(),
                FunctionDescriptor.of(
                        ValueLayout.ADDRESS, // *md_dtx
                        ValueLayout.ADDRESS, // const char *name
                        ValueLayout.JAVA_INT,// xof_len
                        ValueLayout.ADDRESS // int *err
                ), Linker.Option.critical(true)
        );

        copyDigestFuncHandle = linker.downcallHandle(lookup.find("MD_Copy").orElseThrow(),
                FunctionDescriptor.of(
                        ValueLayout.ADDRESS, // *md_ctx (the clone)
                        ValueLayout.ADDRESS, // md_ctx *src
                        ValueLayout.ADDRESS // int *err
                ), Linker.Option.critical(true)
        );

        updateByteFuncHandle = linker.downcallHandle(lookup.find("MD_UpdateByte").orElseThrow(),
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT, // return value
                        ValueLayout.ADDRESS, // *md_dtx
                        ValueLayout.JAVA_BYTE // data
                ), Linker.Option.critical(true)
        );


        updateBytesFuncHandle = linker.downcallHandle(lookup.find("MD_UpdateBytes").orElseThrow(),
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT, // return value
                        ValueLayout.ADDRESS, // md_ctx *
                        ValueLayout.ADDRESS, // uint8_t *input
                        ValueLayout.JAVA_LONG, //size_t input_size
                        ValueLayout.JAVA_INT,// in_off
                        ValueLayout.JAVA_INT // in_len
                ), Linker.Option.critical(true)
        );

        disposeFuncHandle = linker.downcallHandle(lookup.find("MD_Dispose").orElseThrow(),
                FunctionDescriptor.ofVoid(
                        ValueLayout.ADDRESS // md_ctx *
                ), Linker.Option.critical(true)
        );

        digestLenFuncHandle = linker.downcallHandle(lookup.find("MD_GetDigestLen").orElseThrow(),
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS // md_ctx *
                )
        );

        digestBytesFuncHandle = linker.downcallHandle(lookup.find("MD_Digest").orElseThrow(),
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT, // return value
                        ValueLayout.ADDRESS, // md_ctx *
                        ValueLayout.ADDRESS, // uint8_t *output
                        ValueLayout.JAVA_LONG, // size_t output_size
                        ValueLayout.JAVA_INT, // out_off
                        ValueLayout.JAVA_INT // out_len
                ), Linker.Option.critical(true));

        resetFuncHandle = linker.downcallHandle(lookup.find("MD_Reset").orElseThrow(),
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT, // return value
                        ValueLayout.ADDRESS // md_ctx *
                )
        );
    }

    @Override
    public long ni_allocateDigest(String name, int xofLen, int[] err)
    {
        try (var a = Arena.ofConfined())
        {
            var nameSeg = name == null ? MemorySegment.NULL : a.allocateFrom(name);
            var errSeg = MemorySegment.ofArray(err);
            var ctxSeg = (MemorySegment) allocateDigestFuncHandle.invokeExact(nameSeg, xofLen, errSeg);
            return ctxSeg.address();
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI MD_Allocate", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public long ni_copyDigest(long ref, int[] err)
    {
        try
        {
            var errSeg = MemorySegment.ofArray(err);
            var ctxSeg = (MemorySegment) copyDigestFuncHandle.invokeExact(
                    MemorySegment.ofAddress(ref),
                    errSeg);
            return ctxSeg.address();
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI MD_Copy", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_updateByte(long ref, byte b)
    {
        try
        {
            return (int) updateByteFuncHandle.invokeExact(
                    MemorySegment.ofAddress(ref),
                    b);
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI MD_UpdateByte", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_updateBytes(long ref, byte[] input, int offset, int len)
    {
        try
        {
            var inSeg = input == null ?
                    MemorySegment.NULL :
                    MemorySegment.ofArray(input);
            return (int) updateBytesFuncHandle.invokeExact(
                    MemorySegment.ofAddress(ref),
                    inSeg,
                    inSeg.byteSize(),
                    offset,
                    len);
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI MD_UpdateBytes", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public void ni_dispose(long reference)
    {
        try
        {
            disposeFuncHandle.invokeExact(MemorySegment.ofAddress(reference));
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI MD_Dispose", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_getDigestOutputLen(long reference)
    {
        try
        {
            return (int) digestLenFuncHandle.invokeExact(MemorySegment.ofAddress(reference));
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI MD_GetDigestLen", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_digest(long ref, byte[] out, int offset, int length)
    {
        try
        {
            var outSeg = out == null ?
                    MemorySegment.NULL :
                    MemorySegment.ofArray(out);

            return (int) digestBytesFuncHandle.invokeExact(
                    MemorySegment.ofAddress(ref),
                    outSeg,
                    outSeg.byteSize(),
                    offset, length
            );
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI MD_Digest", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_reset(long ref)
    {
        try
        {
            return (int) resetFuncHandle.invokeExact(MemorySegment.ofAddress(ref));
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI MD_Reset", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }
}
