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

package org.openssl.jostle.jcajce.provider.blockcipher;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * FFM binding for the {@code JoCCM_*} symbols exported by
 * {@code interface/nonfips/ffm/ccm_ni_ffm.c}. CCM is one-shot — there's no
 * streaming update path; the SPI buffers everything and calls
 * {@link #ni_doFinal} once.
 */
// Symbol resolution is parameterised by a SymbolLookup so the same
// marshalling serves both interface libraries: the no-arg constructor uses
// the process-global loader lookup (base library), the FIPS subclass passes
// a library-scoped lookup pinned to the FIPS interface library.
public class CCMCipherFFM implements CCMCipherNI
{
    private static final Logger L = Logger.getLogger("CCM_NI_FFM");
    private static final Linker linker = Linker.nativeLinker();

    private final MethodHandle makeInstanceH;
    private final MethodHandle disposeH;
    private final MethodHandle initH;
    private final MethodHandle doFinalH;
    private final MethodHandle getOutputSizeH;


    public CCMCipherFFM()
    {
        this(SymbolLookup.loaderLookup());
    }

    public CCMCipherFFM(SymbolLookup lookup)
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
    public CCMCipherFFM(SymbolLookup lookup, String symPrefix)
    {
        makeInstanceH = linker.downcallHandle(
                lookup.find(symPrefix + "JoCCM_makeInstance").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.ADDRESS,
                        ValueLayout.JAVA_INT,    // cipher_id
                        ValueLayout.ADDRESS));   // *err

        disposeH = linker.downcallHandle(
                lookup.find(symPrefix + "JoCCM_dispose").orElseThrow(),
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));

        // JoCCM_init(ctx, op_mode, key*, key_len, iv*, iv_len, tag_len) -> int
        initH = linker.downcallHandle(
                lookup.find(symPrefix + "JoCCM_init").orElseThrow(),
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,    // ctx
                        ValueLayout.JAVA_INT,   // op_mode
                        ValueLayout.ADDRESS,    // key
                        ValueLayout.JAVA_LONG,  // key_len (size_t)
                        ValueLayout.ADDRESS,    // iv
                        ValueLayout.JAVA_LONG,  // iv_len (size_t)
                        ValueLayout.JAVA_INT),  // tag_len
                Linker.Option.critical(true));

        // JoCCM_doFinal(ctx, aad*, aad_size, aad_len,
        //               input*, input_size, in_off, in_len,
        //               output*, output_size, out_off) -> int
        doFinalH = linker.downcallHandle(
                lookup.find(symPrefix + "JoCCM_doFinal").orElseThrow(),
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,    // ctx
                        ValueLayout.ADDRESS,    // aad
                        ValueLayout.JAVA_LONG,  // aad_size
                        ValueLayout.JAVA_INT,   // aad_len
                        ValueLayout.ADDRESS,    // input
                        ValueLayout.JAVA_LONG,  // input_size
                        ValueLayout.JAVA_INT,   // in_off
                        ValueLayout.JAVA_INT,   // in_len
                        ValueLayout.ADDRESS,    // output
                        ValueLayout.JAVA_LONG,  // output_size
                        ValueLayout.JAVA_INT),  // out_off
                Linker.Option.critical(true));

        getOutputSizeH = linker.downcallHandle(
                lookup.find(symPrefix + "JoCCM_getOutputSize").orElseThrow(),
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,    // ctx
                        ValueLayout.JAVA_INT,   // op_mode
                        ValueLayout.JAVA_INT)); // input_len
    }


    @Override
    public long ni_makeInstance(int cipherId, int[] err)
    {
        // Fails on an unusable err array before a context exists.
        err[0] = 0;
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment errSeg = a.allocate(ValueLayout.JAVA_INT);
            MemorySegment ref = (MemorySegment) makeInstanceH.invokeExact(cipherId, errSeg);
            err[0] = errSeg.get(ValueLayout.JAVA_INT, 0);
            return ref.address();
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFM CCM_makeInstance", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public void ni_dispose(long ref)
    {
        try
        {
            disposeH.invokeExact(MemorySegment.ofAddress(ref));
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFM CCM_dispose", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_init(long ref, int opMode, byte[] key, byte[] iv, int tagLen)
    {
        try
        {
            MemorySegment keySeg = segment(key);
            MemorySegment ivSeg = segment(iv);
            return (int) initH.invokeExact(MemorySegment.ofAddress(ref), opMode,
                    keySeg, keySeg.byteSize(),
                    ivSeg, ivSeg.byteSize(),
                    tagLen);
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFM CCM_init", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_doFinal(long ref,
                          byte[] aad, int aadLen,
                          byte[] input, int inOff, int inLen,
                          byte[] output, int outOff)
    {
        try
        {
            MemorySegment aadSeg = segment(aad);
            MemorySegment inSeg = segment(input);
            MemorySegment outSeg = segment(output);
            return (int) doFinalH.invokeExact(MemorySegment.ofAddress(ref),
                    aadSeg, aadSeg.byteSize(), aadLen,
                    inSeg, inSeg.byteSize(), inOff, inLen,
                    outSeg, outSeg.byteSize(), outOff);
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFM CCM_doFinal", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_getOutputSize(long ref, int opMode, int inputLen)
    {
        try
        {
            return (int) getOutputSizeH.invokeExact(MemorySegment.ofAddress(ref), opMode, inputLen);
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFM CCM_getOutputSize", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }


    /** The heap array itself, or NULL; the critical downcall reads and writes it in place. */
    private static MemorySegment segment(byte[] array)
    {
        return array == null ? MemorySegment.NULL : MemorySegment.ofArray(array);
    }
}
