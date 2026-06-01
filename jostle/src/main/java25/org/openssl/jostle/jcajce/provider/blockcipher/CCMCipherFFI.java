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
 * FFI binding for the {@code JoCCM_*} symbols exported by
 * {@code interface/ffi/ccm_ni_ffi.c}. CCM is one-shot — there's no
 * streaming update path; the SPI buffers everything and calls
 * {@link #ni_doFinal} once.
 */
public class CCMCipherFFI implements CCMCipherNI
{
    private static final Logger L = Logger.getLogger("CCM_NI_FFI");
    private static final SymbolLookup lookup = SymbolLookup.loaderLookup();
    private static final Linker linker = Linker.nativeLinker();

    private static final MethodHandle makeInstanceH;
    private static final MethodHandle disposeH;
    private static final MethodHandle initH;
    private static final MethodHandle doFinalH;
    private static final MethodHandle getOutputSizeH;


    static
    {
        makeInstanceH = linker.downcallHandle(
                lookup.find("JoCCM_makeInstance").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.ADDRESS,
                        ValueLayout.JAVA_INT,    // cipher_id
                        ValueLayout.ADDRESS));   // *err

        disposeH = linker.downcallHandle(
                lookup.find("JoCCM_dispose").orElseThrow(),
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));

        // JoCCM_init(ctx, op_mode, key*, key_len, iv*, iv_len, tag_len) -> int
        initH = linker.downcallHandle(
                lookup.find("JoCCM_init").orElseThrow(),
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,    // ctx
                        ValueLayout.JAVA_INT,   // op_mode
                        ValueLayout.ADDRESS,    // key
                        ValueLayout.JAVA_LONG,  // key_len (size_t)
                        ValueLayout.ADDRESS,    // iv
                        ValueLayout.JAVA_LONG,  // iv_len (size_t)
                        ValueLayout.JAVA_INT)); // tag_len

        // JoCCM_doFinal(ctx, aad*, aad_size, aad_len,
        //               input*, input_size, in_off, in_len,
        //               output*, output_size, out_off) -> int
        doFinalH = linker.downcallHandle(
                lookup.find("JoCCM_doFinal").orElseThrow(),
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
                        ValueLayout.JAVA_INT)); // out_off

        getOutputSizeH = linker.downcallHandle(
                lookup.find("JoCCM_getOutputSize").orElseThrow(),
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,    // ctx
                        ValueLayout.JAVA_INT,   // op_mode
                        ValueLayout.JAVA_INT)); // input_len
    }


    @Override
    public long ni_makeInstance(int cipherId, int[] err)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment errSeg = a.allocate(ValueLayout.JAVA_INT);
            MemorySegment ref = (MemorySegment) makeInstanceH.invokeExact(cipherId, errSeg);
            err[0] = errSeg.get(ValueLayout.JAVA_INT, 0);
            return ref.address();
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI CCM_makeInstance", t);
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
            L.log(Level.WARNING, "FFI CCM_dispose", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_init(long ref, int opMode, byte[] key, byte[] iv, int tagLen)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment ctx = MemorySegment.ofAddress(ref);
            MemorySegment keySeg = nativeCopy(a, key);
            MemorySegment ivSeg  = nativeCopy(a, iv);
            long keyLen = (key == null) ? 0L : key.length;
            long ivLen  = (iv == null)  ? 0L : iv.length;
            return (int) initH.invokeExact(ctx, opMode,
                    keySeg, keyLen,
                    ivSeg, ivLen,
                    tagLen);
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI CCM_init", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_doFinal(long ref,
                          byte[] aad, int aadLen,
                          byte[] input, int inOff, int inLen,
                          byte[] output, int outOff)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment ctx = MemorySegment.ofAddress(ref);
            MemorySegment aadSeg = nativeCopy(a, aad);
            long aadSize = (aad == null) ? 0L : aad.length;

            MemorySegment inSeg = nativeCopy(a, input);
            long inSize = (input == null) ? 0L : input.length;

            // Output buffer: caller-provided heap byte[]. Allocate a
            // native copy, invoke, then copy back only the bytes the
            // C side wrote.
            MemorySegment outSeg;
            long outSize;
            if (output == null)
            {
                outSeg = MemorySegment.NULL;
                outSize = 0L;
            }
            else
            {
                outSeg = a.allocate(output.length);
                outSize = output.length;
            }

            int rc = (int) doFinalH.invokeExact(ctx,
                    aadSeg, aadSize, aadLen,
                    inSeg, inSize, inOff, inLen,
                    outSeg, outSize, outOff);

            // Mirror the RSAOAEPCipherFFI convention: copy back only the
            // bytes the C side actually wrote, starting at outOff, to
            // preserve caller-provided bytes preceding outOff.
            if (output != null && rc > 0)
            {
                outSeg.asByteBuffer().get(outOff, output, outOff, rc);
            }
            return rc;
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI CCM_doFinal", t);
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
            L.log(Level.WARNING, "FFI CCM_getOutputSize", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }


    /**
     * Allocate a native segment, copy the byte[] into it, return it.
     * Returns MemorySegment.NULL for a null input. Allocations are
     * tied to {@code arena}'s scope.
     */
    private static MemorySegment nativeCopy(Arena arena, byte[] src)
    {
        if (src == null)
        {
            return MemorySegment.NULL;
        }
        MemorySegment seg = arena.allocate(src.length == 0 ? 1 : src.length);
        if (src.length > 0)
        {
            seg.asByteBuffer().put(src);
        }
        return seg;
    }
}
