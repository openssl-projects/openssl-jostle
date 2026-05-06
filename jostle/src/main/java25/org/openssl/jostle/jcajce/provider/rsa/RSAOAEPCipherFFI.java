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

package org.openssl.jostle.jcajce.provider.rsa;

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
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * FFI binding for the {@code JoRSAOAEP_*} symbols exported by
 * {@code interface/ffi/rsa_oaep_ni_ffi.c}. Mirrors {@link RSAServiceFFI};
 * the OAEP-specific behaviour is the entropy upcall threaded through
 * {@link #ni_init} (encrypt-mode only) and {@link #ni_doFinal}
 * (encrypt-mode only).
 */
public class RSAOAEPCipherFFI implements RSAOAEPCipherNI
{
    private static final Logger L = Logger.getLogger("RSA_OAEP_NI_FFI");
    private static final SymbolLookup lookup = SymbolLookup.loaderLookup();
    private static final Linker linker = Linker.nativeLinker();

    private static final MethodHandle allocCipherH;
    private static final MethodHandle disposeCipherH;
    private static final MethodHandle initH;
    private static final MethodHandle doFinalH;

    private static final FunctionDescriptor entropyFd;
    private static final MethodType entropyMt;


    static
    {
        allocCipherH = linker.downcallHandle(
                lookup.find("JoRSAOAEP_allocateCipher").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));

        disposeCipherH = linker.downcallHandle(
                lookup.find("JoRSAOAEP_disposeCipher").orElseThrow(),
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));

        // JoRSAOAEP_init(ctx, key, op_mode, oaep_md*, mgf1_md*,
        //                label*, label_len, rnd_src) -> int
        initH = linker.downcallHandle(
                lookup.find("JoRSAOAEP_init").orElseThrow(),
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,    // ctx
                        ValueLayout.ADDRESS,    // key
                        ValueLayout.JAVA_INT,   // op_mode
                        ValueLayout.ADDRESS,    // oaep_md_name
                        ValueLayout.ADDRESS,    // mgf1_md_name (nullable)
                        ValueLayout.ADDRESS,    // label
                        ValueLayout.JAVA_LONG,  // label_len
                        ValueLayout.ADDRESS));  // rnd_src upcall

        // JoRSAOAEP_doFinal(ctx, in*, in_size, in_off, in_len,
        //                   out*, out_size, out_off, rnd_src) -> int
        doFinalH = linker.downcallHandle(
                lookup.find("JoRSAOAEP_doFinal").orElseThrow(),
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,    // ctx
                        ValueLayout.ADDRESS,    // input
                        ValueLayout.JAVA_LONG,  // input_size
                        ValueLayout.JAVA_INT,   // in_off
                        ValueLayout.JAVA_INT,   // in_len
                        ValueLayout.ADDRESS,    // output (nullable)
                        ValueLayout.JAVA_LONG,  // output_size
                        ValueLayout.JAVA_INT,   // out_off
                        ValueLayout.ADDRESS));  // rnd_src upcall

        entropyFd = FunctionDescriptor.of(
                ValueLayout.JAVA_INT,
                ValueLayout.ADDRESS.withTargetLayout(ValueLayout.JAVA_BYTE),
                ValueLayout.JAVA_INT,
                ValueLayout.JAVA_INT,
                ValueLayout.JAVA_BOOLEAN);
        entropyMt = MethodType.methodType(
                int.class,
                MemorySegment.class,
                int.class,
                int.class,
                boolean.class);
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
                    .findVirtual(src.getClass(), "getRandomSegment", entropyMt)
                    .bindTo(src);
            return linker.upcallStub(h, entropyFd, arena);
        }
        catch (Throwable t)
        {
            throw new RuntimeException("unable to create entropy upcall stub", t);
        }
    }

    private static MemorySegment arrayOrNull(byte[] a)
    {
        return a == null ? MemorySegment.NULL : MemorySegment.ofArray(a);
    }


    @Override
    public long ni_allocateCipher(int[] err)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment errSeg = a.allocate(ValueLayout.JAVA_INT);
            MemorySegment ref = (MemorySegment) allocCipherH.invokeExact(errSeg);
            err[0] = errSeg.get(ValueLayout.JAVA_INT, 0);
            return ref.address();
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI RSAOAEP_allocateCipher", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public void ni_disposeCipher(long reference)
    {
        try
        {
            disposeCipherH.invokeExact(MemorySegment.ofAddress(reference));
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI RSAOAEP_disposeCipher", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_init(long ref, long keyRef, int opMode,
                       String oaepMdName, String mgf1MdName,
                       byte[] label,
                       RandSource rndSource)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment ctx = MemorySegment.ofAddress(ref);
            MemorySegment key = MemorySegment.ofAddress(keyRef);
            MemorySegment oaepSeg = oaepMdName == null ? MemorySegment.NULL : a.allocateFrom(oaepMdName);
            MemorySegment mgfSeg = mgf1MdName == null ? MemorySegment.NULL : a.allocateFrom(mgf1MdName);

            // init is non-critical (entropy upcall); a heap segment for label
            // would be rejected by the linker. Allocate a native copy.
            MemorySegment labelSeg;
            long labelLen;
            if (label == null)
            {
                labelSeg = MemorySegment.NULL;
                labelLen = 0L;
            }
            else
            {
                labelSeg = a.allocate(label.length);
                if (label.length > 0)
                {
                    labelSeg.asByteBuffer().put(label);
                }
                labelLen = label.length;
            }

            return (int) initH.invokeExact(ctx, key, opMode,
                    oaepSeg, mgfSeg,
                    labelSeg, labelLen,
                    entropyStub(a, rndSource));
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI RSAOAEP_init", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_doFinal(long ref,
                          byte[] input, int inOff, int inLen,
                          byte[] output, int outOff,
                          RandSource rndSource)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment ctx = MemorySegment.ofAddress(ref);
            // doFinal isn't critical (entropy upcall in encrypt mode);
            // copy in to a native segment so we don't pass a heap segment.
            MemorySegment inSeg;
            long inSize;
            if (input == null)
            {
                inSeg = MemorySegment.NULL;
                inSize = 0L;
            }
            else
            {
                inSeg = a.allocate(input.length);
                if (input.length > 0)
                {
                    inSeg.asByteBuffer().put(input);
                }
                inSize = input.length;
            }

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
                    inSeg, inSize, inOff, inLen,
                    outSeg, outSize, outOff,
                    entropyStub(a, rndSource));

            // Copy back only the bytes the C side actually wrote, at
            // their original offset. A blanket get(0, output, 0, len)
            // would clobber caller-provided bytes preceding outOff.
            if (output != null && rc > 0)
            {
                outSeg.asByteBuffer().get(outOff, output, outOff, rc);
            }
            return rc;
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI RSAOAEP_doFinal", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }
}
