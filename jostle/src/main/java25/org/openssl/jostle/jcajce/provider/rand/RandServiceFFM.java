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

package org.openssl.jostle.jcajce.provider.rand;

import org.openssl.jostle.jcajce.provider.cache.NativeLengthCache;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Arena;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.util.logging.Level;
import java.util.logging.Logger;

// Symbol resolution is parameterised by a SymbolLookup so the same
// marshalling serves both interface libraries (see MDServiceFFM).
public class RandServiceFFM implements RandServiceNI
{
    private final NativeLengthCache<String> lengthCache = new NativeLengthCache<String>();

    @Override
    public NativeLengthCache<String> lengthCache()
    {
        return lengthCache;
    }

    private static final Logger L = Logger.getLogger("Rand_NI_FFM");
    private static final Linker linker = Linker.nativeLinker();

    private final MethodHandle createContextFuncHandle;

    private final MethodHandle disposeContextFuncHandle;

    private final MethodHandle contextRandomBytesFuncHandle;

    private final MethodHandle contextReseedFuncHandle;

    private final MethodHandle drbgStrengthFuncHandle;

    public RandServiceFFM()
    {
        this(SymbolLookup.loaderLookup());
    }

    public RandServiceFFM(SymbolLookup lookup)
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
    public RandServiceFFM(SymbolLookup lookup, String symPrefix)
    {
        MemorySegment createContextFunc = lookup.find(symPrefix + "JoRand_createContext").orElseThrow();
        createContextFuncHandle = linker.downcallHandle(createContextFunc,
                FunctionDescriptor.of(
                        ValueLayout.ADDRESS,    // JO_RAND_CTX* return
                        ValueLayout.ADDRESS,    // mechanism
                        ValueLayout.ADDRESS,    // variant
                        ValueLayout.JAVA_BYTE,  // use_df
                        ValueLayout.JAVA_INT,   // strength
                        ValueLayout.JAVA_BYTE,  // prediction_resistant
                        ValueLayout.ADDRESS,    // personalization_string
                        ValueLayout.JAVA_LONG,  // personalization_string_size
                        ValueLayout.ADDRESS,    // err
                        ValueLayout.JAVA_INT    // err_len
                )
        );

        MemorySegment disposeContextFunc = lookup.find(symPrefix + "JoRand_disposeContext").orElseThrow();
        disposeContextFuncHandle = linker.downcallHandle(disposeContextFunc,
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS)
        );

        MemorySegment contextRandomBytesFunc = lookup.find(symPrefix + "JoRand_contextRandomBytes").orElseThrow();
        contextRandomBytesFuncHandle = linker.downcallHandle(contextRandomBytesFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_BYTE,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG
                )
        );

        MemorySegment contextReseedFunc = lookup.find(symPrefix + "JoRand_contextReseed").orElseThrow();
        contextReseedFuncHandle = linker.downcallHandle(contextReseedFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_BYTE,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG
                )
        );

        MemorySegment drbgStrengthFunc = lookup.find(symPrefix + "JoRand_drbgStrength").orElseThrow();
        drbgStrengthFuncHandle = linker.downcallHandle(drbgStrengthFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,    // strength return
                        ValueLayout.ADDRESS,     // mechanism
                        ValueLayout.ADDRESS      // variant
                )
        );
    }

    @Override
    public long ni_createContext(String mechanism, String variant, boolean useDerivationFunction,
                                 int strength, boolean predictionResistant,
                                 byte[] personalizationString, int[] err)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment mechanismSeg = mechanism == null ? MemorySegment.NULL : a.allocateFrom(mechanism);
            MemorySegment variantSeg = variant == null ? MemorySegment.NULL : a.allocateFrom(variant);
            MemorySegment personalizationStringSeg = byteArraySegment(a, personalizationString);
            // err crosses with its length so C does the checking and both
            // bridges answer the same way.
            MemorySegment errSeg = err == null
                    ? MemorySegment.NULL
                    : a.allocate(ValueLayout.JAVA_INT, Math.max(err.length, 1));

            MemorySegment ctx = (MemorySegment) createContextFuncHandle.invokeExact(
                    mechanismSeg,
                    variantSeg,
                    (byte) (useDerivationFunction ? 1 : 0),
                    strength,
                    (byte) (predictionResistant ? 1 : 0),
                    personalizationStringSeg,
                    personalizationStringSeg.byteSize(),
                    errSeg,
                    err == null ? 0 : err.length
            );
            err[0] = errSeg.getAtIndex(ValueLayout.JAVA_INT, 0);
            return ctx.address();
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFM JoRand_createContext", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public void ni_disposeContext(long reference)
    {
        try
        {
            disposeContextFuncHandle.invokeExact(MemorySegment.ofAddress(reference));
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFM JoRand_disposeContext", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_contextRandomBytes(long reference, byte[] output, int outputLen, int strength,
                                     boolean predictionResistant, byte[] additionalInput)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment outputSeg = output == null ?
                    MemorySegment.NULL :
                    a.allocate(output.length);
            MemorySegment additionalInputSeg = byteArraySegment(a, additionalInput);

            int code = (int) contextRandomBytesFuncHandle.invokeExact(
                    MemorySegment.ofAddress(reference),
                    outputSeg,
                    outputSeg.byteSize(),
                    outputLen,
                    strength,
                    (byte) (predictionResistant ? 1 : 0),
                    additionalInputSeg,
                    additionalInputSeg.byteSize()
            );

            if (code >= 0 && output != null && outputLen > 0)
            {
                outputSeg.asSlice(0, outputLen).asByteBuffer().get(output, 0, outputLen);
            }

            return code;
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFM JoRand_contextRandomBytes", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_contextReseed(long reference, int strength, boolean predictionResistant,
                                byte[] additionalInput)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment additionalInputSeg = byteArraySegment(a, additionalInput);

            return (int) contextReseedFuncHandle.invokeExact(
                    MemorySegment.ofAddress(reference),
                    strength,
                    (byte) (predictionResistant ? 1 : 0),
                    additionalInputSeg,
                    additionalInputSeg.byteSize()
            );
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFM JoRand_contextReseed", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_drbgStrength(String mechanism, String variant)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment mechanismSeg = mechanism == null ? MemorySegment.NULL : a.allocateFrom(mechanism);
            MemorySegment variantSeg = variant == null ? MemorySegment.NULL : a.allocateFrom(variant);

            return (int) drbgStrengthFuncHandle.invokeExact(mechanismSeg, variantSeg);
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFM JoRand_drbgStrength", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    private static MemorySegment byteArraySegment(Arena a, byte[] bytes)
    {
        if (bytes == null || bytes.length == 0)
        {
            return MemorySegment.NULL;
        }

        MemorySegment seg = a.allocate(bytes.length);
        seg.asByteBuffer().put(bytes);
        return seg;
    }
}
