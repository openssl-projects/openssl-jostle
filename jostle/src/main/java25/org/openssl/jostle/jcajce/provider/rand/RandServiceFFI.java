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

import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Arena;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.util.logging.Level;
import java.util.logging.Logger;

public class RandServiceFFI implements RandServiceNI
{
    private static final Logger L = Logger.getLogger("Rand_NI_FFI");
    private static final SymbolLookup lookup = SymbolLookup.loaderLookup();
    private static final Linker linker = Linker.nativeLinker();

    private static final MemorySegment randomBytesFunc;
    private static final MethodHandle randomBytesFuncHandle;

    private static final MemorySegment instantiateFunc;
    private static final MethodHandle instantiateFuncHandle;

    private static final MemorySegment reseedFunc;
    private static final MethodHandle reseedFuncHandle;

    private static final MemorySegment createContextFunc;
    private static final MethodHandle createContextFuncHandle;

    private static final MemorySegment disposeContextFunc;
    private static final MethodHandle disposeContextFuncHandle;

    private static final MemorySegment contextRandomBytesFunc;
    private static final MethodHandle contextRandomBytesFuncHandle;

    private static final MemorySegment contextReseedFunc;
    private static final MethodHandle contextReseedFuncHandle;

    static
    {
        randomBytesFunc = lookup.find("JoRand_randomBytes").orElseThrow();
        randomBytesFuncHandle = linker.downcallHandle(randomBytesFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_BYTE,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG
                )
        );

        instantiateFunc = lookup.find("JoRand_instantiate").orElseThrow();
        instantiateFuncHandle = linker.downcallHandle(instantiateFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_BYTE,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG
                )
        );

        reseedFunc = lookup.find("JoRand_reseed").orElseThrow();
        reseedFuncHandle = linker.downcallHandle(reseedFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_BYTE,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG
                )
        );

        createContextFunc = lookup.find("JoRand_createContext").orElseThrow();
        createContextFuncHandle = linker.downcallHandle(createContextFunc,
                FunctionDescriptor.of(
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_BYTE,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.ADDRESS
                )
        );

        disposeContextFunc = lookup.find("JoRand_disposeContext").orElseThrow();
        disposeContextFuncHandle = linker.downcallHandle(disposeContextFunc,
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS)
        );

        contextRandomBytesFunc = lookup.find("JoRand_contextRandomBytes").orElseThrow();
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

        contextReseedFunc = lookup.find("JoRand_contextReseed").orElseThrow();
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
    }

    @Override
    public int ni_randomBytes(byte[] output, int outputLen, int strength,
                              boolean predictionResistant, byte[] additionalInput)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment outputSeg = output == null ?
                    MemorySegment.NULL :
                    a.allocate(output.length);
            MemorySegment additionalInputSeg = byteArraySegment(a, additionalInput);

            int code = (int) randomBytesFuncHandle.invokeExact(
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
            L.log(Level.WARNING, "FFI JoRand_randomBytes", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_instantiate(int strength, boolean predictionResistant, byte[] personalizationString)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment personalizationStringSeg = byteArraySegment(a, personalizationString);

            return (int) instantiateFuncHandle.invokeExact(
                    strength,
                    (byte) (predictionResistant ? 1 : 0),
                    personalizationStringSeg,
                    personalizationStringSeg.byteSize()
            );
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI JoRand_instantiate", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_reseed(int strength, boolean predictionResistant, byte[] additionalInput)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment additionalInputSeg = byteArraySegment(a, additionalInput);

            return (int) reseedFuncHandle.invokeExact(
                    strength,
                    (byte) (predictionResistant ? 1 : 0),
                    additionalInputSeg,
                    additionalInputSeg.byteSize()
            );
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI JoRand_reseed", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public long ni_createContext(int strength, boolean predictionResistant,
                                 byte[] personalizationString, int[] err)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment personalizationStringSeg = byteArraySegment(a, personalizationString);
            MemorySegment errSeg = a.allocate(ValueLayout.JAVA_INT);

            MemorySegment ctx = (MemorySegment) createContextFuncHandle.invokeExact(
                    strength,
                    (byte) (predictionResistant ? 1 : 0),
                    personalizationStringSeg,
                    personalizationStringSeg.byteSize(),
                    errSeg
            );
            err[0] = errSeg.getAtIndex(ValueLayout.JAVA_INT, 0);
            return ctx.address();
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI JoRand_createContext", t);
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
            L.log(Level.WARNING, "FFI JoRand_disposeContext", t);
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
            L.log(Level.WARNING, "FFI JoRand_contextRandomBytes", t);
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
            L.log(Level.WARNING, "FFI JoRand_contextReseed", t);
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
