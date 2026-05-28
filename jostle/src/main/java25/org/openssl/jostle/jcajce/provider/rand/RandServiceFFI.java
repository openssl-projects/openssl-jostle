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

    static
    {
        randomBytesFunc = lookup.find("JoRand_randomBytes").orElseThrow();
        randomBytesFuncHandle = linker.downcallHandle(randomBytesFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_INT
                )
        );
    }

    @Override
    public int ni_randomBytes(byte[] output, int outputLen, int strength)
    {
        if (output != null && outputLen == 0 && strength >= 0)
        {
            return 0;
        }

        try
        {
            MemorySegment outputSeg = output == null ?
                    MemorySegment.NULL :
                    MemorySegment.ofArray(output);

            return (int) randomBytesFuncHandle.invokeExact(
                    outputSeg,
                    outputSeg.byteSize(),
                    outputLen,
                    strength
            );
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI JoRand_randomBytes", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }
}
