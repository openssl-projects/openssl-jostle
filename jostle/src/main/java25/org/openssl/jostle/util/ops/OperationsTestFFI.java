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

package org.openssl.jostle.util.ops;

import org.openssl.jostle.rand.RandSource;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.util.Optional;

public class OperationsTestFFI implements OperationsTestNI
{

    private static final SymbolLookup lookup = SymbolLookup.loaderLookup();
    private static final Linker linker = Linker.nativeLinker();

    private static final boolean isOpsTestAvailable;

    private static MethodHandle setOpsFuncHandler = null;
    private static MethodHandle getRandomBytes = null;
    private static final FunctionDescriptor entropyFd;
    private static final MethodType entropyMt;

    static
    {
        Optional<MemorySegment> func = lookup.find("set_ops_test");
        isOpsTestAvailable = func.isPresent();
        if (isOpsTestAvailable)
        {
            MemorySegment setOpsFunc = func.get();
            setOpsFuncHandler = linker.downcallHandle(setOpsFunc, FunctionDescriptor.ofVoid(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT));

            MemorySegment getRandomBytesFunc = lookup.find("OPS_GetRandomBytes").orElseThrow();
            getRandomBytes = linker.downcallHandle(getRandomBytesFunc, FunctionDescriptor.of(
                    ValueLayout.JAVA_INT, // return code
                    ValueLayout.ADDRESS,
                    ValueLayout.JAVA_LONG,
                    ValueLayout.JAVA_INT,
                    ValueLayout.JAVA_INT,
                    ValueLayout.ADDRESS));
        }

        entropyFd = FunctionDescriptor.of(
                ValueLayout.JAVA_INT, // return code
                ValueLayout.ADDRESS.withTargetLayout(ValueLayout.JAVA_BYTE), // out array
                ValueLayout.JAVA_INT, // len
                ValueLayout.JAVA_INT, // strength
                ValueLayout.JAVA_BOOLEAN // pred resistance
        );
        entropyMt = MethodType.methodType(
                int.class, // return type
                MemorySegment.class, // out
                int.class, // out_len
                int.class, // strength
                boolean.class // pred resistance
        );

    }

    public static boolean isIsOpsTestAvailable()
    {
        return isOpsTestAvailable;
    }


    @Override
    public boolean opsTestAvailable()
    {
        return isOpsTestAvailable;
    }

    @Override
    public void setOpsTestFlag(int flag, int value)
    {
        if (!isOpsTestAvailable)
        {
            throw new IllegalStateException("no ops testing available on native side");
        }

        try
        {
            setOpsFuncHandler.invokeExact(flag, value);
        }
        catch (Throwable e)
        {
            throw new RuntimeException(e);
        }
    }

    @Override
    public int op_getEntropy(byte[] out, int len, int strength, boolean predictionResistant, RandSource randSource)
    {
        try (Arena a = Arena.ofConfined())
        {

            var gHandle = MethodHandles.lookup().findVirtual(
                    randSource.getClass(),
                    "getEntropySegment",
                    entropyMt).bindTo(randSource);
            var getEntropySegment = linker.upcallStub(gHandle, entropyFd, a);

            MemorySegment outSegment = out != null ? a.allocate(out.length) : MemorySegment.NULL;

            int rc = (int) getRandomBytes.invokeExact(outSegment, (long)len, strength, predictionResistant?1:0, getEntropySegment);

            if (out != null)
            {
                outSegment.asByteBuffer().get(out);
            }

            return rc;
        }
        catch (Throwable t)
        {
            throw new RuntimeException(t);
        }
    }
}
