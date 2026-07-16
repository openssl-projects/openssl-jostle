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

/**
 * FFI implementation of {@link OperationsTestNI}. Marshalling is parameterised
 * by a {@link SymbolLookup} so the same code serves both interface libraries:
 * the no-arg constructor uses the process-global {@code loaderLookup()} (the
 * base library); {@code OperationsTestFIPSFFI} passes a library-scoped lookup
 * pinned to the extracted FIPS library. The ops symbols exist only in a
 * JOSTLE_OPS_TEST build, so {@link #opsTestAvailable()} probes for
 * {@code set_ops_test} and reports false when absent.
 */
public class OperationsTestFFI implements OperationsTestNI
{
    private static final Linker linker = Linker.nativeLinker();

    // Lookup-independent descriptors for the RandSource entropy upcall. These
    // MUST be inline static initializers, not assigned in a lookup-dependent
    // static block (the SpecFFI lesson): they carry no native handle.
    private static final FunctionDescriptor entropyFd = FunctionDescriptor.of(
            ValueLayout.JAVA_INT, // return code
            ValueLayout.ADDRESS.withTargetLayout(ValueLayout.JAVA_BYTE), // out array
            ValueLayout.JAVA_LONG, // len
            ValueLayout.JAVA_INT, // strength
            ValueLayout.JAVA_INT // pred resistance
    );
    private static final MethodType entropyMt = MethodType.methodType(
            int.class, // return type
            MemorySegment.class, // out
            long.class, // out_len
            int.class, // strength
            int.class // pred resistance
    );

    private final boolean opsAvailable;
    private final MethodHandle setOpsFuncHandler;
    private final MethodHandle getRandomBytes;

    public OperationsTestFFI()
    {
        this(SymbolLookup.loaderLookup());
    }

    public OperationsTestFFI(SymbolLookup lookup)
    {
        Optional<MemorySegment> func = lookup.find("set_ops_test");
        opsAvailable = func.isPresent();
        if (opsAvailable)
        {
            setOpsFuncHandler = linker.downcallHandle(func.get(),
                    FunctionDescriptor.ofVoid(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT));

            MemorySegment getRandomBytesFunc = lookup.find("OPS_GetRandomBytes").orElseThrow();
            getRandomBytes = linker.downcallHandle(getRandomBytesFunc, FunctionDescriptor.of(
                    ValueLayout.JAVA_INT, // return code
                    ValueLayout.ADDRESS,
                    ValueLayout.JAVA_LONG,
                    ValueLayout.JAVA_INT,
                    ValueLayout.JAVA_INT,
                    ValueLayout.ADDRESS));
        }
        else
        {
            setOpsFuncHandler = null;
            getRandomBytes = null;
        }
    }

    @Override
    public boolean opsTestAvailable()
    {
        return opsAvailable;
    }

    @Override
    public void setOpsTestFlag(int flag, int value)
    {
        if (!opsAvailable)
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
                    "getRandomSegment",
                    entropyMt).bindTo(randSource);
            var getEntropySegment = linker.upcallStub(gHandle, entropyFd, a);

            MemorySegment outSegment = out != null ? a.allocate(out.length) : MemorySegment.NULL;

            int rc = (int) getRandomBytes.invokeExact(outSegment, (long) len, strength, predictionResistant ? 1 : 0, getEntropySegment);

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
