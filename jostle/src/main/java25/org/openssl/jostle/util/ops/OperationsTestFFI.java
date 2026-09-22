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

import org.openssl.jostle.rand.EntropyUpcall;
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
    private static final FunctionDescriptor entropyFd = EntropyUpcall.DESCRIPTOR;
    private static final MethodType entropyMt = EntropyUpcall.METHOD_TYPE;

    private final boolean opsAvailable;
    private final MethodHandle setOpsFuncHandler;
    private final MethodHandle getRandomBytes;
    private final MethodHandle createTestDrbg;
    private final MethodHandle setTestEntropy;
    private final MethodHandle randLibctxFipsEnabled;

    public OperationsTestFFI()
    {
        this(SymbolLookup.loaderLookup());
    }

    public OperationsTestFFI(SymbolLookup lookup)
    {
        this(lookup, "");
    }

    /**
     * @param lookup    the library to resolve against.
     * @param symPrefix prepended to every symbol name. Empty for the base
     *                  library; {@code "JoFIPS_"} for the FIPS one, whose
     *                  exports are renamed by the {@code <x>_fips_ffi.c}
     *                  wrappers. Deliberately SEPARATE from {@code lookup}:
     *                  two independent values mean either mistake alone
     *                  still resolves correctly or fails loudly, where a
     *                  single bundled value made a wrong lookup silently
     *                  run base-library crypto.
     */
    public OperationsTestFFI(SymbolLookup lookup, String symPrefix)
    {
        Optional<MemorySegment> func = lookup.find(symPrefix + "JoOps_setFlag");
        opsAvailable = func.isPresent();
        if (opsAvailable)
        {
            setOpsFuncHandler = linker.downcallHandle(func.get(),
                    FunctionDescriptor.ofVoid(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT));

            MemorySegment getRandomBytesFunc = lookup.find(symPrefix + "JoOps_getRandomBytes").orElseThrow();
            getRandomBytes = linker.downcallHandle(getRandomBytesFunc, FunctionDescriptor.of(
                    ValueLayout.JAVA_INT, // return code
                    ValueLayout.ADDRESS,
                    ValueLayout.JAVA_LONG,
                    ValueLayout.JAVA_INT,
                    ValueLayout.JAVA_INT,
                    ValueLayout.ADDRESS));

            MemorySegment createTestDrbgFunc =
                    lookup.find(symPrefix + "JoOps_createTestDrbg").orElseThrow();
            createTestDrbg = linker.downcallHandle(createTestDrbgFunc, FunctionDescriptor.of(
                    ValueLayout.ADDRESS,   // the handle
                    ValueLayout.ADDRESS,   // mechanism
                    ValueLayout.ADDRESS,   // variant
                    ValueLayout.JAVA_INT,  // use_df
                    ValueLayout.JAVA_INT,  // strength
                    ValueLayout.JAVA_INT,  // prediction resistance
                    ValueLayout.ADDRESS,   // personalization
                    ValueLayout.JAVA_LONG,
                    ValueLayout.ADDRESS,   // entropy
                    ValueLayout.JAVA_LONG,
                    ValueLayout.ADDRESS,   // nonce
                    ValueLayout.JAVA_LONG,
                    ValueLayout.ADDRESS)); // err

            MemorySegment setTestEntropyFunc =
                    lookup.find(symPrefix + "JoOps_setTestEntropy").orElseThrow();
            setTestEntropy = linker.downcallHandle(setTestEntropyFunc, FunctionDescriptor.of(
                    ValueLayout.JAVA_INT,  // status
                    ValueLayout.ADDRESS,   // the handle
                    ValueLayout.ADDRESS,   // entropy
                    ValueLayout.JAVA_LONG));

            MemorySegment fipsEnabledFunc =
                    lookup.find(symPrefix + "JoOps_randLibctxFipsEnabled").orElseThrow();
            randLibctxFipsEnabled = linker.downcallHandle(fipsEnabledFunc,
                    FunctionDescriptor.of(ValueLayout.JAVA_INT));
        }
        else
        {
            setOpsFuncHandler = null;
            getRandomBytes = null;
            createTestDrbg = null;
            setTestEntropy = null;
            randLibctxFipsEnabled = null;
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
    public long op_createTestDrbg(String mechanism, String variant, boolean useDerivationFunction,
                                  int strength, boolean predictionResistant,
                                  byte[] personalizationString, byte[] entropy, byte[] nonce,
                                  int[] err)
    {
        if (!opsAvailable)
        {
            throw new IllegalStateException("no ops testing available on native side");
        }

        // Arena copies rather than critical segments: this entry point is not
        // on a hot path and copying keeps the marshalling obvious.
        try (Arena arena = Arena.ofConfined())
        {
            MemorySegment mech = arena.allocateFrom(mechanism);
            MemorySegment var = arena.allocateFrom(variant);
            MemorySegment pers = copyIn(arena, personalizationString);
            MemorySegment ent = copyIn(arena, entropy);
            MemorySegment non = copyIn(arena, nonce);
            MemorySegment errSeg = arena.allocate(ValueLayout.JAVA_INT, 1);

            MemorySegment handle = (MemorySegment) createTestDrbg.invokeExact(
                    mech, var, useDerivationFunction ? 1 : 0, strength,
                    predictionResistant ? 1 : 0,
                    pers, (long) lengthOf(personalizationString),
                    ent, (long) lengthOf(entropy),
                    non, (long) lengthOf(nonce),
                    errSeg);

            err[0] = errSeg.get(ValueLayout.JAVA_INT, 0);
            return handle.address();
        }
        catch (Throwable e)
        {
            throw new RuntimeException(e);
        }
    }

    @Override
    public int op_setTestEntropy(long ref, byte[] entropy)
    {
        if (!opsAvailable)
        {
            throw new IllegalStateException("no ops testing available on native side");
        }

        try (Arena arena = Arena.ofConfined())
        {
            return (int) setTestEntropy.invokeExact(
                    MemorySegment.ofAddress(ref),
                    copyIn(arena, entropy), (long) lengthOf(entropy));
        }
        catch (Throwable e)
        {
            throw new RuntimeException(e);
        }
    }

    @Override
    public boolean op_randLibctxFipsEnabled()
    {
        if (!opsAvailable)
        {
            throw new IllegalStateException("no ops testing available on native side");
        }

        try
        {
            return ((int) randLibctxFipsEnabled.invokeExact()) != 0;
        }
        catch (Throwable e)
        {
            throw new RuntimeException(e);
        }
    }

    private static MemorySegment copyIn(Arena arena, byte[] value)
    {
        return value == null ? MemorySegment.NULL : arena.allocateFrom(ValueLayout.JAVA_BYTE, value);
    }

    private static int lengthOf(byte[] value)
    {
        return value == null ? 0 : value.length;
    }

    @Override
    public int op_getEntropy(byte[] out, int len, int strength, boolean predictionResistant, RandSource randSource)
    {
        try (Arena a = Arena.ofConfined())
        {

            var gHandle = MethodHandles.lookup().findVirtual(
                    RandSource.class,
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
