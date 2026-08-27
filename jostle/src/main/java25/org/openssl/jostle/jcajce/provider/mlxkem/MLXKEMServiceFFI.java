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

package org.openssl.jostle.jcajce.provider.mlxkem;

import org.openssl.jostle.rand.EntropyUpcall;
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

public class MLXKEMServiceFFI implements MLXKEMServiceNI
{
    private static final Logger L = Logger.getLogger("MLXKEM_NI_FFI");

    // Per-instance, NOT the process-global loaderLookup: the base and FIPS
    // interface libraries would otherwise be indistinguishable to a global
    // lookup. The FIPS subclass passes a library-scoped lookup.
    private final SymbolLookup lookup;
    private static final Linker linker = Linker.nativeLinker();

    private final MemorySegment generateKeyPairFunc;
    private final MethodHandle generateKeyPairFuncHandle;

    private final MemorySegment getPublicKeyFunc;
    private final MethodHandle getPublicKeyFuncHandle;

    private final MemorySegment getPrivateKeyFunc;
    private final MethodHandle getPrivateKeyFuncHandle;

    private final MemorySegment decodePublicKeyFunc;
    private final MethodHandle decodePublicKeyFuncHandle;

    private final MemorySegment decodePrivateKeyFunc;
    private final MethodHandle decodePrivateKeyFuncHandle;

    private final FunctionDescriptor entropyFd;
    private final MethodType entropyMt;

    public MLXKEMServiceFFI()
    {
        this(SymbolLookup.loaderLookup());
    }

    public MLXKEMServiceFFI(SymbolLookup lookup)
    {
        this(lookup, "");
    }

    /**
     * @param lookup    the library to resolve against.
     * @param symPrefix prepended to every symbol name. Empty for the base
     *                  library; {@code "JoFIPS_"} for the FIPS one. Kept
     *                  SEPARATE from {@code lookup} on purpose — two
     *                  independent values mean either mistake alone still
     *                  resolves correctly or fails loudly.
     */
    public MLXKEMServiceFFI(SymbolLookup lookup, String symPrefix)
    {
        this.lookup = lookup;

        generateKeyPairFunc = lookup.find(symPrefix + "JoMLXKEM_generateKeyPair").orElseThrow();
        generateKeyPairFuncHandle = linker.downcallHandle(generateKeyPairFunc,
                FunctionDescriptor.of(
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS
                ));

        getPublicKeyFunc = lookup.find(symPrefix + "JoMLXKEM_getPublicKey").orElseThrow();
        getPublicKeyFuncHandle = linker.downcallHandle(getPublicKeyFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG
                ), Linker.Option.critical(true));

        getPrivateKeyFunc = lookup.find(symPrefix + "JoMLXKEM_getPrivateKey").orElseThrow();
        getPrivateKeyFuncHandle = linker.downcallHandle(getPrivateKeyFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG
                ), Linker.Option.critical(true));

        // The decode entry points take NO RandSource — a hybrid import is
        // pure fromdata with no entropy draw — so critical marshalling is
        // safe here where it would not be on an upcall-bearing entry point.
        decodePublicKeyFunc = lookup.find(symPrefix + "JoMLXKEM_decodePublicKey").orElseThrow();
        decodePublicKeyFuncHandle = linker.downcallHandle(decodePublicKeyFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_INT
                ), Linker.Option.critical(true));

        decodePrivateKeyFunc = lookup.find(symPrefix + "JoMLXKEM_decodePrivateKey").orElseThrow();
        decodePrivateKeyFuncHandle = linker.downcallHandle(decodePrivateKeyFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_INT
                ), Linker.Option.critical(true));

        entropyFd = EntropyUpcall.DESCRIPTOR;
        entropyMt = EntropyUpcall.METHOD_TYPE;
    }

    @Override
    public long ni_generateKeyPair(int type, int[] err, RandSource randSource)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment getEntropySegment;
            if (randSource == null)
            {
                getEntropySegment = MemorySegment.NULL;
            }
            else
            {
                var gHandle = MethodHandles.lookup().findVirtual(
                        RandSource.class,
                        "getRandomSegment",
                        entropyMt).bindTo(randSource);
                getEntropySegment = linker.upcallStub(gHandle, entropyFd, a);
            }

            MemorySegment retCodeRef = a.allocate(ValueLayout.JAVA_INT);
            MemorySegment segment = (MemorySegment) generateKeyPairFuncHandle.invokeExact(
                    type, retCodeRef, getEntropySegment);

            err[0] = retCodeRef.get(ValueLayout.JAVA_INT, 0);
            return segment.address();
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI JoMLXKEM_generateKeyPair", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_getPublicKey(long ref, byte[] output)
    {
        try
        {
            MemorySegment ctx = MemorySegment.ofAddress(ref);
            MemorySegment refOutput = output == null ? MemorySegment.NULL : MemorySegment.ofArray(output);
            long len = output == null ? 0L : refOutput.byteSize();

            return (int) getPublicKeyFuncHandle.invokeExact(ctx, refOutput, len);
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI JoMLXKEM_getPublicKey", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_getPrivateKey(long ref, byte[] output)
    {
        try
        {
            MemorySegment ctx = MemorySegment.ofAddress(ref);
            MemorySegment refOutput = output == null ? MemorySegment.NULL : MemorySegment.ofArray(output);
            long len = output == null ? 0L : refOutput.byteSize();

            return (int) getPrivateKeyFuncHandle.invokeExact(ctx, refOutput, len);
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI JoMLXKEM_getPrivateKey", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_decode_publicKey(long specRef, int keyType, byte[] input, int inputOffset, int inputLen)
    {
        return decode(decodePublicKeyFuncHandle, "JoMLXKEM_decodePublicKey",
                specRef, keyType, input, inputOffset, inputLen);
    }

    @Override
    public int ni_decode_privateKey(long specRef, int keyType, byte[] input, int inputOffset, int inputLen)
    {
        return decode(decodePrivateKeyFuncHandle, "JoMLXKEM_decodePrivateKey",
                specRef, keyType, input, inputOffset, inputLen);
    }

    private int decode(MethodHandle handle, String name, long specRef, int keyType,
                       byte[] input, int inputOffset, int inputLen)
    {
        try
        {
            MemorySegment ctx = MemorySegment.ofAddress(specRef);
            // A null input must reach the bridge as NULL with size 0, so the
            // bridge's own JO_INPUT_IS_NULL check fires rather than a util
            // assert. Matching what the JNI twin does with a null array.
            MemorySegment refInput = input == null ? MemorySegment.NULL : MemorySegment.ofArray(input);
            long size = input == null ? 0L : refInput.byteSize();

            return (int) handle.invokeExact(ctx, keyType, refInput, size, inputOffset, inputLen);
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI " + name, t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }
}
