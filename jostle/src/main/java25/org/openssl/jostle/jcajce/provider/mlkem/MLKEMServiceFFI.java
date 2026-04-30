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

package org.openssl.jostle.jcajce.provider.mlkem;

import org.openssl.jostle.rand.RandSource;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.util.logging.Level;
import java.util.logging.Logger;

public class MLKEMServiceFFI implements MLKEMServiceNI
{


    private static final Logger L = Logger.getLogger("MLKEM_NI_FFI");
    private static final SymbolLookup lookup = SymbolLookup.loaderLookup();
    private static final Linker linker = Linker.nativeLinker();

    private static final MemorySegment generateKeyPairFunc;
    private static final MethodHandle generateKeyPairFuncHandle;

    private static final MemorySegment generateKeyPairWithSeedFunc;
    private static final MethodHandle generateKeyPairWithSeedFuncHandle;


    private static final MemorySegment getPublicKeyFunc;
    private static final MethodHandle getPublicKeyFuncHandle;

    private static final MemorySegment getPrivateKeyFunc;
    private static final MethodHandle getPrivateKeyFuncHandle;

    private static final MemorySegment getSeedKeyFunc;
    private static final MethodHandle getSeedKeyFuncHandle;

    private static final MemorySegment decodePublicKeyFunc;
    private static final MethodHandle decodePublicKeyFuncHandle;

    private static final MemorySegment decodePrivateKeyFunc;
    private static final MethodHandle decodePrivateKeyFuncHandle;

    private static final FunctionDescriptor entropyFd;
    private static final MethodType entropyMt;


    static
    {
        generateKeyPairFunc = lookup.find("MLKEM_generateKeyPair").orElseThrow();
        generateKeyPairFuncHandle = linker.downcallHandle(generateKeyPairFunc,
                FunctionDescriptor.of(
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS
                ));

        generateKeyPairWithSeedFunc = lookup.find("MLKEM_generateKeyPairSeed").orElseThrow();
        generateKeyPairWithSeedFuncHandle = linker.downcallHandle(generateKeyPairWithSeedFunc,
                FunctionDescriptor.of(
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS
                ));


        getPublicKeyFunc = lookup.find("MLKEM_getPublicKey").orElseThrow();
        getPublicKeyFuncHandle = linker.downcallHandle(getPublicKeyFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG
                ), Linker.Option.critical(true));

        getPrivateKeyFunc = lookup.find("MLKEM_getPrivateKey").orElseThrow();
        getPrivateKeyFuncHandle = linker.downcallHandle(getPrivateKeyFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG
                ), Linker.Option.critical(true));

        getSeedKeyFunc = lookup.find("MLKEM_getSeed").orElseThrow();
        getSeedKeyFuncHandle = linker.downcallHandle(getSeedKeyFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG
                ), Linker.Option.critical(true));

        decodePublicKeyFunc = lookup.find("MLKEM_decodePublicKey").orElseThrow();
        decodePublicKeyFuncHandle = linker.downcallHandle(decodePublicKeyFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS
                ));

        decodePrivateKeyFunc = lookup.find("MLKEM_decodePrivateKey").orElseThrow();
        decodePrivateKeyFuncHandle = linker.downcallHandle(decodePrivateKeyFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS
                ));

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
                        randSource.getClass(),
                        "getRandomSegment",
                        entropyMt).bindTo(randSource);
                getEntropySegment = linker.upcallStub(gHandle, entropyFd, a);
            }


            MemorySegment retCodeRef = a.allocate(ValueLayout.JAVA_INT);
            MemorySegment segment = (MemorySegment) generateKeyPairFuncHandle.invokeExact(type, retCodeRef, getEntropySegment);

            int retCode = retCodeRef.get(ValueLayout.JAVA_INT, 0);
            err[0] = retCode;
            return segment.address();
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING,
                    "FFI MLKEM_generateKeyPair", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public long ni_generateKeyPair(int type, int[] err, byte[] seed, int seedLen, RandSource randSource)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment retCodeRef = a.allocate(ValueLayout.JAVA_INT);
            MemorySegment seedRef = seed == null ? MemorySegment.NULL : a.allocate(seed.length);

            MemorySegment getEntropySegment;
            if (randSource == null)
            {
                getEntropySegment = MemorySegment.NULL;
            }
            else
            {
                var gHandle = MethodHandles.lookup().findVirtual(
                        randSource.getClass(),
                        "getRandomSegment",
                        entropyMt).bindTo(randSource);
                getEntropySegment = linker.upcallStub(gHandle, entropyFd, a);
            }
            if (seed != null)
            {
                seedRef.asByteBuffer().put(seed);
            }

            MemorySegment segment = (MemorySegment) generateKeyPairWithSeedFuncHandle.invokeExact(
                    type,
                    retCodeRef,
                    seedRef,
                    seedRef.byteSize(),
                    seedLen,
                    getEntropySegment
            );

            int retCode = retCodeRef.get(ValueLayout.JAVA_INT, 0);
            err[0] = retCode;
            return segment.address();
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING,
                    "FFI MLKEM_generateKeyPair (seed)", t);
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
            L.log(Level.WARNING,
                    "FFI MLKEM_getPublicKey", t);
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
            L.log(Level.WARNING,
                    "FFI MLKEM_getPrivateKey", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_getSeed(long ref, byte[] output)
    {
        try
        {
            MemorySegment ctx = MemorySegment.ofAddress(ref);
            MemorySegment refOutput = output == null ? MemorySegment.NULL : MemorySegment.ofArray(output);
            long len = output == null ? 0L : refOutput.byteSize();

            return (int) getSeedKeyFuncHandle.invokeExact(ctx, refOutput, len);
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING,
                    "FFI MLKEM_getSeed", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_decode_publicKey(long spec_ref, int keyType, byte[] input, int inputOffset, int inputLen, RandSource randSource)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment keySpec = MemorySegment.ofAddress(spec_ref);
            MemorySegment inputRef = input == null ? MemorySegment.NULL : a.allocate(input.length);
            if (input != null)
            {
                inputRef.asByteBuffer().put(input);
            }

            MemorySegment getEntropySegment;
            if (randSource == null)
            {
                getEntropySegment = MemorySegment.NULL;
            }
            else
            {
                var gHandle = MethodHandles.lookup().findVirtual(
                        randSource.getClass(),
                        "getRandomSegment",
                        entropyMt).bindTo(randSource);
                getEntropySegment = linker.upcallStub(gHandle, entropyFd, a);
            }

            return (int) decodePublicKeyFuncHandle.invokeExact(keySpec, keyType, inputRef, inputRef.byteSize(), inputOffset, inputLen, getEntropySegment);
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING,
                    "FFI MLKEM_decodePublicKey", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_decode_privateKey(long spec_ref, int keyType, byte[] input, int inputOffset, int inputLen, RandSource randSource)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment keySpec = MemorySegment.ofAddress(spec_ref);
            MemorySegment inputRef = input == null ? MemorySegment.NULL : a.allocate(input.length);
            if (input != null)
            {
                inputRef.asByteBuffer().put(input);
            }

            MemorySegment getEntropySegment;
            if (randSource == null)
            {
                getEntropySegment = MemorySegment.NULL;
            }
            else
            {
                var gHandle = MethodHandles.lookup().findVirtual(
                        randSource.getClass(),
                        "getRandomSegment",
                        entropyMt).bindTo(randSource);
                getEntropySegment = linker.upcallStub(gHandle, entropyFd, a);
            }

            return (int) decodePrivateKeyFuncHandle.invokeExact(keySpec, keyType, inputRef, inputRef.byteSize(), inputOffset, inputLen, getEntropySegment);
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING,
                    "FFI MLKEM_decodePrivateKey", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }
}
