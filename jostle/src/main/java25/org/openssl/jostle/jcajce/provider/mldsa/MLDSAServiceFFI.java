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

package org.openssl.jostle.jcajce.provider.mldsa;

import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.rand.RandSource;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.util.logging.Level;
import java.util.logging.Logger;

public class MLDSAServiceFFI implements MLDSAServiceNI
{

    private static final Logger L = Logger.getLogger("MLDSA_NI_FFI");
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

    private static final MemorySegment allocSignerFunc;
    private static final MethodHandle allocSignerFuncHandle;

    private static final MemorySegment disposeSignerFunc;
    private static final MethodHandle disposeSignerFuncHandle;

    private static final MemorySegment initVerifyFunc;
    private static final MethodHandle initVerifyFuncHandle;

    private static final MemorySegment initSignerFunc;
    private static final MethodHandle initSignerFuncHandle;

    private static final MemorySegment updateSignerFunc;
    private static final MethodHandle updateSignerFuncHandle;

    private static final MemorySegment signerFunc;
    private static final MethodHandle signerFuncHandle;

    private static final MemorySegment verifierFunc;
    private static final MethodHandle verifierFuncHandle;

    private static final FunctionDescriptor entropyFd;
    private static final MethodType entropyMt;


    static
    {
        generateKeyPairFunc = lookup.find("MLDSA_generateKeyPair").orElseThrow();
        generateKeyPairFuncHandle = linker.downcallHandle(generateKeyPairFunc,
                FunctionDescriptor.of(
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS // upcall
                ));

        generateKeyPairWithSeedFunc = lookup.find("MLDSA_generateKeyPairSeed").orElseThrow();
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


        getPublicKeyFunc = lookup.find("MLDSA_getPublicKey").orElseThrow();
        getPublicKeyFuncHandle = linker.downcallHandle(getPublicKeyFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG
                ), Linker.Option.critical(true));

        getPrivateKeyFunc = lookup.find("MLDSA_getPrivateKey").orElseThrow();
        getPrivateKeyFuncHandle = linker.downcallHandle(getPrivateKeyFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG
                ), Linker.Option.critical(true));

        getSeedKeyFunc = lookup.find("MLDSA_getSeed").orElseThrow();
        getSeedKeyFuncHandle = linker.downcallHandle(getSeedKeyFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG
                ), Linker.Option.critical(true));

        decodePublicKeyFunc = lookup.find("MLDSA_decodePublicKey").orElseThrow();
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

        decodePrivateKeyFunc = lookup.find("MLDSA_decodePrivateKey").orElseThrow();
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


        allocSignerFunc = lookup.find("MLDSA_allocateSigner").orElseThrow();
        allocSignerFuncHandle = linker.downcallHandle(allocSignerFunc,
                FunctionDescriptor.of(
                        ValueLayout.ADDRESS
                ));


        disposeSignerFunc = lookup.find("MLDSA_disposeSigner").orElseThrow();
        disposeSignerFuncHandle = linker.downcallHandle(disposeSignerFunc,
                FunctionDescriptor.ofVoid(
                        ValueLayout.ADDRESS
                ));


        initVerifyFunc = lookup.find("MLDSA_initVerifier").orElseThrow();
        initVerifyFuncHandle = linker.downcallHandle(initVerifyFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_INT
                ));

        initSignerFunc = lookup.find("MLDSA_initSign").orElseThrow();
        initSignerFuncHandle = linker.downcallHandle(initSignerFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS
                ));


        updateSignerFunc = lookup.find("MLDSA_update").orElseThrow();
        updateSignerFuncHandle = linker.downcallHandle(updateSignerFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_INT
                ), Linker.Option.critical(true));


        signerFunc = lookup.find("MLDSA_sign").orElseThrow();
        signerFuncHandle = linker.downcallHandle(signerFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS
                ));

        verifierFunc = lookup.find("MLDSA_verify").orElseThrow();
        verifierFuncHandle = linker.downcallHandle(verifierFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.JAVA_INT
                ), Linker.Option.critical(true));


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
    public long generateKeyPair(int type, RandSource rndId)
    {
        try (Arena a = Arena.ofConfined())
        {
            var gHandle = MethodHandles.lookup().findVirtual(
                    rndId.getClass(),
                    "getEntropySegment",
                    entropyMt).bindTo(rndId);
            var getEntropySegment = linker.upcallStub(gHandle, entropyFd, a);

            MemorySegment retCodeRef = a.allocate(ValueLayout.JAVA_INT);
            MemorySegment segment = (MemorySegment) generateKeyPairFuncHandle.invokeExact(type, retCodeRef, getEntropySegment);

            int retCode = retCodeRef.get(ValueLayout.JAVA_INT, 0);
            if (retCode != ErrorCode.JO_SUCCESS.getCode())
            {
                return retCode;
            }
            return segment.address();
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING,
                    "FFI MLDSA_generateKeyPair", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public long generateKeyPair(int type, byte[] seed, int seedLen, RandSource rndSource)
    {
        try (Arena a = Arena.ofConfined())
        {

            var gHandle = MethodHandles.lookup().findVirtual(
                    rndSource.getClass(),
                    "getEntropySegment",
                    entropyMt).bindTo(rndSource);
            var getEntropySegment = linker.upcallStub(gHandle, entropyFd, a);


            MemorySegment retCodeRef = a.allocate(ValueLayout.JAVA_INT);
            MemorySegment seedRef = seed == null ? MemorySegment.NULL : a.allocate(seed.length);

            if (seed != null) {
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
            if (retCode != ErrorCode.JO_SUCCESS.getCode())
            {
                return retCode;
            }
            return segment.address();
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING,
                    "FFI MLDSA_generateKeyPair (seed)", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int getPublicKey(long ref, byte[] output)
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
                    "FFI MLDSA_getPublicKey", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int getPrivateKey(long ref, byte[] output)
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
                    "FFI MLDSA_getPrivateKey", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int getSeed(long ref, byte[] output)
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
                    "FFI MLDSA_getSeed", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int decode_publicKey(long spec_ref, int keyType, byte[] input, int inputOffset, int inputLen)
    {
        try
        {
            MemorySegment keySpec = MemorySegment.ofAddress(spec_ref);
            MemorySegment inputRef = input == null ? MemorySegment.NULL : MemorySegment.ofArray(input);
            return (int) decodePublicKeyFuncHandle.invokeExact(keySpec, keyType, inputRef, inputRef.byteSize(), inputOffset, inputLen);
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING,
                    "FFI MLDSA_decodePublicKey", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int decode_privateKey(long spec_ref, int keyType, byte[] input, int inputOffset, int inputLen)
    {
        try
        {
            MemorySegment keySpec = MemorySegment.ofAddress(spec_ref);
            MemorySegment inputRef = input == null ? MemorySegment.NULL : MemorySegment.ofArray(input);
            return (int) decodePrivateKeyFuncHandle.invokeExact(keySpec, keyType, inputRef, inputRef.byteSize(), inputOffset, inputLen);
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING,
                    "FFI MLDSA_decodePrivateKey", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }


    @Override
    public void disposeSigner(long reference)
    {
        try
        {
            MemorySegment ref = MemorySegment.ofAddress(reference);
            disposeSignerFuncHandle.invokeExact(ref);
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING,
                    "FFI MLDSA_disposeSigner", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public long allocateSigner()
    {
        try
        {
            MemorySegment segment = (MemorySegment) allocSignerFuncHandle.invokeExact();
            return segment.address();
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING,
                    "FFI MLDSA_allocateSigner", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int initVerify(long ref, long keyReference, byte[] context, int contextLen, int muOrdinal)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment ctx = MemorySegment.ofAddress(ref);
            MemorySegment keyRef = MemorySegment.ofAddress(keyReference);
            MemorySegment contextRef = context == null ? MemorySegment.NULL : a.allocate(context.length);
            if (context != null) {
                contextRef.asByteBuffer().put(context);
            }
            return (int) initVerifyFuncHandle.invokeExact(ctx, keyRef, contextRef, contextRef.byteSize(), contextLen, muOrdinal);

        }
        catch (Throwable t)
        {
            L.log(Level.WARNING,
                    "FFI MLDSA_initVerifier", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int initSign(long ref, long keyReference, byte[] context, int contextLen, int muOrdinal, RandSource randSource)
    {
        try (Arena a = Arena.ofConfined())
        {

            var gHandle = MethodHandles.lookup().findVirtual(
                    randSource.getClass(),
                    "getEntropySegment",
                    entropyMt).bindTo(randSource);
            var getEntropySegment = linker.upcallStub(gHandle, entropyFd, a);


            MemorySegment ctx = MemorySegment.ofAddress(ref);
            MemorySegment keyRef = MemorySegment.ofAddress(keyReference);
            MemorySegment contextRef = context == null ? MemorySegment.NULL : a.allocate(context.length);

            if (context != null)
            {
                contextRef.asByteBuffer().put(context);
            }

            return (int) initSignerFuncHandle.invokeExact(ctx, keyRef, contextRef, contextRef.byteSize(), contextLen, muOrdinal, getEntropySegment);

        }
        catch (Throwable t)
        {
            L.log(Level.WARNING,
                    "FFI MLDSA_initSign", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int update(long ref, byte[] input, int inputOffset, int inputLen)
    {
        try
        {
            MemorySegment ctx = MemorySegment.ofAddress(ref);
            MemorySegment inputRef = input == null ? MemorySegment.NULL : MemorySegment.ofArray(input);
            return (int) updateSignerFuncHandle.invokeExact(ctx, inputRef, inputRef.byteSize(), inputOffset, inputLen);

        }
        catch (Throwable t)
        {
            L.log(Level.WARNING,
                    "FFI MLDSA_update", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int sign(long ref, byte[] output, int offset, RandSource randSource)
    {
        try (Arena a = Arena.ofConfined())
        {

            var gHandle = MethodHandles.lookup().findVirtual(
                    randSource.getClass(),
                    "getEntropySegment",
                    entropyMt).bindTo(randSource);
            var getEntropySegment = linker.upcallStub(gHandle, entropyFd, a);

            MemorySegment ctx = MemorySegment.ofAddress(ref);

            MemorySegment outputSegment = output == null ? MemorySegment.NULL : a.allocate(output.length);
            int code = (int) signerFuncHandle.invokeExact(ctx, outputSegment, outputSegment.byteSize(), offset, getEntropySegment);

            if (output != null)
            {
                outputSegment.asByteBuffer().get(output);
            }
            return code;

        }
        catch (Throwable t)
        {
            L.log(Level.WARNING,
                    "FFI MLDSA_sign", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int verify(long ref, byte[] sigBytes, int sigLen)
    {
        try
        {
            MemorySegment ctx = MemorySegment.ofAddress(ref);
            MemorySegment sigSegment = sigBytes == null ? MemorySegment.NULL : MemorySegment.ofArray(sigBytes);
            return (int) verifierFuncHandle.invokeExact(ctx, sigSegment, sigSegment.byteSize(), sigLen);

        }
        catch (Throwable t)
        {
            L.log(Level.WARNING,
                    "FFI MLDSA_verify", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }


}
