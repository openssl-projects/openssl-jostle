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

package org.openssl.jostle.jcajce.provider.slhdsa;

import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.rand.RandSource;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.util.logging.Level;
import java.util.logging.Logger;

public class SLHDSAServiceFFI implements SLHDSAServiceNI
{

    private static final Logger L = Logger.getLogger("SLH_DSA_NI_FFI");
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
        generateKeyPairFunc = lookup.find("SLH_DSA_generateKeyPair").orElseThrow();
        generateKeyPairFuncHandle = linker.downcallHandle(generateKeyPairFunc,
                FunctionDescriptor.of(
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS
                ));

        generateKeyPairWithSeedFunc = lookup.find("SLH_DSA_generateKeyPairSeed").orElseThrow();
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


        getPublicKeyFunc = lookup.find("SLH_DSA_getPublicKey").orElseThrow();
        getPublicKeyFuncHandle = linker.downcallHandle(getPublicKeyFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG
                ), Linker.Option.critical(true));

        getPrivateKeyFunc = lookup.find("SLH_DSA_getPrivateKey").orElseThrow();
        getPrivateKeyFuncHandle = linker.downcallHandle(getPrivateKeyFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG
                ), Linker.Option.critical(true));

//        getSeedKeyFunc = lookup.find("SLH_DSA_getSeed").orElseThrow();
//        getSeedKeyFuncHandle = linker.downcallHandle(getSeedKeyFunc,
//                FunctionDescriptor.of(
//                        ValueLayout.JAVA_INT,
//                        ValueLayout.ADDRESS,
//                        ValueLayout.ADDRESS,
//                        ValueLayout.JAVA_LONG
//                ), Linker.Option.critical(true));

        decodePublicKeyFunc = lookup.find("SLH_DSA_decodePublicKey").orElseThrow();
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

        decodePrivateKeyFunc = lookup.find("SLH_DSA_decodePrivateKey").orElseThrow();
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


        allocSignerFunc = lookup.find("SLH_DSA_allocateSigner").orElseThrow();
        allocSignerFuncHandle = linker.downcallHandle(allocSignerFunc,
                FunctionDescriptor.of(
                        ValueLayout.ADDRESS
                ));


        disposeSignerFunc = lookup.find("SLH_DSA_disposeSigner").orElseThrow();
        disposeSignerFuncHandle = linker.downcallHandle(disposeSignerFunc,
                FunctionDescriptor.ofVoid(
                        ValueLayout.ADDRESS
                ));


        initVerifyFunc = lookup.find("SLH_DSA_initVerifier").orElseThrow();
        initVerifyFuncHandle = linker.downcallHandle(initVerifyFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_INT
                ));

        initSignerFunc = lookup.find("SLH_DSA_initSign").orElseThrow();
        initSignerFuncHandle = linker.downcallHandle(initSignerFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS
                ));


        updateSignerFunc = lookup.find("SLH_DSA_update").orElseThrow();
        updateSignerFuncHandle = linker.downcallHandle(updateSignerFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_INT
                ), Linker.Option.critical(true));


        signerFunc = lookup.find("SLH_DSA_sign").orElseThrow();
        signerFuncHandle = linker.downcallHandle(signerFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS
                ));

        verifierFunc = lookup.find("SLH_DSA_verify").orElseThrow();
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
    public long generateKeyPair(int type, RandSource randSource)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment retCodeRef = a.allocate(ValueLayout.JAVA_INT);

            var gHandle = MethodHandles.lookup().findVirtual(
                    randSource.getClass(),
                    "getEntropySegment",
                    entropyMt).bindTo(randSource);
            var getEntropySegment = linker.upcallStub(gHandle, entropyFd, a);

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
                    "FFI SLH_DSA_generateKeyPair", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public long generateKeyPair(int type, byte[] seed, int seedLen, RandSource randSource)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment retCodeRef = a.allocate(ValueLayout.JAVA_INT);
            MemorySegment seedRef = seed == null ? MemorySegment.NULL : a.allocate(seed.length);

            var gHandle = MethodHandles.lookup().findVirtual(
                    randSource.getClass(),
                    "getEntropySegment",
                    entropyMt).bindTo(randSource);
            var getEntropySegment = linker.upcallStub(gHandle, entropyFd, a);

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
            if (retCode != ErrorCode.JO_SUCCESS.getCode())
            {
                return retCode;
            }
            return segment.address();
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING,
                    "FFI SLH_DSA_generateKeyPair (seed)", t);
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
                    "FFI SLH_DSA_getPrivateKey", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public long getPublicKey(long ref, byte[] output)
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
                    "FFI SLH_DSA_getPublicKey", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }


    @Override
    public int decode_publicKey(long specRef, int keyType, byte[] input, int inputOffset, int inputLen)
    {
        try
        {
            MemorySegment keySpec = MemorySegment.ofAddress(specRef);
            MemorySegment inputRef = input == null ? MemorySegment.NULL : MemorySegment.ofArray(input);
            return (int) decodePublicKeyFuncHandle.invokeExact(keySpec, keyType, inputRef, inputRef.byteSize(), inputOffset, inputLen);
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING,
                    "FFI SLH_DSA_decodePublicKey", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int decode_privateKey(long specRef, int keyType, byte[] input, int inputOffset, int inputLen)
    {
        try
        {
            MemorySegment keySpec = MemorySegment.ofAddress(specRef);
            MemorySegment inputRef = input == null ? MemorySegment.NULL : MemorySegment.ofArray(input);
            return (int) decodePrivateKeyFuncHandle.invokeExact(keySpec, keyType, inputRef, inputRef.byteSize(), inputOffset, inputLen);
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING,
                    "FFI SLH_DSA_decodePrivateKey", t);
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
                    "FFI SLH_DSA_allocateSigner", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int initVerify(long ref, long keyReference, byte[] context, int contextLen, int messageEncoding, int deterministic)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment ctx = MemorySegment.ofAddress(ref);
            MemorySegment keyRef = MemorySegment.ofAddress(keyReference);
            MemorySegment contextRef = context == null ? MemorySegment.NULL : a.allocate(context.length);
            if (context != null)
            {
                contextRef.asByteBuffer().put(context);
            }
            return (int) initVerifyFuncHandle.invokeExact(ctx, keyRef, contextRef, contextRef.byteSize(), contextLen, messageEncoding, deterministic);

        }
        catch (Throwable t)
        {
            L.log(Level.WARNING,
                    "FFI SLH_DSA_initVerifier", t);
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
                    "FFI SLH_DSA_update", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public long sign(long ref, byte[] output, int offset, RandSource randSource)
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
            int r = (int) signerFuncHandle.invokeExact(ctx, outputSegment, outputSegment.byteSize(), offset,getEntropySegment);

            if (output != null)
            {
                outputSegment.asByteBuffer().get(output);
            }

            return r;
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING,
                    "FFI SLH_DSA_sign", t);
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
                    "FFI SLH_DSA_verify", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public long initSign(long reference, long keyReference, byte[] context, int contextLen, int messageEncoding, int deterministic, RandSource randSource)
    {
        try (Arena a = Arena.ofConfined())
        {

            var gHandle = MethodHandles.lookup().findVirtual(
                    randSource.getClass(),
                    "getEntropySegment",
                    entropyMt).bindTo(randSource);
            var getEntropySegment = linker.upcallStub(gHandle, entropyFd, a);


            MemorySegment ctx = MemorySegment.ofAddress(reference);
            MemorySegment keyRef = MemorySegment.ofAddress(keyReference);
            MemorySegment contextRef = context == null ? MemorySegment.NULL : a.allocate(context.length);

            if (context != null)
            {
                contextRef.asByteBuffer().put(context);
            }

            return (int) initSignerFuncHandle.invokeExact(ctx, keyRef, contextRef, contextRef.byteSize(), contextLen, messageEncoding, deterministic, getEntropySegment);

        }
        catch (Throwable t)
        {
            L.log(Level.WARNING,
                    "FFI SLH_DSA_initSign", t);
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
}
