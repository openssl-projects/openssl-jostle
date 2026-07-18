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

import org.openssl.jostle.rand.EntropyUpcall;
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
        generateKeyPairFunc = lookup.find("JoSLHDSA_generateKeyPair").orElseThrow();
        generateKeyPairFuncHandle = linker.downcallHandle(generateKeyPairFunc,
                FunctionDescriptor.of(
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS
                ));

        generateKeyPairWithSeedFunc = lookup.find("JoSLHDSA_generateKeyPairSeed").orElseThrow();
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


        getPublicKeyFunc = lookup.find("JoSLHDSA_getPublicKey").orElseThrow();
        getPublicKeyFuncHandle = linker.downcallHandle(getPublicKeyFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG
                ), Linker.Option.critical(true));

        getPrivateKeyFunc = lookup.find("JoSLHDSA_getPrivateKey").orElseThrow();
        getPrivateKeyFuncHandle = linker.downcallHandle(getPrivateKeyFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG
                ), Linker.Option.critical(true));


        decodePublicKeyFunc = lookup.find("JoSLHDSA_decodePublicKey").orElseThrow();
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

        decodePrivateKeyFunc = lookup.find("JoSLHDSA_decodePrivateKey").orElseThrow();
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


        allocSignerFunc = lookup.find("JoSLHDSA_allocateSigner").orElseThrow();
        allocSignerFuncHandle = linker.downcallHandle(allocSignerFunc,
                FunctionDescriptor.of(
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS
                ));


        disposeSignerFunc = lookup.find("JoSLHDSA_disposeSigner").orElseThrow();
        disposeSignerFuncHandle = linker.downcallHandle(disposeSignerFunc,
                FunctionDescriptor.ofVoid(
                        ValueLayout.ADDRESS
                ));


        initVerifyFunc = lookup.find("JoSLHDSA_initVerifier").orElseThrow();
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

        initSignerFunc = lookup.find("JoSLHDSA_initSign").orElseThrow();
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


        updateSignerFunc = lookup.find("JoSLHDSA_update").orElseThrow();
        updateSignerFuncHandle = linker.downcallHandle(updateSignerFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_INT
                ), Linker.Option.critical(true));


        signerFunc = lookup.find("JoSLHDSA_sign").orElseThrow();
        signerFuncHandle = linker.downcallHandle(signerFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS
                ));

        verifierFunc = lookup.find("JoSLHDSA_verify").orElseThrow();
        verifierFuncHandle = linker.downcallHandle(verifierFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG,
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
            MemorySegment retCodeRef = a.allocate(ValueLayout.JAVA_INT);

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

            MemorySegment segment = (MemorySegment) generateKeyPairFuncHandle.invokeExact(type, retCodeRef, getEntropySegment);

            err[0] = retCodeRef.get(ValueLayout.JAVA_INT, 0);
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
                        RandSource.class,
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

            err[0] = retCodeRef.get(ValueLayout.JAVA_INT, 0);

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
                    "FFI SLH_DSA_getPrivateKey", t);
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
                    "FFI SLH_DSA_getPublicKey", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }


    @Override
    public int ni_decode_publicKey(long specRef, int keyType, byte[] input, int inputOffset, int inputLen)
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
    public int ni_decode_privateKey(long specRef, int keyType, byte[] input, int inputOffset, int inputLen)
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
    public long ni_allocateSigner(int[] err)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment retCode = a.allocate(ValueLayout.JAVA_INT);
            MemorySegment segment = (MemorySegment) allocSignerFuncHandle.invokeExact(retCode);
            err[0] = retCode.get(ValueLayout.JAVA_INT, 0);
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
    public int ni_initVerify(long ref, long keyReference, byte[] context, int contextLen, int messageEncoding, int deterministic)
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
    public int ni_update(long ref, byte[] input, int inputOffset, int inputLen)
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
    public long ni_sign(long ref, byte[] output, int offset, RandSource randSource)
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

            MemorySegment ctx = MemorySegment.ofAddress(ref);
            MemorySegment outputSegment = output == null ? MemorySegment.NULL : a.allocate(output.length);
            int r = (int) signerFuncHandle.invokeExact(ctx, outputSegment, outputSegment.byteSize(), offset, getEntropySegment);

            // Copy back only the bytes the C side actually wrote, at their
            // original offset. A blanket get(output) would zero caller bytes
            // outside [offset, offset+r) because the arena segment is
            // zero-filled (Arena.allocate), not a copy of the caller's array.
            if (output != null && r > 0)
            {
                outputSegment.asByteBuffer().get(offset, output, offset, r);
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
    public int ni_verify(long ref, byte[] sigBytes, int sigLen)
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
    public int ni_initSign(long reference, long keyReference, byte[] context, int contextLen, int messageEncoding, int deterministic, RandSource randSource)
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
    public void ni_disposeSigner(long reference)
    {
        try
        {
            MemorySegment ref = MemorySegment.ofAddress(reference);
            disposeSignerFuncHandle.invokeExact(ref);
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING,
                    "FFI SLH_DSA_disposeSigner", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }
}
