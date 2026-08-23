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

package org.openssl.jostle.jcajce.provider.ed;

import org.openssl.jostle.rand.EntropyUpcall;
import org.openssl.jostle.rand.RandSource;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.util.logging.Level;
import java.util.logging.Logger;

// Symbol resolution is parameterised by a SymbolLookup so the same
// marshalling serves both interface libraries. A static
// SymbolLookup.loaderLookup() would resolve into whichever library loaded
// first — both export the same Jo* names — so a FIPS subclass over it would
// silently drive the BASE library (see MDServiceFFI, FIPSLibraryLookup).
public class EdDSAServiceFFI implements EDServiceNI
{

    private static final Logger L = Logger.getLogger("EdDSA_NI_FFI");
    private static final Linker linker = Linker.nativeLinker();

    private final MethodHandle generateKeyPairFuncHandle;
    private final MethodHandle getPublicKeyFuncHandle;
    private final MethodHandle getPrivateKeyFuncHandle;
    private final MethodHandle decodePublicKeyFuncHandle;
    private final MethodHandle decodePrivateKeyFuncHandle;
    private final MethodHandle allocSignerFuncHandle;
    private final MethodHandle disposeSignerFuncHandle;
    private final MethodHandle initVerifyFuncHandle;
    private final MethodHandle initSignerFuncHandle;
    private final MethodHandle updateSignerFuncHandle;
    private final MethodHandle signerFuncHandle;
    private final MethodHandle verifierFuncHandle;

    // Lookup-independent constants for the RandSource entropy upcall stub.
    private static final FunctionDescriptor entropyFd = EntropyUpcall.DESCRIPTOR;
    private static final MethodType entropyMt = EntropyUpcall.METHOD_TYPE;

    public EdDSAServiceFFI()
    {
        this(SymbolLookup.loaderLookup());
    }

    public EdDSAServiceFFI(SymbolLookup lookup)
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
    public EdDSAServiceFFI(SymbolLookup lookup, String symPrefix)
    {
        generateKeyPairFuncHandle = linker.downcallHandle(
                lookup.find(symPrefix + "JoEDDSA_generateKeyPair").orElseThrow(),
                FunctionDescriptor.of(
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS // upcall
                ));

        getPublicKeyFuncHandle = linker.downcallHandle(
                lookup.find(symPrefix + "JoEDDSA_getPublicKey").orElseThrow(),
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG
                ), Linker.Option.critical(true));

        getPrivateKeyFuncHandle = linker.downcallHandle(
                lookup.find(symPrefix + "JoEDDSA_getPrivateKey").orElseThrow(),
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG
                ), Linker.Option.critical(true));

        decodePublicKeyFuncHandle = linker.downcallHandle(
                lookup.find(symPrefix + "JoEDDSA_decodePublicKey").orElseThrow(),
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_INT
                ), Linker.Option.critical(true));

        decodePrivateKeyFuncHandle = linker.downcallHandle(
                lookup.find(symPrefix + "JoEDDSA_decodePrivateKey").orElseThrow(),
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_INT
                ), Linker.Option.critical(true));

        allocSignerFuncHandle = linker.downcallHandle(
                lookup.find(symPrefix + "JoEDDSA_allocateSigner").orElseThrow(),
                FunctionDescriptor.of(
                        ValueLayout.ADDRESS, ValueLayout.ADDRESS
                ));

        disposeSignerFuncHandle = linker.downcallHandle(
                lookup.find(symPrefix + "JoEDDSA_disposeSigner").orElseThrow(),
                FunctionDescriptor.ofVoid(
                        ValueLayout.ADDRESS
                ));

        initVerifyFuncHandle = linker.downcallHandle(
                lookup.find(symPrefix + "JoEDDSA_initVerifier").orElseThrow(),
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT, // return code
                        ValueLayout.ADDRESS, // ctx
                        ValueLayout.ADDRESS, // kp
                        ValueLayout.ADDRESS, // name
                        ValueLayout.JAVA_INT, // name_len
                        ValueLayout.ADDRESS, // context
                        ValueLayout.JAVA_LONG,  // context size
                        ValueLayout.JAVA_INT // context_len
                ));

        initSignerFuncHandle = linker.downcallHandle(
                lookup.find(symPrefix + "JoEDDSA_initSign").orElseThrow(),
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT, // return code
                        ValueLayout.ADDRESS, // ctx
                        ValueLayout.ADDRESS, // kp
                        ValueLayout.ADDRESS, // name
                        ValueLayout.JAVA_INT, // name_len
                        ValueLayout.ADDRESS, // context
                        ValueLayout.JAVA_LONG,  // context size
                        ValueLayout.JAVA_INT, // context_len
                        ValueLayout.ADDRESS
                ));

        updateSignerFuncHandle = linker.downcallHandle(
                lookup.find(symPrefix + "JoEDDSA_update").orElseThrow(),
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_INT
                ), Linker.Option.critical(true));

        signerFuncHandle = linker.downcallHandle(
                lookup.find(symPrefix + "JoEDDSA_sign").orElseThrow(),
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS
                ));

        verifierFuncHandle = linker.downcallHandle(
                lookup.find(symPrefix + "JoEDDSA_verify").orElseThrow(),
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.JAVA_INT
                ), Linker.Option.critical(true));
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
            MemorySegment segment = (MemorySegment) generateKeyPairFuncHandle.invokeExact(type, retCodeRef, getEntropySegment);

            err[0] = retCodeRef.get(ValueLayout.JAVA_INT, 0);
            return segment.address();
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING,
                    "FFI JoEDDSA_generateKeyPair", t);
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
                    "FFI JoEDDSA_getPublicKey", t);
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
                    "FFI JoEDDSA_getPrivateKey", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }


    @Override
    public int ni_decode_publicKey(long spec_ref, int keyType, byte[] input, int inputOffset, int inputLen)
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
                    "FFI JoEDDSA_decodePublicKey", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_decode_privateKey(long spec_ref, int keyType, byte[] input, int inputOffset, int inputLen)
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
                    "FFI JoEDDSA_decodePrivateKey", t);
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
                    "FFI JoEDDSA_disposeSigner", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public long ni_allocateSigner(int[] err)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment errSeg = a.allocate(ValueLayout.JAVA_INT);
            MemorySegment segment = (MemorySegment) allocSignerFuncHandle.invokeExact(errSeg);
            err[0] = errSeg.getAtIndex(ValueLayout.JAVA_INT, 0);
            return segment.address();
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING,
                    "FFI JoEDDSA_allocateSigner", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_initVerify(long ref, long keyReference, String name, byte[] context, int contextLen)
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
            // A null name must reach the C bridge as a NULL pointer so it returns
            // JO_NAME_IS_NULL (allocateFrom(null) would NPE, diverging from JNI).
            MemorySegment nameSeg = name == null ? MemorySegment.NULL : a.allocateFrom(name);

            // byteSize() includes the NUL terminator; the native side wants the
            // NUL-excluded length (matching ni_initSign and the JNI
            // GetStringUTFLength path) so an empty name yields name_len == 0.
            int nameLen = name == null ? 0 : (int) nameSeg.byteSize() - 1;
            return (int) initVerifyFuncHandle.invokeExact(ctx, keyRef, nameSeg, nameLen, contextRef, contextRef.byteSize(), contextLen);

        }
        catch (Throwable t)
        {
            L.log(Level.WARNING,
                    "FFI JoEDDSA_initVerifier", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_initSign(long ref, long keyReference, String name, byte[] context, int contextLen, RandSource randSource)
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
            MemorySegment keyRef = MemorySegment.ofAddress(keyReference);
            MemorySegment contextRef = context == null ? MemorySegment.NULL : a.allocate(context.length);

            if (context != null)
            {
                contextRef.asByteBuffer().put(context);
            }


            // A null name must reach the C bridge as a NULL pointer so it returns
            // JO_NAME_IS_NULL (allocateFrom(null) would NPE, diverging from JNI).
            MemorySegment nameSeg = name == null ? MemorySegment.NULL : a.allocateFrom(name);

            int nameLen = name == null ? 0 : (int) nameSeg.byteSize() - 1;
            return (int) initSignerFuncHandle.invokeExact(ctx, keyRef, nameSeg, nameLen, contextRef, contextRef.byteSize(), contextLen, getEntropySegment);

        }
        catch (Throwable t)
        {
            L.log(Level.WARNING,
                    "FFI JoEDDSA_initSign", t);
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
                    "FFI JoEDDSA_update", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_sign(long ref, byte[] output, int offset, RandSource randSource)
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
            int code = (int) signerFuncHandle.invokeExact(ctx, outputSegment, outputSegment.byteSize(), offset, getEntropySegment);

            // Copy back only the bytes the C side actually wrote, at their
            // original offset. A blanket get(output) would zero caller bytes
            // outside [offset, offset+code) because the arena segment is
            // zero-filled (Arena.allocate), not a copy of the caller's array.
            if (output != null && code > 0)
            {
                outputSegment.asByteBuffer().get(offset, output, offset, code);
            }
            return code;

        }
        catch (Throwable t)
        {
            L.log(Level.WARNING,
                    "FFI JoEDDSA_sign", t);
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
                    "FFI JoEDDSA_verify", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }


}
