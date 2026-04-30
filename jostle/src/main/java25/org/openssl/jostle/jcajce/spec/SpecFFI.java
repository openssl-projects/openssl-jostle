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

package org.openssl.jostle.jcajce.spec;

import org.openssl.jostle.rand.RandSource;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.util.logging.Level;
import java.util.logging.Logger;

public class SpecFFI implements SpecNI
{
    private static final Logger L = Logger.getLogger("SpecNI_FFI");
    private static final SymbolLookup lookup = SymbolLookup.loaderLookup();
    private static final Linker linker = Linker.nativeLinker();

    private static final MemorySegment allocateFunc;
    private static final MethodHandle allocateFuncHandle;

    private static final MemorySegment disposeFunc;
    private static final MethodHandle disposeFuncHandle;

    private static final MemorySegment encapFunc;
    private static final MethodHandle encapFuncHandle;

    private static final MemorySegment decapFunc;
    private static final MethodHandle decapFuncHandle;

    private static final MemorySegment getNameFunc;
    private static final MethodHandle getNameFuncHandle;

    private static final FunctionDescriptor entropyFd;
    private static final MethodType entropyMt;

    static
    {

        allocateFunc = lookup.find("SpecNI_allocateKeySpec").orElseThrow();
        allocateFuncHandle = linker.downcallHandle(allocateFunc,
                FunctionDescriptor.of(
                        ValueLayout.ADDRESS, // return prt
                        ValueLayout.ADDRESS // err out
                ));

        disposeFunc = lookup.find("SpecNI_disposeKeySpec").orElseThrow();
        disposeFuncHandle = linker.downcallHandle(disposeFunc,
                FunctionDescriptor.ofVoid(
                        ValueLayout.ADDRESS // ptr
                ));


        encapFunc = lookup.find("SpecNI_Encap").orElseThrow();
        encapFuncHandle = linker.downcallHandle(encapFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS
                ));

        decapFunc = lookup.find("SpecNI_Decap").orElseThrow();
        decapFuncHandle = linker.downcallHandle(decapFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT
                ), Linker.Option.critical(true));


        getNameFunc = lookup.find("SpecNI_GetName").orElseThrow();
        getNameFuncHandle = linker.downcallHandle(getNameFunc,
                FunctionDescriptor.of(
                        ValueLayout.ADDRESS, // return
                        ValueLayout.ADDRESS, // spec
                        ValueLayout.ADDRESS // len
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
    public void ni_dispose(long reference)
    {
        try
        {
            disposeFuncHandle.invokeExact(MemorySegment.ofAddress(reference));
        }
        catch (Throwable t)
        {
            L.log(
                    Level.WARNING,
                    "FFI SpecNI_disposeKeySpec",
                    t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public long ni_allocate(int[] err)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment retCode = a.allocate(ValueLayout.JAVA_INT);
            MemorySegment addr = (MemorySegment) allocateFuncHandle.invokeExact(retCode);
            handleErrors(retCode.get(ValueLayout.JAVA_INT,0));
            return addr.address();
        }
        catch (Throwable t)
        {
            L.log(
                    Level.WARNING,
                    "FFI SpecNI_allocateKeySpec",
                    t);
            throw new RuntimeException(t.getMessage(), t);
        }

    }


    @Override
    public String ni_getName(long keyRef)
    {
        try (Arena a = Arena.ofConfined())
        {
            var ref = MemorySegment.ofAddress(keyRef);
            var len = a.allocate(ValueLayout.JAVA_LONG);
            MemorySegment memorySegment = (MemorySegment) getNameFuncHandle.invokeExact(ref, len);

            long size = len.get(ValueLayout.OfLong.JAVA_LONG, 0);
            if (size < 0)
            {
                throw new IllegalArgumentException("returned name len is negative");
            }
            // Mirror the JNI bridge: SpecNI_GetName returns NULL with *len=0
            // when the spec is null or has no key. Surface this as a null
            // String to the Java caller rather than dereferencing a NULL
            // segment.
            if (size == 0 || memorySegment.address() == 0)
            {
                return null;
            }
            memorySegment = memorySegment.reinterpret(size + 1); // + null termination
            return memorySegment.getString(0);
        }
        catch (IllegalArgumentException ilex)
        {
            throw ilex;
        }
        catch (Throwable t)
        {
            L.log(
                    Level.WARNING,
                    "FFI SpecNI_GetName",
                    t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_encap(long keyRef, String opt, byte[] secret, int inOff, int inLen, byte[] out, int off, int len, RandSource randSource)
    {
        // we have to arena because C code will make upcall for entropy which is
        // not possible during a critical section
        try (Arena a = Arena.ofConfined())
        {
            var ref = MemorySegment.ofAddress(keyRef);
            var optRef = opt != null ? a.allocateFrom(opt) : MemorySegment.NULL;
            var secretRef = secret != null ? a.allocate(secret.length) : MemorySegment.NULL;
            var outRef = out != null ? a.allocate(out.length) : MemorySegment.NULL;

            // let encap()'s existing check return
            // JO_RAND_NO_RAND_UP_CALL — same path JNI takes.
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


            int r = (int) encapFuncHandle.invokeExact(ref, optRef, secretRef, secretRef.byteSize(), inOff, inLen, outRef, outRef.byteSize(), off, len, getEntropySegment);

            if (out != null)
            {
                outRef.asByteBuffer().get(out);
            }

            if (secret != null)
            {
                secretRef.asByteBuffer().get(secret);
            }

            return r;
        }
        catch (Throwable t)
        {
            L.log(
                    Level.WARNING,
                    "FFI SpecNI_Encap",
                    t);
            throw new RuntimeException(t.getMessage(), t);
        }

    }

    @Override
    public int ni_decap(long keyRef, String opt, byte[] input, int inOff, int inLen, byte[] out, int off, int len)
    {
        // Decap has no upcall, so can use critical
        try (Arena a = Arena.ofConfined())
        {
            var ref = MemorySegment.ofAddress(keyRef);
            var optRef = opt != null ? a.allocateFrom(opt) : MemorySegment.NULL;
            var inputRef = input != null ? MemorySegment.ofArray(input) : MemorySegment.NULL;
            var outRef = out != null ? MemorySegment.ofArray(out) : MemorySegment.NULL;

            return (int) decapFuncHandle.invokeExact(ref, optRef, inputRef, inputRef.byteSize(), inOff, inLen, outRef, outRef.byteSize(), off, len);
        }
        catch (Throwable t)
        {
            L.log(
                    Level.WARNING,
                    "FFI SpecNI_Decap",
                    t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

}
