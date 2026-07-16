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

import org.openssl.jostle.rand.EntropyUpcall;
import org.openssl.jostle.rand.RandSource;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.util.logging.Level;
import java.util.logging.Logger;

// Symbol resolution is parameterised by a SymbolLookup so the same
// marshalling serves both interface libraries (see MDServiceFFI).
public class SpecFFI implements SpecNI
{
    private static final Logger L = Logger.getLogger("SpecNI_FFI");
    private static final Linker linker = Linker.nativeLinker();

    private final MethodHandle allocateFuncHandle;

    private final MethodHandle disposeFuncHandle;

    private final MethodHandle encapFuncHandle;

    private final MethodHandle decapFuncHandle;

    private final MethodHandle getNameFuncHandle;

    // Lookup-independent constants for the RandSource entropy upcall stub.
    private static final FunctionDescriptor entropyFd = EntropyUpcall.DESCRIPTOR;
    private static final MethodType entropyMt = EntropyUpcall.METHOD_TYPE;

    public SpecFFI()
    {
        this(SymbolLookup.loaderLookup());
    }

    public SpecFFI(SymbolLookup lookup)
    {

        MemorySegment allocateFunc = lookup.find("JoSpec_allocateKeySpec").orElseThrow();
        allocateFuncHandle = linker.downcallHandle(allocateFunc,
                FunctionDescriptor.of(
                        ValueLayout.ADDRESS, // return prt
                        ValueLayout.ADDRESS // err out
                ));

        MemorySegment disposeFunc = lookup.find("JoSpec_disposeKeySpec").orElseThrow();
        disposeFuncHandle = linker.downcallHandle(disposeFunc,
                FunctionDescriptor.ofVoid(
                        ValueLayout.ADDRESS // ptr
                ));


        MemorySegment encapFunc = lookup.find("JoSpec_Encap").orElseThrow();
        encapFuncHandle = linker.downcallHandle(encapFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS
                ));

        MemorySegment decapFunc = lookup.find("JoSpec_Decap").orElseThrow();
        decapFuncHandle = linker.downcallHandle(decapFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS
                ));


        MemorySegment getNameFunc = lookup.find("JoSpec_GetName").orElseThrow();
        getNameFuncHandle = linker.downcallHandle(getNameFunc,
                FunctionDescriptor.of(
                        ValueLayout.ADDRESS, // return
                        ValueLayout.ADDRESS, // spec
                        ValueLayout.ADDRESS // len
                ));
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
                    "FFI JoSpec_disposeKeySpec",
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
            int code = retCode.get(ValueLayout.JAVA_INT, 0);
            // Mirror the JNI bridge, which writes the status into err[0] via
            // SetIntArrayRegion. A direct NI caller inspecting err[0] must see
            // the same value on both bridges.
            if (err != null && err.length > 0)
            {
                err[0] = code;
            }
            handleErrors(code);
            return addr.address();
        }
        catch (Throwable t)
        {
            L.log(
                    Level.WARNING,
                    "FFI JoSpec_allocateKeySpec",
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
            // Mirror the JNI bridge: JoSpec_GetName returns NULL with *len=0
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
                    "FFI JoSpec_GetName",
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

            // Pre-copy the caller's secret buffer into the arena segment so any
            // bytes the C side does not overwrite (an over-declared secret
            // window: inLen larger than the actual shared-secret length) are
            // preserved on copy-back, matching the JNI bridge's in-place
            // semantics rather than zero-clobbering the tail.
            if (secret != null)
            {
                MemorySegment.copy(secret, 0, secretRef, ValueLayout.JAVA_BYTE, 0, secret.length);
            }

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

            // Copy back only the regions the C side wrote, at their original
            // offsets. A blanket get() would zero caller bytes outside the
            // written window because the arena segments are zero-filled
            // (Arena.allocate), not copies of the caller's arrays. A real
            // encap (out != null, r > 0) wrote both the encapsulation (r bytes
            // at off) and the shared secret (at inOff). The secret copy-back is
            // gated on out != null too: on a length probe (out == null) C
            // returns the ciphertext length as a positive r but writes NOTHING,
            // so a bare `r > 0` gate would zero the caller's secret buffer with
            // unwritten arena bytes — the exact JNI/FFI divergence this guards
            // against. The secret window is pre-copied above, so copying inLen
            // bytes preserves any tail C did not overwrite.
            if (out != null && r > 0)
            {
                outRef.asByteBuffer().get(off, out, off, r);
                if (secret != null)
                {
                    secretRef.asByteBuffer().get(inOff, secret, inOff, inLen);
                }
            }

            return r;
        }
        catch (Throwable t)
        {
            L.log(
                    Level.WARNING,
                    "FFI JoSpec_Encap",
                    t);
            throw new RuntimeException(t.getMessage(), t);
        }

    }

    @Override
    public int ni_decap(long keyRef, String opt, byte[] input, int inOff, int inLen, byte[] out, int off, int len, RandSource randSource)
    {
        // The C side binds the RandSource upcall (decap is type-agnostic —
        // e.g. an RSA-KEM decap drives RSA blinding, which consumes
        // entropy), and upcalls are impossible from a critical section —
        // so arena copies rather than Option.critical heap segments, the
        // same shape as encap.
        try (Arena a = Arena.ofConfined())
        {
            var ref = MemorySegment.ofAddress(keyRef);
            var optRef = opt != null ? a.allocateFrom(opt) : MemorySegment.NULL;
            var inputRef = input != null ? a.allocateFrom(ValueLayout.JAVA_BYTE, input) : MemorySegment.NULL;
            var outRef = out != null ? a.allocate(out.length) : MemorySegment.NULL;

            // let decap()'s existing check return
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

            int r = (int) decapFuncHandle.invokeExact(ref, optRef, inputRef, inputRef.byteSize(), inOff, inLen, outRef, outRef.byteSize(), off, len, getEntropySegment);

            // Copy back only the shared-secret bytes the C side wrote, at their
            // original offset. A blanket get(out) would zero caller bytes
            // outside [off, off+r) because the arena segment is zero-filled
            // (Arena.allocate), not a copy of the caller's array. r > 0 means
            // decap succeeded and wrote r secret bytes at off; the probe
            // (out == null) and error paths write nothing.
            if (out != null && r > 0)
            {
                outRef.asByteBuffer().get(off, out, off, r);
            }

            return r;
        }
        catch (Throwable t)
        {
            L.log(
                    Level.WARNING,
                    "FFI JoSpec_Decap",
                    t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

}
