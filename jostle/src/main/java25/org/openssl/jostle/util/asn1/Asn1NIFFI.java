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

package org.openssl.jostle.util.asn1;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.util.logging.Level;
import java.util.logging.Logger;

// Symbol resolution is parameterised by a SymbolLookup so the same
// marshalling serves both interface libraries (see MDServiceFFI).
public class Asn1NIFFI implements Asn1Ni
{

    private static final Logger L = Logger.getLogger("ASN1_NI_FFI");
    private static final Linker linker = Linker.nativeLinker();

    private final MethodHandle allocateFuncHandle;

    private final MethodHandle disposeFuncHandle;

    private final MethodHandle encodePublicKeyFuncHandle;

    private final MethodHandle encodePrivateKeyFuncHandle;

    private final MethodHandle getDataFuncHandle;

    private final MethodHandle fromPrivateKeyInfoFuncHandle;

    private final MethodHandle fromPublicKeyInfoFuncHandle;

    public Asn1NIFFI()
    {
        this(SymbolLookup.loaderLookup());
    }

    public Asn1NIFFI(SymbolLookup lookup)
    {
        MemorySegment allocateFunc = lookup.find("ASN1_allocate").orElseThrow();
        allocateFuncHandle = linker.downcallHandle(allocateFunc,
                FunctionDescriptor.of(
                        ValueLayout.ADDRESS,// Return ptr
                        ValueLayout.ADDRESS // err
                ));

        MemorySegment disposeFunc = lookup.find("ASN1_dispose").orElseThrow();
        disposeFuncHandle = linker.downcallHandle(disposeFunc,
                FunctionDescriptor.ofVoid(
                        ValueLayout.ADDRESS // ptr
                ));

        MemorySegment encodePublicKeyFunc = lookup.find("ASN1_encodePublicKey").orElseThrow();
        encodePublicKeyFuncHandle = linker.downcallHandle(encodePublicKeyFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS
                ), Linker.Option.critical(true));

        MemorySegment encodePrivateKeyFunc = lookup.find("ASN1_encodePrivateKey").orElseThrow();
        encodePrivateKeyFuncHandle = linker.downcallHandle(encodePrivateKeyFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG
                ), Linker.Option.critical(true));

        MemorySegment getDataFunc = lookup.find("ASN1_getData").orElseThrow();
        getDataFuncHandle = linker.downcallHandle(getDataFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG
                ), Linker.Option.critical(true));


        MemorySegment fromPrivateKeyInfoFunc = lookup.find("ASN1_fromPrivateKeyInfo").orElseThrow();
        fromPrivateKeyInfoFuncHandle = linker.downcallHandle(fromPrivateKeyInfoFunc,
                FunctionDescriptor.of(
                        ValueLayout.ADDRESS, // key_spec*
                        ValueLayout.ADDRESS, // input *
                        ValueLayout.JAVA_LONG, // input size
                        ValueLayout.JAVA_INT, // in_off
                        ValueLayout.JAVA_INT, // in_len
                        ValueLayout.ADDRESS // receiver for return code
                ), Linker.Option.critical(true));


        MemorySegment fromPublicKeyInfoFunc = lookup.find("ASN1_fromPublicKeyInfo").orElseThrow();
        fromPublicKeyInfoFuncHandle = linker.downcallHandle(fromPublicKeyInfoFunc,
                FunctionDescriptor.of(
                        ValueLayout.ADDRESS, // key_spec*
                        ValueLayout.ADDRESS, // input *
                        ValueLayout.JAVA_LONG, // input size
                        ValueLayout.JAVA_INT, // in_off
                        ValueLayout.JAVA_INT, // in_len
                        ValueLayout.ADDRESS // receiver for return code
                ), Linker.Option.critical(true));


    }

    @Override
    public long ni_allocate(int[] err)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment errSeg = a.allocate(ValueLayout.JAVA_INT);
            MemorySegment addr = (MemorySegment) allocateFuncHandle.invokeExact(errSeg);
            err[0] = errSeg.getAtIndex(ValueLayout.JAVA_INT, 0);
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
                    "FFI ASN1_dispose",
                    t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_encodePublicKey(long ref, long keyRef)
    {
        try
        {
            return (int) encodePublicKeyFuncHandle.invokeExact(MemorySegment.ofAddress(ref), MemorySegment.ofAddress(keyRef));
        }
        catch (Throwable t)
        {
            L.log(
                    Level.WARNING,
                    "FFI ASN1_encodePublicKey",
                    t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_encodePrivateKey(long ref, long keyRef, String option)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment opt;
            long optSize;
            if (option == null)
            {
                opt = MemorySegment.NULL;
                optSize = 0L;
            }
            else
            {
                opt = a.allocateFrom(option);
                optSize = opt.byteSize();
            }
            return (int) encodePrivateKeyFuncHandle.invokeExact(MemorySegment.ofAddress(ref), MemorySegment.ofAddress(keyRef), opt, optSize);
        }
        catch (Throwable t)
        {
            L.log(
                    Level.WARNING,
                    "FFI ASN1_encodePrivateKey",
                    t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_getData(long ref, byte[] out)
    {
        try
        {
            MemorySegment outSegment = out == null ? MemorySegment.NULL : MemorySegment.ofArray(out);
            return (int) getDataFuncHandle.invokeExact(MemorySegment.ofAddress(ref), outSegment, outSegment.byteSize());
        }
        catch (Throwable t)
        {
            L.log(
                    Level.WARNING,
                    "FFI ASN1_getData",
                    t);
            throw new RuntimeException(t.getMessage(), t);
        }

    }

    @Override
    public long ni_fromPrivateKeyInfo(byte[] data, int start, int len)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment inputSegment = data == null ? MemorySegment.NULL : MemorySegment.ofArray(data);
            MemorySegment errorCodeRcvr = a.allocate(ValueLayout.JAVA_INT);
            MemorySegment ptr = (MemorySegment) fromPrivateKeyInfoFuncHandle.invokeExact(
                    inputSegment,
                    inputSegment.byteSize(),
                    start,
                    len,
                    errorCodeRcvr
            );

            int errorCode = errorCodeRcvr.get(ValueLayout.JAVA_INT, 0);
            if (errorCode < 0)
            {
                return errorCode;
            }

            return ptr.address();

        }
        catch (Throwable t)
        {
            L.log(
                    Level.WARNING,
                    "FFI ASN1_fromPrivateKeyInfo",
                    t);
            throw new RuntimeException(t.getMessage(), t);
        }

    }

    @Override
    public long ni_fromPublicKeyInfo(byte[] data, int start, int len)
    {

        try (Arena a = Arena.ofConfined())
        {
            MemorySegment inputSegment = data == null ? MemorySegment.NULL : MemorySegment.ofArray(data);
            MemorySegment errorCodeRcvr = a.allocate(ValueLayout.JAVA_INT);
            MemorySegment ptr = (MemorySegment) fromPublicKeyInfoFuncHandle.invokeExact(
                    inputSegment,
                    inputSegment.byteSize(),
                    start,
                    len,
                    errorCodeRcvr
            );


            int errorCode = errorCodeRcvr.get(ValueLayout.JAVA_INT, 0);
            if (errorCode < 0)
            {
                return errorCode;
            }

            return ptr.address();

        }
        catch (Throwable t)
        {
            L.log(
                    Level.WARNING,
                    "FFI ASN1_fromPublicKeyInfo",
                    t);
            throw new RuntimeException(t.getMessage(), t);
        }

    }
}
