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

package org.openssl.jostle.jcajce.provider.cert;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;

import org.openssl.jostle.jcajce.provider.ErrorCode;

/**
 * FFI binding for the {@code JoX509_*} entry points exported by
 * {@code interface/nonfips/ffi/x509_ni_ffi.c}.
 *
 * <p>No RandSource crosses here, so no upcall can occur and these calls would
 * be eligible for {@code Linker.Option.critical}. It is not used: every entry
 * point writes output arrays, and confined-arena copies keep the marshalling
 * the same shape as every other bridge with out-parameters.
 *
 * <p>Array capacities that JNI discovers with {@code GetArrayLength} are
 * PARAMETERS here, and are passed from the Java array lengths so the two
 * bridges range-check the same thing independently.
 */
public class X509ServiceFFI implements X509NI
{
    private static final Linker linker = Linker.nativeLinker();

    private final MethodHandle allocateH;
    private final MethodHandle fieldsLenH;
    private final MethodHandle fieldsH;
    private final MethodHandle extensionsLenH;
    private final MethodHandle extensionsH;
    private final MethodHandle disposeH;
    private final MethodHandle allocateCrlH;
    private final MethodHandle crlFieldsLenH;
    private final MethodHandle crlFieldsH;
    private final MethodHandle crlExtensionsLenH;
    private final MethodHandle crlExtensionsH;
    private final MethodHandle crlEntriesLenH;
    private final MethodHandle crlEntriesH;
    private final MethodHandle disposeCrlH;

    public X509ServiceFFI()
    {
        this(SymbolLookup.loaderLookup());
    }

    public X509ServiceFFI(SymbolLookup lookup)
    {
        this(lookup, "");
    }

    /**
     * @param symPrefix prepended to every symbol name; empty for the base
     *                  library. Deliberately a SEPARATE parameter from
     *                  {@code lookup}, per {@code FIPSLibraryLookup} — two
     *                  independent values mean either mistake alone is loud,
     *                  where a name-rewriting lookup would restore the single
     *                  point of failure it exists to remove.
     */
    public X509ServiceFFI(SymbolLookup lookup, String symPrefix)
    {
        // int32_t JoX509_allocate(const uint8_t*, int32_t, int32_t, int64_t*, int32_t*)
        allocateH = linker.downcallHandle(
                lookup.find(symPrefix + "JoX509_allocate").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS, ValueLayout.ADDRESS));

        // int32_t JoX509_fieldsLen(int64_t)
        fieldsLenH = linker.downcallHandle(
                lookup.find(symPrefix + "JoX509_fieldsLen").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG));

        // int32_t JoX509_fields(int64_t, uint8_t*, int32_t, int32_t*, int32_t, int32_t*, int32_t)
        fieldsH = linker.downcallHandle(
                lookup.find(symPrefix + "JoX509_fields").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_INT));

        // int32_t JoX509_extensionsLen(int64_t)
        extensionsLenH = linker.downcallHandle(
                lookup.find(symPrefix + "JoX509_extensionsLen").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG));

        // int32_t JoX509_extensions(int64_t, uint8_t*, int32_t, int32_t,
        //                           int32_t*, int32_t*, int32_t*)
        extensionsH = linker.downcallHandle(
                lookup.find(symPrefix + "JoX509_extensions").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));

        // void JoX509_dispose(int64_t)
        disposeH = linker.downcallHandle(
                lookup.find(symPrefix + "JoX509_dispose").orElseThrow(),
                FunctionDescriptor.ofVoid(ValueLayout.JAVA_LONG));

        allocateCrlH = linker.downcallHandle(
                lookup.find(symPrefix + "JoX509_allocateCrl").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        crlFieldsLenH = linker.downcallHandle(
                lookup.find(symPrefix + "JoX509_crlFieldsLen").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG));
        crlFieldsH = linker.downcallHandle(
                lookup.find(symPrefix + "JoX509_crlFields").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
        crlExtensionsLenH = linker.downcallHandle(
                lookup.find(symPrefix + "JoX509_crlExtensionsLen").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG));
        crlExtensionsH = linker.downcallHandle(
                lookup.find(symPrefix + "JoX509_crlExtensions").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        crlEntriesLenH = linker.downcallHandle(
                lookup.find(symPrefix + "JoX509_crlEntriesLen").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG));
        crlEntriesH = linker.downcallHandle(
                lookup.find(symPrefix + "JoX509_crlEntries").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
        disposeCrlH = linker.downcallHandle(
                lookup.find(symPrefix + "JoX509_disposeCrl").orElseThrow(),
                FunctionDescriptor.ofVoid(ValueLayout.JAVA_LONG));
    }

    @Override
    public long ni_allocateCrl(byte[] der, int off, int len, int maxBytes, int[] consumed, int[] err)
    {
        if (err == null || err.length < 1 || consumed == null || consumed.length < 1)
        {
            throw new IllegalArgumentException("output arrays are jostle's own and must be present");
        }
        if (der == null)
        {
            err[0] = ErrorCode.JO_INPUT_IS_NULL.getCode();
            return 0;
        }
        if (off < 0 || len < 0)
        {
            err[0] = ErrorCode.JO_INPUT_LEN_IS_NEGATIVE.getCode();
            return 0;
        }
        if (off > der.length || len > der.length - off)
        {
            err[0] = ErrorCode.JO_INPUT_OUT_OF_RANGE.getCode();
            return 0;
        }
        try (Arena arena = Arena.ofConfined())
        {
            MemorySegment in = arena.allocate(Math.max(len, 1));
            MemorySegment.copy(der, off, in, ValueLayout.JAVA_BYTE, 0, len);
            MemorySegment ref = arena.allocate(ValueLayout.JAVA_LONG);
            MemorySegment used = arena.allocate(ValueLayout.JAVA_INT);
            int rc = (int) allocateCrlH.invokeExact(in, len, maxBytes, ref, used);
            err[0] = rc;
            if (rc != 0)
            {
                return 0;
            }
            consumed[0] = used.get(ValueLayout.JAVA_INT, 0);
            return ref.get(ValueLayout.JAVA_LONG, 0);
        }
        catch (Throwable t)
        {
            throw new RuntimeException(t);
        }
    }

    @Override
    public int ni_crlFieldsLen(long ref)
    {
        try
        {
            return (int) crlFieldsLenH.invokeExact(ref);
        }
        catch (Throwable t)
        {
            throw new RuntimeException(t);
        }
    }

    @Override
    public int ni_crlFields(long ref, byte[] blob, int[] sizes, int[] info)
    {
        if (blob == null || sizes == null || info == null)
        {
            return ErrorCode.JO_OUTPUT_IS_NULL.getCode();
        }
        try (Arena arena = Arena.ofConfined())
        {
            MemorySegment b = arena.allocate(Math.max(blob.length, 1));
            MemorySegment s = arena.allocate(ValueLayout.JAVA_INT, Math.max(sizes.length, 1));
            MemorySegment i = arena.allocate(ValueLayout.JAVA_INT, Math.max(info.length, 1));
            int rc = (int) crlFieldsH.invokeExact(ref, b, blob.length, s, sizes.length, i, info.length);
            if (rc == 0)
            {
                MemorySegment.copy(b, ValueLayout.JAVA_BYTE, 0, blob, 0, blob.length);
                MemorySegment.copy(s, ValueLayout.JAVA_INT, 0, sizes, 0, sizes.length);
                MemorySegment.copy(i, ValueLayout.JAVA_INT, 0, info, 0, info.length);
            }
            return rc;
        }
        catch (Throwable t)
        {
            throw new RuntimeException(t);
        }
    }

    @Override
    public int ni_crlExtensionsLen(long ref)
    {
        try
        {
            return (int) crlExtensionsLenH.invokeExact(ref);
        }
        catch (Throwable t)
        {
            throw new RuntimeException(t);
        }
    }

    @Override
    public int ni_crlExtensions(long ref, byte[] blob, int[] oidSizes, int[] valSizes, int[] critical)
    {
        if (blob == null || oidSizes == null || valSizes == null || critical == null)
        {
            return ErrorCode.JO_OUTPUT_IS_NULL.getCode();
        }
        if (oidSizes.length != valSizes.length || valSizes.length != critical.length)
        {
            return ErrorCode.JO_OUTPUT_TOO_SMALL.getCode();
        }
        try (Arena arena = Arena.ofConfined())
        {
            int n = oidSizes.length;
            MemorySegment b = arena.allocate(Math.max(blob.length, 1));
            MemorySegment os = arena.allocate(ValueLayout.JAVA_INT, Math.max(n, 1));
            MemorySegment vs = arena.allocate(ValueLayout.JAVA_INT, Math.max(n, 1));
            MemorySegment cr = arena.allocate(ValueLayout.JAVA_INT, Math.max(n, 1));
            int rc = (int) crlExtensionsH.invokeExact(ref, b, blob.length, n, os, vs, cr);
            if (rc == 0)
            {
                MemorySegment.copy(b, ValueLayout.JAVA_BYTE, 0, blob, 0, blob.length);
                MemorySegment.copy(os, ValueLayout.JAVA_INT, 0, oidSizes, 0, n);
                MemorySegment.copy(vs, ValueLayout.JAVA_INT, 0, valSizes, 0, n);
                MemorySegment.copy(cr, ValueLayout.JAVA_INT, 0, critical, 0, n);
            }
            return rc;
        }
        catch (Throwable t)
        {
            throw new RuntimeException(t);
        }
    }

    @Override
    public int ni_crlEntriesLen(long ref)
    {
        try
        {
            return (int) crlEntriesLenH.invokeExact(ref);
        }
        catch (Throwable t)
        {
            throw new RuntimeException(t);
        }
    }

    @Override
    public int ni_crlEntries(long ref, byte[] blob, int[] sizes, int[] dates)
    {
        if (blob == null || sizes == null || dates == null)
        {
            return ErrorCode.JO_OUTPUT_IS_NULL.getCode();
        }
        if (dates.length != 2 * sizes.length)
        {
            return ErrorCode.JO_OUTPUT_TOO_SMALL.getCode();
        }
        try (Arena arena = Arena.ofConfined())
        {
            int n = sizes.length;
            MemorySegment b = arena.allocate(Math.max(blob.length, 1));
            MemorySegment s = arena.allocate(ValueLayout.JAVA_INT, Math.max(n, 1));
            MemorySegment d = arena.allocate(ValueLayout.JAVA_INT, Math.max(2 * n, 1));
            int rc = (int) crlEntriesH.invokeExact(ref, b, blob.length, n, s, d, 2 * n);
            if (rc == 0)
            {
                MemorySegment.copy(b, ValueLayout.JAVA_BYTE, 0, blob, 0, blob.length);
                MemorySegment.copy(s, ValueLayout.JAVA_INT, 0, sizes, 0, n);
                MemorySegment.copy(d, ValueLayout.JAVA_INT, 0, dates, 0, 2 * n);
            }
            return rc;
        }
        catch (Throwable t)
        {
            throw new RuntimeException(t);
        }
    }

    @Override
    public void ni_disposeCrl(long ref)
    {
        try
        {
            disposeCrlH.invokeExact(ref);
        }
        catch (Throwable t)
        {
            throw new RuntimeException(t);
        }
    }

    @Override
    public long ni_allocate(byte[] der, int off, int len, int maxBytes, int[] consumed, int[] err)
    {
        if (err == null || err.length < 1 || consumed == null || consumed.length < 1)
        {
            // jostle's own plumbing, never caller data; the JNI twin asserts.
            throw new IllegalArgumentException("output arrays are jostle's own and must be present");
        }
        if (der == null)
        {
            err[0] = ErrorCode.JO_INPUT_IS_NULL.getCode();
            return 0;
        }
        // Split to match the JNI twin code for code, not merely "a typed
        // refusal": there a negative off or len is JO_INPUT_LEN_IS_NEGATIVE and
        // only a bad off+len against the array is JO_INPUT_OUT_OF_RANGE. One
        // combined check here returned the second code for both, so the same
        // input produced different codes on the two legs and a limit test would
        // have had to pin two messages for one contract.
        if (off < 0 || len < 0)
        {
            err[0] = ErrorCode.JO_INPUT_LEN_IS_NEGATIVE.getCode();
            return 0;
        }
        if (off > der.length || len > der.length - off)
        {
            err[0] = ErrorCode.JO_INPUT_OUT_OF_RANGE.getCode();
            return 0;
        }
        try (Arena arena = Arena.ofConfined())
        {
            MemorySegment in = arena.allocate(Math.max(len, 1));
            MemorySegment.copy(der, off, in, ValueLayout.JAVA_BYTE, 0, len);
            MemorySegment ref = arena.allocate(ValueLayout.JAVA_LONG);
            MemorySegment used = arena.allocate(ValueLayout.JAVA_INT);

            int rc = (int) allocateH.invokeExact(in, len, maxBytes, ref, used);
            err[0] = rc;
            if (rc != 0)
            {
                return 0;
            }
            consumed[0] = used.get(ValueLayout.JAVA_INT, 0);
            return ref.get(ValueLayout.JAVA_LONG, 0);
        }
        catch (Throwable t)
        {
            throw new RuntimeException(t);
        }
    }

    @Override
    public int ni_fieldsLen(long ref)
    {
        try
        {
            return (int) fieldsLenH.invokeExact(ref);
        }
        catch (Throwable t)
        {
            throw new RuntimeException(t);
        }
    }

    @Override
    public int ni_fields(long ref, byte[] blob, int[] sizes, int[] info)
    {
        if (blob == null || sizes == null || info == null)
        {
            return ErrorCode.JO_OUTPUT_IS_NULL.getCode();
        }
        try (Arena arena = Arena.ofConfined())
        {
            MemorySegment b = arena.allocate(Math.max(blob.length, 1));
            MemorySegment s = arena.allocate(ValueLayout.JAVA_INT, Math.max(sizes.length, 1));
            MemorySegment i = arena.allocate(ValueLayout.JAVA_INT, Math.max(info.length, 1));

            int rc = (int) fieldsH.invokeExact(ref, b, blob.length, s, sizes.length, i, info.length);
            if (rc == 0)
            {
                MemorySegment.copy(b, ValueLayout.JAVA_BYTE, 0, blob, 0, blob.length);
                MemorySegment.copy(s, ValueLayout.JAVA_INT, 0, sizes, 0, sizes.length);
                MemorySegment.copy(i, ValueLayout.JAVA_INT, 0, info, 0, info.length);
            }
            return rc;
        }
        catch (Throwable t)
        {
            throw new RuntimeException(t);
        }
    }

    @Override
    public int ni_extensionsLen(long ref)
    {
        try
        {
            return (int) extensionsLenH.invokeExact(ref);
        }
        catch (Throwable t)
        {
            throw new RuntimeException(t);
        }
    }

    @Override
    public int ni_extensions(long ref, byte[] blob, int[] oidSizes, int[] valSizes, int[] critical)
    {
        if (blob == null || oidSizes == null || valSizes == null || critical == null)
        {
            return ErrorCode.JO_OUTPUT_IS_NULL.getCode();
        }
        if (oidSizes.length != valSizes.length || valSizes.length != critical.length)
        {
            return ErrorCode.JO_OUTPUT_TOO_SMALL.getCode();
        }
        try (Arena arena = Arena.ofConfined())
        {
            int n = oidSizes.length;
            MemorySegment b = arena.allocate(Math.max(blob.length, 1));
            MemorySegment os = arena.allocate(ValueLayout.JAVA_INT, Math.max(n, 1));
            MemorySegment vs = arena.allocate(ValueLayout.JAVA_INT, Math.max(n, 1));
            MemorySegment cr = arena.allocate(ValueLayout.JAVA_INT, Math.max(n, 1));

            int rc = (int) extensionsH.invokeExact(ref, b, blob.length, n, os, vs, cr);
            if (rc == 0)
            {
                MemorySegment.copy(b, ValueLayout.JAVA_BYTE, 0, blob, 0, blob.length);
                MemorySegment.copy(os, ValueLayout.JAVA_INT, 0, oidSizes, 0, n);
                MemorySegment.copy(vs, ValueLayout.JAVA_INT, 0, valSizes, 0, n);
                MemorySegment.copy(cr, ValueLayout.JAVA_INT, 0, critical, 0, n);
            }
            return rc;
        }
        catch (Throwable t)
        {
            throw new RuntimeException(t);
        }
    }

    @Override
    public void ni_dispose(long ref)
    {
        try
        {
            disposeH.invokeExact(ref);
        }
        catch (Throwable t)
        {
            throw new RuntimeException(t);
        }
    }

}
