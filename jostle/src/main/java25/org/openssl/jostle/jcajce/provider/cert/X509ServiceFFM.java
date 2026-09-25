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

/**
 * FFM binding for the {@code JoX509_*} entry points exported by
 * {@code interface/nonfips/ffm/x509_ni_ffm.c}.
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
public class X509ServiceFFM implements X509NI
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

    public X509ServiceFFM()
    {
        this(SymbolLookup.loaderLookup());
    }

    public X509ServiceFFM(SymbolLookup lookup)
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
    public X509ServiceFFM(SymbolLookup lookup, String symPrefix)
    {
        // int32_t JoX509_allocate(const uint8_t*, int32_t der_size, int32_t off,
        //                         int32_t len, int32_t max_bytes, int64_t* out_ref,
        //                         int32_t* out_consumed, int32_t consumed_len,
        //                         int32_t err_len)
        allocateH = linker.downcallHandle(
                lookup.find(symPrefix + "JoX509_allocate").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_INT, ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS, ValueLayout.ADDRESS,
                        ValueLayout.JAVA_INT, ValueLayout.JAVA_INT));

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

        // int32_t JoX509_extensions(int64_t, uint8_t*, int32_t,
        //                           int32_t*, int32_t, int32_t*, int32_t,
        //                           int32_t*, int32_t)
        extensionsH = linker.downcallHandle(
                lookup.find(symPrefix + "JoX509_extensions").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_INT));

        // void JoX509_dispose(int64_t)
        disposeH = linker.downcallHandle(
                lookup.find(symPrefix + "JoX509_dispose").orElseThrow(),
                FunctionDescriptor.ofVoid(ValueLayout.JAVA_LONG));

        // int32_t JoX509_allocateCrl(const uint8_t*, int32_t der_size, int32_t off,
        //                            int32_t len, int32_t max_bytes, int64_t* out_ref,
        //                            int32_t* out_consumed, int32_t consumed_len,
        //                            int32_t err_len)
        allocateCrlH = linker.downcallHandle(
                lookup.find(symPrefix + "JoX509_allocateCrl").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_INT, ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS, ValueLayout.ADDRESS,
                        ValueLayout.JAVA_INT, ValueLayout.JAVA_INT));
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
                        ValueLayout.ADDRESS, ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
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
        try (Arena arena = Arena.ofConfined())
        {
            // The WHOLE array crosses, with its size and the caller's off/len,
            // so C does the null, sign and range checks and both bridges answer
            // the same code. Slicing here would be validation by another name.
            MemorySegment in;
            int size;
            if (der == null)
            {
                in = MemorySegment.NULL;
                size = 0;
            }
            else
            {
                in = arena.allocate(Math.max(der.length, 1));
                MemorySegment.copy(der, 0, in, ValueLayout.JAVA_BYTE, 0, der.length);
                size = der.length;
            }
            MemorySegment ref = arena.allocate(ValueLayout.JAVA_LONG);
            // consumed and err are jostle's own: their null-ness and length
            // travel down and C asserts them, so nothing is checked here.
            MemorySegment used = consumed == null
                    ? MemorySegment.NULL : arena.allocate(ValueLayout.JAVA_INT);
            int rc = (int) allocateCrlH.invokeExact(in, size, off, len, maxBytes, ref, used,
                    consumed == null ? 0 : consumed.length, err == null ? 0 : err.length);
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
        try (Arena arena = Arena.ofConfined())
        {
            // A null output array crosses as MemorySegment.NULL with a zero
            // capacity; C answers JO_OUTPUT_IS_NULL, as the JNI twin does.
            MemorySegment b = blob == null
                    ? MemorySegment.NULL : arena.allocate(Math.max(blob.length, 1));
            MemorySegment s = sizes == null
                    ? MemorySegment.NULL
                    : arena.allocate(ValueLayout.JAVA_INT, Math.max(sizes.length, 1));
            MemorySegment i = info == null
                    ? MemorySegment.NULL
                    : arena.allocate(ValueLayout.JAVA_INT, Math.max(info.length, 1));

            int rc = (int) crlFieldsH.invokeExact(ref, b, blob == null ? 0 : blob.length,
                    s, sizes == null ? 0 : sizes.length,
                    i, info == null ? 0 : info.length);
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
        try (Arena arena = Arena.ofConfined())
        {
            // Each array's own capacity crosses, so C sees a disagreement
            // between the three and answers JO_OUTPUT_TOO_SMALL; a null one
            // crosses as MemorySegment.NULL and answers JO_OUTPUT_IS_NULL.
            MemorySegment b = blob == null
                    ? MemorySegment.NULL : arena.allocate(Math.max(blob.length, 1));
            MemorySegment os = segmentFor(arena, oidSizes);
            MemorySegment vs = segmentFor(arena, valSizes);
            MemorySegment cr = segmentFor(arena, critical);

            int rc = (int) crlExtensionsH.invokeExact(ref, b, blob == null ? 0 : blob.length,
                    os, oidSizes == null ? 0 : oidSizes.length,
                    vs, valSizes == null ? 0 : valSizes.length,
                    cr, critical == null ? 0 : critical.length);
            if (rc == 0)
            {
                int n = oidSizes.length;
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
        try (Arena arena = Arena.ofConfined())
        {
            // dates carries its OWN length, not one derived from sizes, so the
            // pairing check is C's: it answers JO_OUTPUT_TOO_SMALL when
            // dates_len is not twice the entry count.
            MemorySegment b = blob == null
                    ? MemorySegment.NULL : arena.allocate(Math.max(blob.length, 1));
            MemorySegment s = segmentFor(arena, sizes);
            MemorySegment d = segmentFor(arena, dates);

            int rc = (int) crlEntriesH.invokeExact(ref, b, blob == null ? 0 : blob.length,
                    sizes == null ? 0 : sizes.length, s, d,
                    dates == null ? 0 : dates.length);
            if (rc == 0)
            {
                MemorySegment.copy(b, ValueLayout.JAVA_BYTE, 0, blob, 0, blob.length);
                MemorySegment.copy(s, ValueLayout.JAVA_INT, 0, sizes, 0, sizes.length);
                MemorySegment.copy(d, ValueLayout.JAVA_INT, 0, dates, 0, dates.length);
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
        try (Arena arena = Arena.ofConfined())
        {
            // The WHOLE array crosses, with its size and the caller's off/len,
            // so C does the null, sign and range checks and both bridges answer
            // the same code. Slicing here would be validation by another name.
            MemorySegment in;
            int size;
            if (der == null)
            {
                in = MemorySegment.NULL;
                size = 0;
            }
            else
            {
                in = arena.allocate(Math.max(der.length, 1));
                MemorySegment.copy(der, 0, in, ValueLayout.JAVA_BYTE, 0, der.length);
                size = der.length;
            }
            MemorySegment ref = arena.allocate(ValueLayout.JAVA_LONG);
            // consumed and err are jostle's own: their null-ness and length
            // travel down and C asserts them, so nothing is checked here.
            MemorySegment used = consumed == null
                    ? MemorySegment.NULL : arena.allocate(ValueLayout.JAVA_INT);

            int rc = (int) allocateH.invokeExact(in, size, off, len, maxBytes, ref, used,
                    consumed == null ? 0 : consumed.length, err == null ? 0 : err.length);
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
        try (Arena arena = Arena.ofConfined())
        {
            // A null output array crosses as MemorySegment.NULL with a zero
            // capacity; C answers JO_OUTPUT_IS_NULL, as the JNI twin does.
            MemorySegment b = blob == null
                    ? MemorySegment.NULL : arena.allocate(Math.max(blob.length, 1));
            MemorySegment s = sizes == null
                    ? MemorySegment.NULL
                    : arena.allocate(ValueLayout.JAVA_INT, Math.max(sizes.length, 1));
            MemorySegment i = info == null
                    ? MemorySegment.NULL
                    : arena.allocate(ValueLayout.JAVA_INT, Math.max(info.length, 1));

            int rc = (int) fieldsH.invokeExact(ref, b, blob == null ? 0 : blob.length,
                    s, sizes == null ? 0 : sizes.length,
                    i, info == null ? 0 : info.length);
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
        try (Arena arena = Arena.ofConfined())
        {
            // Each array's own capacity crosses, so C sees a disagreement
            // between the three and answers JO_OUTPUT_TOO_SMALL; a null one
            // crosses as MemorySegment.NULL and answers JO_OUTPUT_IS_NULL.
            MemorySegment b = blob == null
                    ? MemorySegment.NULL : arena.allocate(Math.max(blob.length, 1));
            MemorySegment os = segmentFor(arena, oidSizes);
            MemorySegment vs = segmentFor(arena, valSizes);
            MemorySegment cr = segmentFor(arena, critical);

            int rc = (int) extensionsH.invokeExact(ref, b, blob == null ? 0 : blob.length,
                    os, oidSizes == null ? 0 : oidSizes.length,
                    vs, valSizes == null ? 0 : valSizes.length,
                    cr, critical == null ? 0 : critical.length);
            if (rc == 0)
            {
                int n = oidSizes.length;
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

    /**
     * An int output array as a confined-arena segment, or MemorySegment.NULL
     * when the caller passed none. The capacity travels as its own parameter,
     * so C refuses a null or a disagreeing length rather than this bridge.
     */
    private static MemorySegment segmentFor(Arena arena, int[] a)
    {
        return a == null
                ? MemorySegment.NULL
                : arena.allocate(ValueLayout.JAVA_INT, Math.max(a.length, 1));
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
