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

package org.openssl.jostle.jcajce.provider.kdf;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.util.logging.Level;
import java.util.logging.Logger;

// Symbol resolution is parameterised by a SymbolLookup so the same
// marshalling serves both interface libraries (see MDServiceFFI).
//
// These downcalls are marshalled with confined-arena copies rather than
// Linker.Option.critical heap segments. A critical downcall pins the caller's
// heap arrays (and on some collectors holds the GC lock) for the whole call —
// and PBKDF2 / scrypt run for a caller-controlled duration (high iteration /
// cost parameters take seconds by design), which is the worst case for pinning.
// The copies cost a memcpy per array, negligible next to the derive itself.
public class KdfNIFFI implements KdfNI
{
    //KDF_PBKDF2

    private static final Logger L = Logger.getLogger("KDF_NI_FFI");
    private static final Linker linker = Linker.nativeLinker();

    private final MethodHandle pbkdf2FuncHandle;

    private final MethodHandle scryptFuncHandle;

    private final MethodHandle hkdfFuncHandle;

    public KdfNIFFI()
    {
        this(SymbolLookup.loaderLookup());
    }

    public KdfNIFFI(SymbolLookup lookup)
    {

        MemorySegment pbkdf2 = lookup.find("JoKDF_PBKDF2").orElseThrow();
        pbkdf2FuncHandle = linker.downcallHandle(pbkdf2,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT, // return value
                        ValueLayout.ADDRESS, // passwd
                        ValueLayout.JAVA_LONG, // passwd_len
                        ValueLayout.ADDRESS, // salt
                        ValueLayout.JAVA_LONG, // salt_len
                        ValueLayout.JAVA_INT, // iter
                        ValueLayout.ADDRESS, // digest name as bytes
                        ValueLayout.JAVA_LONG, // length of digest name (excluding null terminus)
                        ValueLayout.ADDRESS, // output
                        ValueLayout.JAVA_LONG, // output_size -- total length of output array
                        ValueLayout.JAVA_INT, // output offset
                        ValueLayout.JAVA_INT // output length wanted
                ));


        MemorySegment scrypt = lookup.find("JoKDF_SCRYPT").orElseThrow();
        scryptFuncHandle = linker.downcallHandle(scrypt,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT, // return value
                        ValueLayout.ADDRESS, // passwd
                        ValueLayout.JAVA_LONG, // passwd_len
                        ValueLayout.ADDRESS, // salt
                        ValueLayout.JAVA_LONG, // salt_len
                        ValueLayout.JAVA_INT, // n
                        ValueLayout.JAVA_INT, // r
                        ValueLayout.JAVA_INT, // p
                        ValueLayout.ADDRESS, // output
                        ValueLayout.JAVA_LONG, // output_size -- total length of output array
                        ValueLayout.JAVA_INT, // output offset
                        ValueLayout.JAVA_INT // output length wanted
                ));


        MemorySegment hkdf = lookup.find("JoKDF_HKDF").orElseThrow();
        hkdfFuncHandle = linker.downcallHandle(hkdf,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT, // return value
                        ValueLayout.ADDRESS, // ikm
                        ValueLayout.JAVA_LONG, // ikm_len
                        ValueLayout.ADDRESS, // salt
                        ValueLayout.JAVA_LONG, // salt_len
                        ValueLayout.ADDRESS, // info
                        ValueLayout.JAVA_LONG, // info_len
                        ValueLayout.ADDRESS, // digest name as bytes
                        ValueLayout.JAVA_LONG, // length of digest name (excluding null terminus)
                        ValueLayout.ADDRESS, // output
                        ValueLayout.JAVA_LONG, // output_size -- total length of output array
                        ValueLayout.JAVA_INT, // output offset
                        ValueLayout.JAVA_INT // output length wanted
                ));


    }

    /**
     * Copy an input array into the confined arena. A null array marshals to
     * {@code MemorySegment.NULL} so the bridge's null checks fire; a non-null
     * array (even empty) gets a non-NULL segment of at least one byte so the
     * bridge can still distinguish "null array" (e.g. {@code JO_KDF_SALT_NULL})
     * from "empty array" ({@code JO_KDF_SALT_EMPTY}) — a NULL pointer for an
     * empty array would collapse that distinction. The caller passes the true
     * Java length separately (see {@link #len(byte[])}).
     */
    private static MemorySegment copyIn(Arena a, byte[] src)
    {
        if (src == null)
        {
            return MemorySegment.NULL;
        }
        MemorySegment seg = a.allocate(src.length == 0 ? 1L : src.length);
        if (src.length > 0)
        {
            MemorySegment.copy(src, 0, seg, ValueLayout.JAVA_BYTE, 0L, src.length);
        }
        return seg;
    }

    /**
     * Zero-filled output segment in the confined arena, at least one byte so a
     * non-null (even zero-length) caller buffer still has a non-NULL address.
     * The written window is copied back to the caller after a successful call.
     */
    private static MemorySegment outSeg(Arena a, byte[] out)
    {
        if (out == null)
        {
            return MemorySegment.NULL;
        }
        return a.allocate(out.length == 0 ? 1L : out.length);
    }

    private static long len(byte[] a)
    {
        return a == null ? 0L : a.length;
    }


    @Override
    public int scrypt(byte[] password, byte[] salt, int n, int r, int p, byte[] out, int outOffset, int outLen)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment pwSeg = copyIn(a, password);
            MemorySegment saltSeg = copyIn(a, salt);
            MemorySegment output = outSeg(a, out);

            int ret = (int) scryptFuncHandle.invokeExact(
                    pwSeg, len(password),
                    saltSeg, len(salt),
                    n,
                    r,
                    p,
                    output,
                    len(out),
                    outOffset,
                    outLen
            );

            copyOutBack(ret, output, out, outOffset, outLen);
            return ret;
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING,
                    "FFI JoKDF_SCRYPT", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int pbkdf2(byte[] password, byte[] salt, int iter, String digest, byte[] out, int outOffset, int outLen)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment pwSeg = copyIn(a, password);
            MemorySegment saltSeg = copyIn(a, salt);
            MemorySegment digestName = (digest == null) ? MemorySegment.NULL : a.allocateFrom(digest);
            MemorySegment output = outSeg(a, out);

            int ret = (int) pbkdf2FuncHandle.invokeExact(
                    pwSeg, len(password),
                    saltSeg, len(salt),
                    iter,
                    digestName,
                    digest == null ? 0L : digestName.byteSize() - 1, // less null terminus
                    output,
                    len(out),
                    outOffset,
                    outLen
            );

            copyOutBack(ret, output, out, outOffset, outLen);
            return ret;
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING,
                    "FFI JoKDF_PBKDF2", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int hkdf(byte[] ikm, byte[] salt, byte[] info, String digest, byte[] out, int outOffset, int outLen)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment ikmSeg = copyIn(a, ikm);
            MemorySegment saltSeg = copyIn(a, salt);
            MemorySegment infoSeg = copyIn(a, info);
            MemorySegment digestName = (digest == null) ? MemorySegment.NULL : a.allocateFrom(digest);
            MemorySegment output = outSeg(a, out);

            int ret = (int) hkdfFuncHandle.invokeExact(
                    ikmSeg, len(ikm),
                    saltSeg, len(salt),
                    infoSeg, len(info),
                    digestName,
                    digest == null ? 0L : digestName.byteSize() - 1, // less null terminus
                    output,
                    len(out),
                    outOffset,
                    outLen
            );

            copyOutBack(ret, output, out, outOffset, outLen);
            return ret;
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING,
                    "FFI JoKDF_HKDF", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    /**
     * Copy the derived bytes back to the caller's array. The KDF bridges return
     * {@code JO_SUCCESS} (0) and write exactly {@code outLen} bytes at
     * {@code outOffset} on success; on any negative (error) return the native
     * side wrote nothing, so nothing is copied — and only the written window is
     * copied, so bytes outside {@code [outOffset, outOffset + outLen)} keep the
     * caller's original contents (the arena segment is zero-filled, not a copy
     * of the caller's array).
     */
    private static void copyOutBack(int ret, MemorySegment output, byte[] out, int outOffset, int outLen)
    {
        if (ret == 0 && out != null && outLen > 0)
        {
            output.asByteBuffer().get(outOffset, out, outOffset, outLen);
        }
    }

}
