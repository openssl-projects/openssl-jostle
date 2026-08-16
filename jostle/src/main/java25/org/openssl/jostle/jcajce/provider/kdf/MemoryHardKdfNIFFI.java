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

/**
 * FFI bridge for the memory-hard KDFs (scrypt, Argon2).
 *
 * <p>Separate from {@link KdfNIFFI} because the FIPS FFI class extends that one
 * and inherits its constructor, which resolves every symbol with
 * {@code orElseThrow()}. Binding {@code JoKDF_SCRYPT} / {@code JoKDF_ARGON2}
 * there would make the FIPS KDF NI fail at construction, since the FIPS
 * interface library deliberately exports neither — see {@link MemoryHardKdfNI}.
 * This class is instantiated only against the base library.</p>
 *
 * <p>Marshalled with confined-arena copies rather than
 * {@code Linker.Option.critical} heap segments for the same reason as
 * {@link KdfNIFFI}: both KDFs run for a caller-controlled duration (high cost
 * parameters take seconds by design), which is the worst case for pinning the
 * caller's arrays.</p>
 */
public class MemoryHardKdfNIFFI implements MemoryHardKdfNI
{
    private static final Logger L = Logger.getLogger("MEMHARD_KDF_NI_FFI");
    private static final Linker linker = Linker.nativeLinker();

    private final MethodHandle scryptFuncHandle;
    private final MethodHandle argon2FuncHandle;

    public MemoryHardKdfNIFFI()
    {
        this(SymbolLookup.loaderLookup());
    }

    public MemoryHardKdfNIFFI(SymbolLookup lookup)
    {
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

        MemorySegment argon2 = lookup.find("JoKDF_ARGON2").orElseThrow();
        argon2FuncHandle = linker.downcallHandle(argon2,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT, // return value
                        ValueLayout.JAVA_INT, // type (0=d, 1=i, 2=id)
                        ValueLayout.JAVA_INT, // version (0x10 | 0x13)
                        ValueLayout.ADDRESS, // passwd
                        ValueLayout.JAVA_LONG, // passwd_len
                        ValueLayout.ADDRESS, // salt
                        ValueLayout.JAVA_LONG, // salt_len
                        ValueLayout.JAVA_INT, // iterations
                        ValueLayout.JAVA_INT, // memory cost in KiB
                        ValueLayout.JAVA_INT, // lanes
                        ValueLayout.ADDRESS, // output
                        ValueLayout.JAVA_LONG, // output_size -- total length of output array
                        ValueLayout.JAVA_INT, // output offset
                        ValueLayout.JAVA_INT // output length wanted
                ));
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
            L.log(Level.WARNING, "FFI JoKDF_SCRYPT", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int argon2(byte[] password, byte[] salt, int type, int version, int iterations, int memoryKiB,
                      int lanes, byte[] out, int outOffset, int outLen)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment pwSeg = copyIn(a, password);
            MemorySegment saltSeg = copyIn(a, salt);
            MemorySegment output = outSeg(a, out);

            int ret = (int) argon2FuncHandle.invokeExact(
                    type,
                    version,
                    pwSeg, len(password),
                    saltSeg, len(salt),
                    iterations,
                    memoryKiB,
                    lanes,
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
            L.log(Level.WARNING, "FFI JoKDF_ARGON2", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    /**
     * Copy an input array into the confined arena. A null array marshals to
     * {@code MemorySegment.NULL} so the bridge's null checks fire; a non-null
     * array (even empty) gets a non-NULL segment of at least one byte so the
     * bridge can still distinguish "null array" from "empty array" — a NULL
     * pointer for an empty array would collapse that distinction.
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

    private static void copyOutBack(int ret, MemorySegment output, byte[] out, int outOffset, int outLen)
    {
        if (ret == 0 && out != null && outLen > 0)
        {
            output.asByteBuffer().get(outOffset, out, outOffset, outLen);
        }
    }
}
