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
// and PBKDF2 runs for a caller-controlled duration (a high iteration count
// takes seconds by design), which is the worst case for pinning.
// The copies cost a memcpy per array, negligible next to the derive itself.
public class KdfNIFFI implements KdfNI
{
    //KDF_PBKDF2

    private static final Logger L = Logger.getLogger("KDF_NI_FFI");
    private static final Linker linker = Linker.nativeLinker();

    private final MethodHandle pbkdf2FuncHandle;

    private final MethodHandle hkdfFuncHandle;

    private final MethodHandle kbkdfFuncHandle;

    private final MethodHandle sskdfFuncHandle;

    private final MethodHandle sshkdfFuncHandle;

    public KdfNIFFI()
    {
        this(SymbolLookup.loaderLookup());
    }

    public KdfNIFFI(SymbolLookup lookup)
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
    public KdfNIFFI(SymbolLookup lookup, String symPrefix)
    {

        MemorySegment pbkdf2 = lookup.find(symPrefix + "JoKDF_PBKDF2").orElseThrow();
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




        MemorySegment hkdf = lookup.find(symPrefix + "JoKDF_HKDF").orElseThrow();
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


        MemorySegment kbkdf = lookup.find(symPrefix + "JoKDF_KBKDF").orElseThrow();
        kbkdfFuncHandle = linker.downcallHandle(kbkdf,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT, // return value
                        ValueLayout.ADDRESS, // mode name as bytes
                        ValueLayout.JAVA_LONG, // length of mode name
                        ValueLayout.ADDRESS, // mac name as bytes
                        ValueLayout.JAVA_LONG, // length of mac name
                        ValueLayout.ADDRESS, // digest name as bytes
                        ValueLayout.JAVA_LONG, // length of digest name
                        ValueLayout.ADDRESS, // cipher name as bytes
                        ValueLayout.JAVA_LONG, // length of cipher name
                        ValueLayout.ADDRESS, // key
                        ValueLayout.JAVA_LONG, // key_len
                        ValueLayout.ADDRESS, // label
                        ValueLayout.JAVA_LONG, // label_len
                        ValueLayout.ADDRESS, // context
                        ValueLayout.JAVA_LONG, // context_len
                        ValueLayout.ADDRESS, // seed (feedback IV)
                        ValueLayout.JAVA_LONG, // seed_len
                        ValueLayout.JAVA_INT, // r
                        ValueLayout.JAVA_INT, // use_l
                        ValueLayout.JAVA_INT, // use_separator
                        ValueLayout.ADDRESS, // output
                        ValueLayout.JAVA_LONG, // output_size -- total length of output array
                        ValueLayout.JAVA_INT, // output offset
                        ValueLayout.JAVA_INT // output length wanted
                ));


        MemorySegment sskdf = lookup.find(symPrefix + "JoKDF_SSKDF").orElseThrow();
        sskdfFuncHandle = linker.downcallHandle(sskdf,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT, // return value
                        ValueLayout.ADDRESS, // digest name as bytes
                        ValueLayout.JAVA_LONG, // length of digest name
                        ValueLayout.ADDRESS, // secret
                        ValueLayout.JAVA_LONG, // secret_len
                        ValueLayout.ADDRESS, // info
                        ValueLayout.JAVA_LONG, // info_len
                        ValueLayout.ADDRESS, // output
                        ValueLayout.JAVA_LONG, // output_size -- total length of output array
                        ValueLayout.JAVA_INT, // output offset
                        ValueLayout.JAVA_INT // output length wanted
                ));


        MemorySegment sshkdf = lookup.find(symPrefix + "JoKDF_SSHKDF").orElseThrow();
        sshkdfFuncHandle = linker.downcallHandle(sshkdf,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT, // return value
                        ValueLayout.ADDRESS, // digest name as bytes
                        ValueLayout.JAVA_LONG, // length of digest name
                        ValueLayout.ADDRESS, // key
                        ValueLayout.JAVA_LONG, // key_len
                        ValueLayout.ADDRESS, // xcghash
                        ValueLayout.JAVA_LONG, // xcghash_len
                        ValueLayout.ADDRESS, // session_id
                        ValueLayout.JAVA_LONG, // session_id_len
                        ValueLayout.ADDRESS, // type name as bytes
                        ValueLayout.JAVA_LONG, // length of type name
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
     * Marshal a name into the arena, or {@code MemorySegment.NULL} when absent
     * so the bridge's null checks fire. Paired with {@link #nameLen}, which
     * must be applied to the SAME segment.
     */
    private static MemorySegment nameSeg(Arena a, String name)
    {
        return (name == null) ? MemorySegment.NULL : a.allocateFrom(name);
    }

    /**
     * Byte length of a name segment excluding its NUL terminus, matching what
     * the JNI bridge gets from {@code GetStringUTFLength}.
     */
    private static long nameLen(String name, MemorySegment seg)
    {
        return (name == null) ? 0L : seg.byteSize() - 1;
    }

    @Override
    public int kbkdf(String mode, String mac, String digest, String cipher,
                     byte[] key, byte[] label, byte[] context, byte[] seed,
                     int r, int useL, int useSeparator,
                     byte[] out, int outOffset, int outLen)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment modeName = nameSeg(a, mode);
            MemorySegment macName = nameSeg(a, mac);
            MemorySegment digestName = nameSeg(a, digest);
            MemorySegment cipherName = nameSeg(a, cipher);
            MemorySegment keySeg = copyIn(a, key);
            MemorySegment labelSeg = copyIn(a, label);
            MemorySegment contextSeg = copyIn(a, context);
            MemorySegment seedSeg = copyIn(a, seed);
            MemorySegment output = outSeg(a, out);

            int ret = (int) kbkdfFuncHandle.invokeExact(
                    modeName, nameLen(mode, modeName),
                    macName, nameLen(mac, macName),
                    digestName, nameLen(digest, digestName),
                    cipherName, nameLen(cipher, cipherName),
                    keySeg, len(key),
                    labelSeg, len(label),
                    contextSeg, len(context),
                    seedSeg, len(seed),
                    r, useL, useSeparator,
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
                    "FFI JoKDF_KBKDF", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int sskdf(String digest, byte[] secret, byte[] info, byte[] out, int outOffset, int outLen)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment digestName = nameSeg(a, digest);
            MemorySegment secretSeg = copyIn(a, secret);
            MemorySegment infoSeg = copyIn(a, info);
            MemorySegment output = outSeg(a, out);

            int ret = (int) sskdfFuncHandle.invokeExact(
                    digestName, nameLen(digest, digestName),
                    secretSeg, len(secret),
                    infoSeg, len(info),
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
                    "FFI JoKDF_SSKDF", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int sshkdf(String digest, byte[] key, byte[] xcghash, byte[] sessionId, String type,
                      byte[] out, int outOffset, int outLen)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment digestName = nameSeg(a, digest);
            MemorySegment keySeg = copyIn(a, key);
            MemorySegment xcghashSeg = copyIn(a, xcghash);
            MemorySegment sessionSeg = copyIn(a, sessionId);
            MemorySegment typeName = nameSeg(a, type);
            MemorySegment output = outSeg(a, out);

            int ret = (int) sshkdfFuncHandle.invokeExact(
                    digestName, nameLen(digest, digestName),
                    keySeg, len(key),
                    xcghashSeg, len(xcghash),
                    sessionSeg, len(sessionId),
                    typeName, nameLen(type, typeName),
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
                    "FFI JoKDF_SSHKDF", t);
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
