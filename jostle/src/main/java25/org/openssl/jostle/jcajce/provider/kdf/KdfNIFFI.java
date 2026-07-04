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

        MemorySegment pbkdf2 = lookup.find("KDF_PBKDF2").orElseThrow();
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
                ), Linker.Option.critical(true));


        MemorySegment scrypt = lookup.find("KDF_SCRYPT").orElseThrow();
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
                ), Linker.Option.critical(true));


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
                ), Linker.Option.critical(true));


    }


    @Override
    public int scrypt(byte[] password, byte[] salt, int n, int r, int p, byte[] out, int outOffset, int outLen)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment pwSeg = (password == null) ? MemorySegment.NULL : MemorySegment.ofArray(password);
            MemorySegment pwSalt = (salt == null) ? MemorySegment.NULL : MemorySegment.ofArray(salt);

            MemorySegment output = (out == null) ? MemorySegment.NULL : MemorySegment.ofArray(out);

            return (int) scryptFuncHandle.invokeExact(
                    pwSeg, pwSeg.byteSize(),
                    pwSalt, pwSalt.byteSize(),
                    n,
                    r,
                    p,
                    output,
                    output.byteSize(),
                    outOffset,
                    outLen
            );

        }
        catch (Throwable t)
        {
            L.log(Level.WARNING,
                    "FFI KDF_SCRYPT", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int pbkdf2(byte[] password, byte[] salt, int iter, String digest, byte[] out, int outOffset, int outLen)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment pwSeg = (password == null) ? MemorySegment.NULL : MemorySegment.ofArray(password);
            MemorySegment pwSalt = (salt == null) ? MemorySegment.NULL : MemorySegment.ofArray(salt);
            MemorySegment digestName = (digest == null) ? MemorySegment.NULL : a.allocateFrom(digest);
            MemorySegment output = (out == null) ? MemorySegment.NULL : MemorySegment.ofArray(out);

            return (int) pbkdf2FuncHandle.invokeExact(
                    pwSeg, pwSeg.byteSize(),
                    pwSalt, pwSalt.byteSize(),
                    iter,
                    digestName,
                    digest == null ? 0 : digestName.byteSize() - 1, // less null terminus
                    output,
                    output.byteSize(),
                    outOffset,
                    outLen
            );

        }
        catch (Throwable t)
        {
            L.log(Level.WARNING,
                    "FFI KDF_PBKDF2", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int hkdf(byte[] ikm, byte[] salt, byte[] info, String digest, byte[] out, int outOffset, int outLen)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment ikmSeg = (ikm == null) ? MemorySegment.NULL : MemorySegment.ofArray(ikm);
            MemorySegment saltSeg = (salt == null) ? MemorySegment.NULL : MemorySegment.ofArray(salt);
            MemorySegment infoSeg = (info == null) ? MemorySegment.NULL : MemorySegment.ofArray(info);
            MemorySegment digestName = (digest == null) ? MemorySegment.NULL : a.allocateFrom(digest);
            MemorySegment output = (out == null) ? MemorySegment.NULL : MemorySegment.ofArray(out);

            return (int) hkdfFuncHandle.invokeExact(
                    ikmSeg, ikmSeg.byteSize(),
                    saltSeg, saltSeg.byteSize(),
                    infoSeg, infoSeg.byteSize(),
                    digestName,
                    digest == null ? 0L : digestName.byteSize() - 1, // less null terminus
                    output,
                    output.byteSize(),
                    outOffset,
                    outLen
            );

        }
        catch (Throwable t)
        {
            L.log(Level.WARNING,
                    "FFI KDF_HKDF", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

}
