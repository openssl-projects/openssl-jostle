package org.openssl.jostle.jcajce.provider.kdf;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.util.logging.Level;
import java.util.logging.Logger;

public class KdfNIFFI implements KdfNI
{
    //KDF_PBKDF2

    private static final Logger L = Logger.getLogger("MLDSA_NI_FFI");
    private static final SymbolLookup lookup = SymbolLookup.loaderLookup();
    private static final Linker linker = Linker.nativeLinker();

    private static final MemorySegment pbkdf2;
    private static final MethodHandle pbkdf2FuncHandle;

    private static final MemorySegment scrypt;
    private static final MethodHandle scryptFuncHandle;

    static
    {

        pbkdf2 = lookup.find("KDF_PBKDF2").orElseThrow();
        pbkdf2FuncHandle = linker.downcallHandle(pbkdf2,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT, // return value
                        ValueLayout.ADDRESS, // passwd
                        ValueLayout.JAVA_LONG, // passwd_len
                        ValueLayout.ADDRESS, // salt
                        ValueLayout.JAVA_LONG, // salt_len
                        ValueLayout.JAVA_INT, // iter
                        ValueLayout.ADDRESS, // digest name as bytes
                        ValueLayout.JAVA_LONG, // length of digest name + null terminus
                        ValueLayout.ADDRESS, // output
                        ValueLayout.JAVA_LONG, // output_size -- total length of output array
                        ValueLayout.JAVA_INT, // output offset
                        ValueLayout.JAVA_INT // output length wanted
                ), Linker.Option.critical(true));


        scrypt = lookup.find("KDF_SCRYPT").orElseThrow();
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

        } catch (Throwable t)
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

        } catch (Throwable t)
        {
            L.log(Level.WARNING,
                    "FFI KDF_PBKDF2", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int pkcs12(byte[] password, byte[] salt, int iter, String digest, byte[] out, int outOffset, int outLen)
    {
        return 0;
    }
}
