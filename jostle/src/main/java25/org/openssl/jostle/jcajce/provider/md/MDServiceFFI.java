package org.openssl.jostle.jcajce.provider.md;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.util.logging.Level;
import java.util.logging.Logger;

public class MDServiceFFI implements MDServiceNI
{

    private static final Logger L = Logger.getLogger("MD_NI_FFI");
    private static final SymbolLookup lookup = SymbolLookup.loaderLookup();
    private static final Linker linker = Linker.nativeLinker();

    private static final MemorySegment allocateDigestFunc;
    private static final MethodHandle allocateDigestFuncHandle;

    private static final MemorySegment updateByteFunc;
    private static final MethodHandle updateByteFuncHandle;

    private static final MemorySegment updateBytesFunc;
    private static final MethodHandle updateBytesFuncHandle;

    private static final MemorySegment disposeFunc;
    private static final MethodHandle disposeFuncHandle;

    private static final MemorySegment digestLenFunc;
    private static final MethodHandle digestLenFuncHandle;

    private static final MemorySegment digestBytesFunc;
    private static final MethodHandle digestBytesFuncHandle;

    private static final MemorySegment resetFunc;
    private static final MethodHandle resetFuncHandle;


    static
    {
        allocateDigestFunc = lookup.find("MD_Allocate").orElseThrow();
        allocateDigestFuncHandle = linker.downcallHandle(allocateDigestFunc,
                FunctionDescriptor.of(
                        ValueLayout.ADDRESS, // *md_dtx
                        ValueLayout.ADDRESS, // const char *name
                        ValueLayout.JAVA_INT,// xof_len
                        ValueLayout.ADDRESS // int *err
                ), Linker.Option.critical(true)
        );

        updateByteFunc = lookup.find("MB_UpdateByte").orElseThrow();
        updateByteFuncHandle = linker.downcallHandle(updateByteFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT, // return value
                        ValueLayout.ADDRESS, // *md_dtx
                        ValueLayout.JAVA_BYTE // data
                ), Linker.Option.critical(true)
        );


        updateBytesFunc = lookup.find("MB_UpdateBytes").orElseThrow();
        updateBytesFuncHandle = linker.downcallHandle(updateBytesFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT, // return value
                        ValueLayout.ADDRESS, // md_ctx *
                        ValueLayout.ADDRESS, // uint8_t *input
                        ValueLayout.JAVA_LONG, //size_t input_size
                        ValueLayout.JAVA_INT,// in_off
                        ValueLayout.JAVA_INT // in_len
                ), Linker.Option.critical(true)
        );

        disposeFunc = lookup.find("MD_Dispose").orElseThrow();
        disposeFuncHandle = linker.downcallHandle(disposeFunc,
                FunctionDescriptor.ofVoid(
                        ValueLayout.ADDRESS // md_ctx *
                ), Linker.Option.critical(true)
        );

        digestLenFunc = lookup.find("MD_GetDigestLen").orElseThrow();
        digestLenFuncHandle = linker.downcallHandle(digestLenFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS // md_ctx *
                )
        );

        digestBytesFunc = lookup.find("MB_Digest").orElseThrow();
        digestBytesFuncHandle = linker.downcallHandle(digestBytesFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT, // return value
                        ValueLayout.ADDRESS, // md_ctx *
                        ValueLayout.ADDRESS, // uint8_t *output
                        ValueLayout.JAVA_LONG, // size_t output_size
                        ValueLayout.JAVA_INT, // out_off
                        ValueLayout.JAVA_INT // out_len
                ),Linker.Option.critical(true));

        resetFunc = lookup.find("MD_Reset").orElseThrow();
        resetFuncHandle = linker.downcallHandle(resetFunc,
                FunctionDescriptor.ofVoid(
                        ValueLayout.ADDRESS // md_ctx *
                )
        );
    }

    @Override
    public long ni_allocateDigest(String name, int xofLen, int[] err)
    {
        try (var a = Arena.ofConfined())
        {
            var nameSeg =  name == null?MemorySegment.NULL: a.allocateFrom(name);
            var errSeg = MemorySegment.ofArray(err);
            var ctxSeg = (MemorySegment) allocateDigestFuncHandle.invokeExact(nameSeg, xofLen, errSeg);
            return ctxSeg.address();
        } catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI MD_Allocate", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_updateByte(long ref, byte b)
    {
        try
        {
            return (int) updateByteFuncHandle.invokeExact(
                    MemorySegment.ofAddress(ref),
                    b);
        } catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI MB_UpdateByte", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_updateBytes(long ref, byte[] input, int offset, int len)
    {
        try
        {
            var inSeg = input == null ?
                    MemorySegment.NULL :
                    MemorySegment.ofArray(input);
            return (int) updateBytesFuncHandle.invokeExact(
                    MemorySegment.ofAddress(ref),
                    inSeg,
                    inSeg.byteSize(),
                    offset,
                    len);
        } catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI MB_UpdateBytes", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public void ni_dispose(long reference)
    {
        try
        {
            disposeFuncHandle.invokeExact(MemorySegment.ofAddress(reference));
        } catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI MD_Dispose", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_getDigestOutputLen(long reference)
    {
        try
        {
            return (int) digestLenFuncHandle.invokeExact(MemorySegment.ofAddress(reference));
        } catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI MD_GetDigestLen", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_digest(long ref, byte[] out, int offset, int length)
    {
        try
        {
            var outSeg = out == null ?
                    MemorySegment.NULL :
                    MemorySegment.ofArray(out);

            return (int) digestBytesFuncHandle.invokeExact(
                    MemorySegment.ofAddress(ref),
                    outSeg,
                    outSeg.byteSize(),
                    offset, length
            );
        } catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI MB_Digest", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public void ni_reset(long ref)
    {
        try
        {
            resetFuncHandle.invokeExact(MemorySegment.ofAddress(ref));
        } catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI MD_Reset", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }
}
