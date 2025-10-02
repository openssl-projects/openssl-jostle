package org.openssl.jostle.jcajce.provider;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * FFI Version
 */
public class BlockCipherFFI implements BlockCipherNI
{
    private static final Logger L = Logger.getLogger("BlockCipherNI_FFI");
    private static final SymbolLookup lookup = SymbolLookup.loaderLookup();
    private static final Linker linker = Linker.nativeLinker();

    private static final MemorySegment makeInstanceFunc;
    private static final MethodHandle makeInstanceFuncHandle;

    private static final MemorySegment initFunc;
    private static final MethodHandle initFuncHandle;

    private static final MemorySegment getBlockSizeFunc;
    private static final MethodHandle getBlockSizeFuncHandle;

    private static final MemorySegment updateAADFunc;
    private static final MethodHandle updateAADFuncHandle;

    private static final MemorySegment updateFunc;
    private static final MethodHandle updateFuncHandle;

    private static final MemorySegment finalFunc;
    private static final MethodHandle finalFuncHandle;

    private static final MemorySegment finalSizeFunc;
    private static final MethodHandle finalSizeFuncHandle;


    private static final MemorySegment updateSizeFunc;
    private static final MethodHandle updateSizeFuncHandle;


    private static final MemorySegment disposeFunc;
    private static final MethodHandle disposeFuncHandle;

    static
    {
        makeInstanceFunc = lookup.find("BlockCipherNI_make_instance").orElseThrow();
        makeInstanceFuncHandle = linker.downcallHandle(makeInstanceFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_LONG, // Return ptr
                        ValueLayout.JAVA_INT, // cipher id
                        ValueLayout.JAVA_INT, // mode id
                        ValueLayout.JAVA_INT // padding
                ));

        initFunc = lookup.find("BlockCipherNI_init").orElseThrow();
        initFuncHandle = linker.downcallHandle(initFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT, // Return code
                        ValueLayout.JAVA_LONG, // Ref
                        ValueLayout.JAVA_INT, // Opp Mode
                        ValueLayout.ADDRESS, // ptr to key
                        ValueLayout.JAVA_LONG, // key size
                        ValueLayout.ADDRESS, // ptr to IV
                        ValueLayout.JAVA_LONG, // iv size
                        ValueLayout.JAVA_INT
                ), Linker.Option.critical(true));


        getBlockSizeFunc = lookup.find("BlockCipherNI_getBlockSize").orElseThrow();
        getBlockSizeFuncHandle = linker.downcallHandle(getBlockSizeFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_LONG
                ));


        updateFunc = lookup.find("BlockCipherNI_update").orElseThrow();
        updateFuncHandle = linker.downcallHandle(updateFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT, // Return code
                        ValueLayout.JAVA_LONG, // Reference
                        ValueLayout.ADDRESS, // output array
                        ValueLayout.JAVA_LONG, // output_size
                        ValueLayout.JAVA_INT, // out_off
                        ValueLayout.ADDRESS, // input array
                        ValueLayout.JAVA_LONG, // input_size
                        ValueLayout.JAVA_INT, // in_off
                        ValueLayout.JAVA_INT // in_len
                ), Linker.Option.critical(true));

        updateAADFunc = lookup.find("BlockCipherNI_updateAAD").orElseThrow();
        updateAADFuncHandle = linker.downcallHandle(updateAADFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT, // Return code
                        ValueLayout.JAVA_LONG, // Reference
                        ValueLayout.ADDRESS, // input array
                        ValueLayout.JAVA_LONG, // input_size
                        ValueLayout.JAVA_INT, // in_off
                        ValueLayout.JAVA_INT // in_len
                ), Linker.Option.critical(true));

        finalFunc = lookup.find("BlockCipherNI_doFinal").orElseThrow();
        finalFuncHandle = linker.downcallHandle(finalFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT, // Return code
                        ValueLayout.JAVA_LONG, // Reference
                        ValueLayout.ADDRESS, // output array
                        ValueLayout.JAVA_LONG, // output_size
                        ValueLayout.JAVA_INT // out_off
                ), Linker.Option.critical(true));

        finalSizeFunc = lookup.find("BlockCipherNI_getFinalSize").orElseThrow();
        finalSizeFuncHandle = linker.downcallHandle(finalSizeFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.JAVA_INT
                ));


        updateSizeFunc = lookup.find("BlockCipherNI_getUpdateSize").orElseThrow();
        updateSizeFuncHandle = linker.downcallHandle(updateSizeFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.JAVA_INT
                ));


        disposeFunc = lookup.find("BlockCipherNI_dispose").orElseThrow();
        disposeFuncHandle = linker.downcallHandle(disposeFunc,
                FunctionDescriptor.ofVoid(ValueLayout.JAVA_LONG));

    }


    @Override
    public long makeInstance(int cipher, int mode, int padding)
    {
        long ref = 0;
        try
        {
            ref = (long) makeInstanceFuncHandle.invokeExact(cipher, mode, padding);
        } catch (Throwable e)
        {
            L.log(
                    Level.WARNING,
                    "FFI BlockCipherNI.makeInstance %s, %s".formatted(
                            OSSLCipher.values()[cipher].toString(),
                            OSSLMode.values()[mode].toString()),
                    e);
            throw new RuntimeException(e.getMessage(), e);
        }
        return ref;
    }

    @Override
    public int init(long ref, int oppmode, byte[] keyBytes, byte[] iv, int tag_len)
    {
        int code = 0;
        try
        {
            var keySegment = keyBytes != null ? MemorySegment.ofArray(keyBytes) : MemorySegment.NULL;
            var ivSegment = iv != null ? MemorySegment.ofArray(iv) : MemorySegment.NULL;

            code = (int) initFuncHandle.invokeExact(
                    ref,
                    oppmode,
                    keySegment,
                    keySegment.byteSize(),
                    ivSegment,
                    ivSegment.byteSize(),
                    tag_len);
        } catch (Throwable t)
        {
            L.log(
                    Level.WARNING,
                    "FFI BlockCipherNI_init",
                    t);
            throw new RuntimeException(t.getMessage(), t);
        }
        return code;
    }

    @Override
    public int getBlockSize(long ref)
    {
        int code = 0;
        try
        {
            code = (int) getBlockSizeFuncHandle.invokeExact(ref);
        } catch (Throwable t)
        {
            L.log(
                    Level.WARNING,
                    "FFI BlockCipherNI_getBlockSize",
                    t);
            throw new RuntimeException(t.getMessage(), t);
        }
        return code;
    }

    @Override
    public int update(long ref, byte[] output, int outputOffset, byte[] input, int inputOffset, int inputLen)
    {
        int code = 0;
        try
        {
            var outputSegment = output == null ? MemorySegment.NULL : MemorySegment.ofArray(output);
            var inputSegment = input == null ? MemorySegment.NULL : MemorySegment.ofArray(input);

            code = (int) updateFuncHandle.invokeExact(
                    ref,
                    outputSegment,
                    outputSegment.byteSize(),
                    outputOffset,
                    inputSegment,
                    inputSegment.byteSize(),
                    inputOffset,
                    inputLen);
        } catch (Throwable t)
        {
            L.log(
                    Level.WARNING,
                    "FFI BlockCipherNI_update",
                    t);
            throw new RuntimeException(t.getMessage(), t);
        }
        return code;
    }

    @Override
    public int updateAAD(long ref, byte[] input, int inputOffset, int inputLen)
    {
        int code = 0;
        try
        {

            var inputSegment = input == null ? MemorySegment.NULL : MemorySegment.ofArray(input);

            code = (int) updateAADFuncHandle.invokeExact(
                    ref,
                    inputSegment,
                    inputSegment.byteSize(),
                    inputOffset,
                    inputLen);
        } catch (Throwable t)
        {
            L.log(
                    Level.WARNING,
                    "FFI BlockCipherNI_updateAAD",
                    t);
            throw new RuntimeException(t.getMessage(), t);
        }
        return code;
    }

    @Override
    public int doFinal(long ref, byte[] output, int outputOffset)
    {
        int code = 0;
        try
        {
            var outputSegment = output == null ? MemorySegment.NULL : MemorySegment.ofArray(output);

            code = (int) finalFuncHandle.invokeExact(
                    ref,
                    outputSegment,
                    outputSegment.byteSize(),
                    outputOffset);
        } catch (Throwable t)
        {
            L.log(
                    Level.WARNING,
                    "FFI BlockCipherNI_final",
                    t);
            throw new RuntimeException(t.getMessage(), t);
        }
        return code;
    }


    @Override
    public int getFinalSize(long ref, int length)
    {
        int code = 0;
        try
        {
            code = (int) finalSizeFuncHandle.invokeExact(ref, length);
        } catch (Throwable t)
        {
            L.log(
                    Level.WARNING,
                    "FFI BlockCipherNI_getFinalSize",
                    t);
            throw new RuntimeException(t.getMessage(), t);
        }
        return code;
    }

    @Override
    public int getUpdateSize(long ref, int length)
    {
        int code = 0;
        try
        {
            code = (int) updateSizeFuncHandle.invokeExact(ref, length);
        } catch (Throwable t)
        {
            L.log(
                    Level.WARNING,
                    "FFI BlockCipherNI_getUpdateSize",
                    t);
            throw new RuntimeException(t.getMessage(), t);
        }
        return code;
    }

    @Override
    public void dispose(long ref)
    {
        try
        {
            disposeFuncHandle.invokeExact(ref);
        } catch (Throwable t)
        {
            L.log(
                    Level.WARNING,
                    "FFI BlockCipherNI_dispose",
                    t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

}
