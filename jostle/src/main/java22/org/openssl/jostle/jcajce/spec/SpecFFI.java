package org.openssl.jostle.jcajce.spec;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.util.logging.Level;
import java.util.logging.Logger;

public class SpecFFI implements SpecNI
{
    private static final Logger L = Logger.getLogger("SpecNI_FFI");
    private static final SymbolLookup lookup = SymbolLookup.loaderLookup();
    private static final Linker linker = Linker.nativeLinker();

    private static final MemorySegment allocateFunc;
    private static final MethodHandle allocateFuncHandle;

    private static final MemorySegment disposeFunc;
    private static final MethodHandle disposeFuncHandle;

    private static final MemorySegment encapFunc;
    private static final MethodHandle encapFuncHandle;

    private static final MemorySegment decapFunc;
    private static final MethodHandle decapFuncHandle;

    private static final MemorySegment getNameFunc;
    private static final MethodHandle getNameFuncHandle;

    static
    {

        allocateFunc = lookup.find("SpecNI_allocateKeySpec").orElseThrow();
        allocateFuncHandle = linker.downcallHandle(allocateFunc,
                FunctionDescriptor.of(
                        ValueLayout.ADDRESS // Return ptr
                ));

        disposeFunc = lookup.find("SpecNI_disposeKeySpec").orElseThrow();
        disposeFuncHandle = linker.downcallHandle(disposeFunc,
                FunctionDescriptor.ofVoid(
                        ValueLayout.ADDRESS // ptr
                ));


        encapFunc = lookup.find("SpecNI_Encap").orElseThrow();
        encapFuncHandle = linker.downcallHandle(encapFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT
                ), Linker.Option.critical(true));

        decapFunc = lookup.find("SpecNI_Decap").orElseThrow();
        decapFuncHandle = linker.downcallHandle(decapFunc,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT
                ), Linker.Option.critical(true));


        getNameFunc = lookup.find("SpecNI_GetName").orElseThrow();
        getNameFuncHandle = linker.downcallHandle(getNameFunc,
                FunctionDescriptor.of(
                        ValueLayout.ADDRESS, // return
                        ValueLayout.ADDRESS, // spec
                        ValueLayout.ADDRESS // len
                ));

    }


    @Override
    public void dispose(long reference)
    {
        try
        {
            disposeFuncHandle.invokeExact(MemorySegment.ofAddress(reference));
        } catch (Throwable t)
        {
            L.log(
                    Level.WARNING,
                    "FFI SpecNI_getTypeOrdinal",
                    t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public long allocate()
    {
        try
        {
            MemorySegment addr = (MemorySegment) allocateFuncHandle.invokeExact();
            return addr.address();
        } catch (Throwable t)
        {
            L.log(
                    Level.WARNING,
                    "FFI SpecNI_allocateKeySpec",
                    t);
            throw new RuntimeException(t.getMessage(), t);
        }

    }



    @Override
    public String getName(long keyRef)
    {
        try (Arena a = Arena.ofConfined())
        {
            var ref = MemorySegment.ofAddress(keyRef);
            var len = a.allocate(ValueLayout.JAVA_LONG);
            MemorySegment memorySegment = (MemorySegment) getNameFuncHandle.invokeExact(ref, len);

            long size = len.get(ValueLayout.OfLong.JAVA_LONG, 0);
            if (size < 0)
            {
                throw new IllegalArgumentException("returned name len is negative");
            }
            memorySegment = memorySegment.reinterpret(size+1); // + null termination
            return memorySegment.getString(0);
        } catch (IllegalArgumentException ilex)
        {
            throw ilex;
        } catch (Throwable t)
        {
            L.log(
                    Level.WARNING,
                    "FFI SpecNI_getTypeOrdinal",
                    t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int encap(long keyRef, String opt, byte[] input, int inOff, int inLen, byte[] out, int off, int len)
    {
        try (Arena a = Arena.ofConfined())
        {
            var ref = MemorySegment.ofAddress(keyRef);
            var optRef = opt != null ? a.allocateFrom(opt) : MemorySegment.NULL;
            var inputRef = input != null ? MemorySegment.ofArray(input) : MemorySegment.NULL;
            var inSize = input != null ? input.length : 0;
            var outRef = out != null ? MemorySegment.ofArray(out) : MemorySegment.NULL;
            var outSize = out != null ? out.length : 0;

            return (int) encapFuncHandle.invokeExact(ref, optRef, inputRef, (long) inSize, inOff, inLen, outRef, (long) outSize, off, len);

        } catch (Throwable t)
        {
            L.log(
                    Level.WARNING,
                    "FFI SpecNI_Encap",
                    t);
            throw new RuntimeException(t.getMessage(), t);
        }

    }

    @Override
    public int decap(long keyRef, String opt, byte[] input, int inOff, int inLen, byte[] out, int off, int len)
    {
        try (Arena a = Arena.ofConfined())
        {
            var ref = MemorySegment.ofAddress(keyRef);
            var optRef = opt != null ? a.allocateFrom(opt) : MemorySegment.NULL;
            var inputRef = input != null ? MemorySegment.ofArray(input) : MemorySegment.NULL;
            var inSize = input != null ? input.length : 0;
            var outRef = out != null ? MemorySegment.ofArray(out) : MemorySegment.NULL;
            var outSize = out != null ? out.length : 0;

            return (int) decapFuncHandle.invokeExact(ref, optRef, inputRef, (long) inSize, inOff, inLen, outRef, (long) outSize, off, len);

        } catch (Throwable t)
        {
            L.log(
                    Level.WARNING,
                    "FFI SpecNI_Decap",
                    t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

}
