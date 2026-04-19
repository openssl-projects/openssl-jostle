package org.openssl.jostle.jcajce.provider.mac;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.util.logging.Level;
import java.util.logging.Logger;

public class MacServiceFFI implements MacServiceNI
{
    private static final Logger L = Logger.getLogger("MAC_NI_FFI");
    private static final SymbolLookup LOOKUP = SymbolLookup.loaderLookup();
    private static final Linker LINKER = Linker.nativeLinker();

    private static final MethodHandle MH_new;
    private static final MethodHandle MH_init;
    private static final MethodHandle MH_update;
    private static final MethodHandle MH_final;
    private static final MethodHandle MH_len;
    private static final MethodHandle MH_reset;
    private static final MethodHandle MH_free;
    private static final MethodHandle MH_copy;

    static
    {
        MH_new = LINKER.downcallHandle(
                LOOKUP.find("MAC_new").orElseThrow(),
                FunctionDescriptor.of(
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS
                ), Linker.Option.critical(true));

        MH_init = LINKER.downcallHandle(
                LOOKUP.find("MAC_init").orElseThrow(),
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG
                ), Linker.Option.critical(true));

        MH_update = LINKER.downcallHandle(
                LOOKUP.find("MAC_update").orElseThrow(),
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_INT
                ), Linker.Option.critical(true));

        MH_final = LINKER.downcallHandle(
                LOOKUP.find("MAC_final").orElseThrow(),
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.JAVA_INT
                ), Linker.Option.critical(true));

        MH_len = LINKER.downcallHandle(
                LOOKUP.find("MAC_len").orElseThrow(),
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_LONG
                ), Linker.Option.critical(true));

        MH_reset = LINKER.downcallHandle(
                LOOKUP.find("MAC_reset").orElseThrow(),
                FunctionDescriptor.ofVoid(ValueLayout.JAVA_LONG),
                Linker.Option.critical(true));

        MH_free = LINKER.downcallHandle(
                LOOKUP.find("MAC_free").orElseThrow(),
                FunctionDescriptor.ofVoid(ValueLayout.JAVA_LONG),
                Linker.Option.critical(true));

        MH_copy = LINKER.downcallHandle(
                LOOKUP.find("MAC_copy").orElseThrow(),
                FunctionDescriptor.of(
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.ADDRESS
                ), Linker.Option.critical(true));
    }

    @Override
    public long ni_allocateMac(String macName, String canonicalDigestName, int[] err)
    {
        try (Arena arena = Arena.ofConfined())
        {
            MemorySegment macNameSeg = macName == null ? MemorySegment.NULL : arena.allocateFrom(macName);
            MemorySegment name = canonicalDigestName == null ? MemorySegment.NULL : arena.allocateFrom(canonicalDigestName);
            MemorySegment errSeg = MemorySegment.ofArray(err);
            MemorySegment outPtr = (MemorySegment)MH_new.invokeExact(macNameSeg, name, errSeg);
            return outPtr.address();
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI MAC_new", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_init(long ref, byte[] keyBytes)
    {
        try
        {
            MemorySegment key = keyBytes == null ? MemorySegment.NULL : MemorySegment.ofArray(keyBytes);
            return (int) MH_init.invokeExact(ref, key, key.byteSize());
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI MAC_init", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_updateByte(long ref, byte b)
    {
        return ni_updateBytes(ref, new byte[]{b}, 0, 1);
    }

    @Override
    public int ni_updateBytes(long ref, byte[] in, int inOff, int inLen)
    {
        try
        {
            MemorySegment input = in == null ? MemorySegment.NULL : MemorySegment.ofArray(in);
            return (int) MH_update.invokeExact(ref, input, input.byteSize(), inOff, inLen);
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI MAC_update", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_doFinal(long ref, byte[] out, int outOff)
    {
        try
        {
            MemorySegment output = out == null ? MemorySegment.NULL : MemorySegment.ofArray(out);
            return (int) MH_final.invokeExact(ref, output, output.byteSize(), outOff);
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI MAC_final", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_getMacLength(long ref)
    {
        try
        {
            return (int) MH_len.invokeExact(ref);
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI MAC_len", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public void ni_reset(long ref)
    {
        try
        {
            MH_reset.invokeExact(ref);
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI MAC_reset", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public void ni_dispose(long ref)
    {
        try
        {
            MH_free.invokeExact(ref);
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI MAC_free", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public long ni_copy(long ref, int[] err)
    {
        try (Arena arena = Arena.ofConfined())
        {
            MemorySegment errSeg = MemorySegment.ofArray(err);
            MemorySegment outPtr = (MemorySegment)MH_copy.invokeExact(ref, errSeg);
            return outPtr.address();
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI MAC_copy", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }
}
