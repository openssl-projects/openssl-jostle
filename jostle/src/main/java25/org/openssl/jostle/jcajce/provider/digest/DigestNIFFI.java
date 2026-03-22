package org.openssl.jostle.jcajce.provider.digest;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;

/**
 * FFI-backed implementation of {@link DigestNI} using libinterface_ffi.
 * <p>
 * This variant binds native symbols via the JDK Foreign Function & Memory API
 * and exposes Java implementations for all {@link DigestNI} methods.
 * It avoids JNI glue, enabling easier Java-side debugging and maintenance.
 */
public class DigestNIFFI implements DigestNI
{
    private static final SymbolLookup LOOKUP = SymbolLookup.loaderLookup();
    private static final Linker LINKER = Linker.nativeLinker();

    private static final MethodHandle MH_new;
    private static final MethodHandle MH_update;
    private static final MethodHandle MH_final;
    private static final MethodHandle MH_len;
    private static final MethodHandle MH_reset;
    private static final MethodHandle MH_free;
    private static final MethodHandle MH_setProvider;
    private static final MethodHandle MH_copy;

    static
    {
        MH_new = LINKER.downcallHandle(
                LOOKUP.find("jo_digest_new").orElseThrow(),
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,          // rc
                        ValueLayout.ADDRESS,            // const char* name
                        ValueLayout.ADDRESS             // uintptr_t* out
                ), Linker.Option.critical(true));

        MH_update = LINKER.downcallHandle(
                LOOKUP.find("jo_digest_update").orElseThrow(),
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,          // rc
                        ValueLayout.JAVA_LONG,         // uintptr_t ctx
                        ValueLayout.ADDRESS,           // const uint8_t* in
                        ValueLayout.JAVA_INT,          // off
                        ValueLayout.JAVA_INT           // len
                ), Linker.Option.critical(true));

        MH_final = LINKER.downcallHandle(
                LOOKUP.find("jo_digest_final").orElseThrow(),
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,          // written or rc
                        ValueLayout.JAVA_LONG,         // uintptr_t ctx
                        ValueLayout.ADDRESS,           // uint8_t* out
                        ValueLayout.JAVA_INT,          // off
                        ValueLayout.JAVA_INT           // out_len
                ), Linker.Option.critical(true));

        MH_len = LINKER.downcallHandle(
                LOOKUP.find("jo_digest_len").orElseThrow(),
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,          // len or rc
                        ValueLayout.JAVA_LONG          // uintptr_t ctx
                ), Linker.Option.critical(true));

        MH_reset = LINKER.downcallHandle(
                LOOKUP.find("jo_digest_reset").orElseThrow(),
                FunctionDescriptor.ofVoid(
                        ValueLayout.JAVA_LONG          // uintptr_t ctx
                ), Linker.Option.critical(true));

        MH_free = LINKER.downcallHandle(
                LOOKUP.find("jo_digest_free").orElseThrow(),
                FunctionDescriptor.ofVoid(
                        ValueLayout.JAVA_LONG          // uintptr_t ctx
                ), Linker.Option.critical(true));

        MH_copy = LINKER.downcallHandle(
                LOOKUP.find("jo_digest_copy").orElseThrow(),
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,          // rc
                        ValueLayout.JAVA_LONG,         // uintptr_t ctx
                        ValueLayout.ADDRESS            // uintptr_t* out
                ), Linker.Option.critical(true));

        // Attempt to load the default provider early so EVP_MD_fetch works
        MethodHandle setProv = null;
        try
        {
            setProv = LINKER.downcallHandle(
                    LOOKUP.find("set_openssl_module").orElseThrow(),
                    FunctionDescriptor.of(
                            ValueLayout.JAVA_INT,      // rc
                            ValueLayout.ADDRESS        // const char* prov_name
                    ), Linker.Option.critical(true));
        }
        catch (Throwable ignored)
        {
        }
        MH_setProvider = setProv;

        try (Arena a = Arena.ofConfined())
        {
            if (MH_setProvider != null)
            {
                MemorySegment def = a.allocateFrom("default");
                MH_setProvider.invokeExact(def);
            }
        }
        catch (Throwable ignored)
        {
        }
    }

    @Override
    public long makeInstance(String canonicalAlgName)
    {
        // Marshal the Java String to a native C string and allocate space for
        // a native pointer (outPtr). On success, jo_digest_new writes the
        // created context pointer into outPtr which we then read as a long.
        try (Arena arena = Arena.ofConfined())
        {
            MemorySegment name = (canonicalAlgName == null) ? MemorySegment.NULL : arena.allocateFrom(canonicalAlgName);
            // uintptr_t* out (allocate space to hold a native pointer/address)
            MemorySegment outPtr = arena.allocate(ValueLayout.ADDRESS);
            int rc = (int) MH_new.invokeExact(name, outPtr);
            if (rc < 0)
            {
                return 0L;
            }
            // Read pointer value as long
            long ref = outPtr.get(ValueLayout.ADDRESS, 0).address();
            return ref;
        }
        catch (Throwable t)
        {
            return 0L;
        }
    }

    @Override
    public int update(long ref, byte[] in, int inOff, int inLen)
    {
        // Convert the input array into a MemorySegment view and call into native.
        try
        {
            // Fast-path: zero-length update does nothing
            if (inLen == 0)
            {
                return 0;
            }
            // Quick Java-side validation to avoid native hop on obvious errors
            if (in == null)
            {
                return -1;
            }
            if (inOff < 0 || inLen < 0)
            {
                return -1;
            }
            if ((long) inOff + (long) inLen > (long) in.length)
            {
                return -1;
            }
            MemorySegment inSeg = (in == null) ? MemorySegment.NULL : MemorySegment.ofArray(in);
            return (int) MH_update.invokeExact(ref, inSeg, inOff, inLen);
        }
        catch (Throwable t)
        {
            return -1; // generic failure mapped by DigestNI.handleUpdateCodes
        }
    }

    @Override
    public int doFinal(long ref, byte[] out, int outOff)
    {
        // Finalize and write the digest into the provided buffer.
        try
        {
            MemorySegment outSeg = (out == null) ? MemorySegment.NULL : MemorySegment.ofArray(out);
            return (int) MH_final.invokeExact(ref, outSeg, outOff, out == null ? 0 : (int) outSeg.byteSize());
        }
        catch (Throwable t)
        {
            return -1;
        }
    }

    @Override
    public int getDigestLength(long ref)
    {
        // Query the native context for its digest length in bytes.
        try
        {
            return (int) MH_len.invokeExact(ref);
        }
        catch (Throwable t)
        {
            return -1;
        }
    }

    @Override
    public void reset(long ref)
    {
        // Reset the native context for reuse.
        try
        {
            MH_reset.invokeExact(ref);
        }
        catch (Throwable ignored)
        {
        }
    }

    @Override
    public void dispose(long ref)
    {
        // Free the native context and associated resources.
        try
        {
            MH_free.invokeExact(ref);
        }
        catch (Throwable ignored)
        {
        }
    }

    @Override
    public long copy(long ref)
    {
        try (Arena arena = Arena.ofConfined())
        {
            MemorySegment outPtr = arena.allocate(ValueLayout.ADDRESS);
            int rc = (int) MH_copy.invokeExact(ref, outPtr);
            if (rc < 0)
            {
                return 0L;
            }
            long newRef = outPtr.get(ValueLayout.ADDRESS, 0).address();
            return newRef;
        }
        catch (Throwable t)
        {
            return 0L;
        }
    }
}
