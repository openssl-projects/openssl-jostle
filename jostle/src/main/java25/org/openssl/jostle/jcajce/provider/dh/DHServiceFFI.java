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

package org.openssl.jostle.jcajce.provider.dh;

import org.openssl.jostle.rand.RandSource;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.nio.charset.StandardCharsets;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * FFI binding for the {@code JoDH_*} symbols exported by
 * {@code interface/ffi/dh_ni_ffi.c}.
 */
public class DHServiceFFI implements DHServiceNI
{
    private static final Logger L = Logger.getLogger("DH_NI_FFI");
    private static final SymbolLookup lookup = SymbolLookup.loaderLookup();
    private static final Linker linker = Linker.nativeLinker();

    private static final MethodHandle groupSupportedH;
    private static final MethodHandle generateKeyPairByGroupH;
    private static final MethodHandle generateParametersH;
    private static final MethodHandle makeParamsFromComponentsH;
    private static final MethodHandle generateKeyPairH;
    private static final MethodHandle makePrivateFromComponentsH;
    private static final MethodHandle makePublicFromComponentsH;
    private static final MethodHandle getComponentH;
    private static final MethodHandle allocKexH;
    private static final MethodHandle disposeKexH;
    private static final MethodHandle kexInitH;
    private static final MethodHandle kexSetPeerH;
    private static final MethodHandle kexDeriveH;

    private static final FunctionDescriptor entropyFd;
    private static final MethodType entropyMt;


    static
    {
        groupSupportedH = bind("JoDH_groupSupported",
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));

        // JoDH_generateKeyPairByGroup(const char* group_name, int32_t* err,
        //                             void* rnd_src) -> key_spec*
        generateKeyPairByGroupH = bind("JoDH_generateKeyPairByGroup",
                FunctionDescriptor.of(
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,    // group_name
                        ValueLayout.ADDRESS,    // err out
                        ValueLayout.ADDRESS));  // rnd_src upcall

        // JoDH_generateParameters(int32_t p_bits, int32_t* err,
        //                         void* rnd_src) -> key_spec*
        // NON-critical: the safe-prime search draws from the Java RAND
        // upcall.
        generateParametersH = bind("JoDH_generateParameters",
                FunctionDescriptor.of(
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_INT,   // p_bits
                        ValueLayout.ADDRESS,    // err out
                        ValueLayout.ADDRESS));  // rnd_src upcall

        // JoDH_makeParamsFromComponents(p, p_size, g, g_size, err_out) -> key_spec*
        makeParamsFromComponentsH = bind("JoDH_makeParamsFromComponents",
                FunctionDescriptor.of(
                        ValueLayout.ADDRESS,    // returns key_spec*
                        ValueLayout.ADDRESS,    // p bytes
                        ValueLayout.JAVA_LONG,  // p_size
                        ValueLayout.ADDRESS,    // g bytes
                        ValueLayout.JAVA_LONG,  // g_size
                        ValueLayout.ADDRESS));  // err out

        // JoDH_generateKeyPair(key_spec* params, int32_t* err,
        //                      void* rnd_src) -> key_spec*
        generateKeyPairH = bind("JoDH_generateKeyPair",
                FunctionDescriptor.of(
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,    // params spec
                        ValueLayout.ADDRESS,    // err out
                        ValueLayout.ADDRESS));  // rnd_src upcall

        // JoDH_makePrivateFromComponents(p, p_size, g, g_size, x, x_size,
        //                                err_out, rnd_src) -> key_spec*
        // NON-critical: the entropy upcall must be allowed during import.
        makePrivateFromComponentsH = bind("JoDH_makePrivateFromComponents",
                FunctionDescriptor.of(
                        ValueLayout.ADDRESS,    // returns key_spec*
                        ValueLayout.ADDRESS,    // p bytes
                        ValueLayout.JAVA_LONG,  // p_size
                        ValueLayout.ADDRESS,    // g bytes
                        ValueLayout.JAVA_LONG,  // g_size
                        ValueLayout.ADDRESS,    // x bytes
                        ValueLayout.JAVA_LONG,  // x_size
                        ValueLayout.ADDRESS,    // err out
                        ValueLayout.ADDRESS));  // rnd_src upcall

        // JoDH_makePublicFromComponents(p, p_size, g, g_size, y, y_size,
        //                               err_out) -> key_spec*
        makePublicFromComponentsH = bind("JoDH_makePublicFromComponents",
                FunctionDescriptor.of(
                        ValueLayout.ADDRESS,    // returns key_spec*
                        ValueLayout.ADDRESS,    // p bytes
                        ValueLayout.JAVA_LONG,  // p_size
                        ValueLayout.ADDRESS,    // g bytes
                        ValueLayout.JAVA_LONG,  // g_size
                        ValueLayout.ADDRESS,    // y bytes
                        ValueLayout.JAVA_LONG,  // y_size
                        ValueLayout.ADDRESS));  // err out

        // JoDH_getComponent(key_spec*, int32_t, uint8_t*, size_t) -> int32_t
        getComponentH = bind("JoDH_getComponent",
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG),
                /* critical */ true);

        allocKexH = bind("JoDH_allocateKex",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));

        disposeKexH = linker.downcallHandle(
                lookup.find("JoDH_disposeKex").orElseThrow(),
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));

        // JoDH_kexInit(dh_kex_ctx*, key_spec*, void* rnd_src) -> int
        kexInitH = bind("JoDH_kexInit",
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS));

        // JoDH_kexSetPeer(dh_kex_ctx*, key_spec*, void* rnd_src) -> int
        kexSetPeerH = bind("JoDH_kexSetPeer",
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS));

        // JoDH_kexDerive(dh_kex_ctx*, uint8_t* out, size_t out_size,
        //                int32_t out_off, void* rnd_src) -> int
        // NON-critical: the entropy upcall must be allowed during derive.
        kexDeriveH = bind("JoDH_kexDerive",
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS));

        // Entropy upcall: int(uint8_t* buf, int len, int strength, bool predRes).
        entropyFd = FunctionDescriptor.of(
                ValueLayout.JAVA_INT,
                ValueLayout.ADDRESS,
                ValueLayout.JAVA_INT,
                ValueLayout.JAVA_INT,
                ValueLayout.JAVA_BOOLEAN);
        entropyMt = MethodType.methodType(
                int.class,
                MemorySegment.class,
                int.class,
                int.class,
                boolean.class);
    }

    private static MethodHandle bind(String symbol, FunctionDescriptor fd)
    {
        return linker.downcallHandle(lookup.find(symbol).orElseThrow(), fd);
    }

    private static MethodHandle bind(String symbol, FunctionDescriptor fd, boolean critical)
    {
        return critical
                ? linker.downcallHandle(lookup.find(symbol).orElseThrow(), fd, Linker.Option.critical(true))
                : linker.downcallHandle(lookup.find(symbol).orElseThrow(), fd);
    }

    private static MemorySegment entropyStub(Arena arena, RandSource src)
    {
        if (src == null)
        {
            return MemorySegment.NULL;
        }
        try
        {
            MethodHandle h = MethodHandles.lookup()
                    .findVirtual(src.getClass(), "getRandomSegment", entropyMt)
                    .bindTo(src);
            return linker.upcallStub(h, entropyFd, arena);
        }
        catch (Throwable t)
        {
            throw new RuntimeException("unable to create entropy upcall stub", t);
        }
    }

    /** Allocate a NUL-terminated UTF-8 C string in the arena, or NULL. */
    private static MemorySegment nativeString(Arena a, String s)
    {
        if (s == null)
        {
            return MemorySegment.NULL;
        }
        byte[] utf8 = s.getBytes(StandardCharsets.UTF_8);
        MemorySegment seg = a.allocate(utf8.length + 1);
        seg.asByteBuffer().put(utf8);
        seg.set(ValueLayout.JAVA_BYTE, utf8.length, (byte) 0);
        return seg;
    }

    /**
     * Copy a byte array into a confined-arena native segment, or NULL.
     * Used for the non-critical handles where heap segments aren't legal.
     */
    private static MemorySegment nativeBytes(Arena a, byte[] bytes)
    {
        if (bytes == null)
        {
            return MemorySegment.NULL;
        }
        MemorySegment seg = a.allocate(Math.max(bytes.length, 1));
        if (bytes.length > 0)
        {
            seg.asByteBuffer().put(bytes);
        }
        return seg;
    }

    private static long sizeOf(byte[] bytes)
    {
        return bytes == null ? 0L : bytes.length;
    }


    @Override
    public int ni_groupSupported(String groupName)
    {
        try (Arena a = Arena.ofConfined())
        {
            return (int) groupSupportedH.invokeExact(nativeString(a, groupName));
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI DH_groupSupported", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public long ni_generateKeyPairByGroup(String groupName, int[] err, RandSource rndSource)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment errSeg = a.allocate(ValueLayout.JAVA_INT);
            MemorySegment ref = (MemorySegment) generateKeyPairByGroupH.invokeExact(
                    nativeString(a, groupName), errSeg, entropyStub(a, rndSource));
            err[0] = errSeg.get(ValueLayout.JAVA_INT, 0);
            return ref.address();
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI DH_generateKeyPairByGroup", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public long ni_generateParameters(int pBits, int[] err, RandSource rndSource)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment errSeg = a.allocate(ValueLayout.JAVA_INT);
            MemorySegment ref = (MemorySegment) generateParametersH.invokeExact(
                    pBits, errSeg, entropyStub(a, rndSource));
            err[0] = errSeg.get(ValueLayout.JAVA_INT, 0);
            return ref.address();
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI DH_generateParameters", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public long ni_makeParamsFromComponents(byte[] p, byte[] g, int[] err)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment errSeg = a.allocate(ValueLayout.JAVA_INT);
            MemorySegment ref = (MemorySegment) makeParamsFromComponentsH.invokeExact(
                    nativeBytes(a, p), sizeOf(p),
                    nativeBytes(a, g), sizeOf(g),
                    errSeg);
            err[0] = errSeg.get(ValueLayout.JAVA_INT, 0);
            return ref.address();
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI DH_makeParamsFromComponents", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public long ni_generateKeyPair(long paramsRef, int[] err, RandSource rndSource)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment errSeg = a.allocate(ValueLayout.JAVA_INT);
            MemorySegment ref = (MemorySegment) generateKeyPairH.invokeExact(
                    MemorySegment.ofAddress(paramsRef), errSeg, entropyStub(a, rndSource));
            err[0] = errSeg.get(ValueLayout.JAVA_INT, 0);
            return ref.address();
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI DH_generateKeyPair", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public long ni_makePrivateFromComponents(byte[] p, byte[] g, byte[] x,
                                             int[] err, RandSource rndSource)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment errSeg = a.allocate(ValueLayout.JAVA_INT);
            MemorySegment ref = (MemorySegment) makePrivateFromComponentsH.invokeExact(
                    nativeBytes(a, p), sizeOf(p),
                    nativeBytes(a, g), sizeOf(g),
                    nativeBytes(a, x), sizeOf(x),
                    errSeg, entropyStub(a, rndSource));
            err[0] = errSeg.get(ValueLayout.JAVA_INT, 0);
            return ref.address();
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI DH_makePrivateFromComponents", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public long ni_makePublicFromComponents(byte[] p, byte[] g, byte[] y,
                                            int[] err)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment errSeg = a.allocate(ValueLayout.JAVA_INT);
            MemorySegment ref = (MemorySegment) makePublicFromComponentsH.invokeExact(
                    nativeBytes(a, p), sizeOf(p),
                    nativeBytes(a, g), sizeOf(g),
                    nativeBytes(a, y), sizeOf(y),
                    errSeg);
            err[0] = errSeg.get(ValueLayout.JAVA_INT, 0);
            return ref.address();
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI DH_makePublicFromComponents", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_getComponent(long specRef, int component, byte[] out)
    {
        try
        {
            MemorySegment spec = MemorySegment.ofAddress(specRef);
            MemorySegment outSeg = out == null ? MemorySegment.NULL : MemorySegment.ofArray(out);
            long outLen = out == null ? 0L : outSeg.byteSize();
            return (int) getComponentH.invokeExact(spec, component, outSeg, outLen);
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI DH_getComponent", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }


    // =================================================================
    // Key agreement session
    // =================================================================

    @Override
    public long ni_allocateKex(int[] err)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment errSeg = a.allocate(ValueLayout.JAVA_INT);
            MemorySegment ref = (MemorySegment) allocKexH.invokeExact(errSeg);
            err[0] = errSeg.get(ValueLayout.JAVA_INT, 0);
            return ref.address();
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI DH_allocateKex", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public void ni_disposeKex(long reference)
    {
        try
        {
            disposeKexH.invokeExact(MemorySegment.ofAddress(reference));
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI DH_disposeKex", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_kexInit(long ref, long keyRef, RandSource rndSource)
    {
        try (Arena a = Arena.ofConfined())
        {
            return (int) kexInitH.invokeExact(
                    MemorySegment.ofAddress(ref),
                    MemorySegment.ofAddress(keyRef),
                    entropyStub(a, rndSource));
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI DH_kexInit", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_kexSetPeer(long ref, long peerRef, RandSource rndSource)
    {
        try (Arena a = Arena.ofConfined())
        {
            return (int) kexSetPeerH.invokeExact(
                    MemorySegment.ofAddress(ref),
                    MemorySegment.ofAddress(peerRef),
                    entropyStub(a, rndSource));
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI DH_kexSetPeer", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_kexDerive(long ref, byte[] out, int outOff, RandSource rndSource)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment ctx = MemorySegment.ofAddress(ref);
            MemorySegment outSeg;
            long outSize;
            if (out == null)
            {
                outSeg = MemorySegment.NULL;
                outSize = 0L;
            }
            else
            {
                outSeg = a.allocate(out.length);
                outSize = out.length;
            }
            int rc = (int) kexDeriveH.invokeExact(ctx, outSeg, outSize, outOff,
                    entropyStub(a, rndSource));
            if (out != null && rc > 0)
            {
                outSeg.asByteBuffer().get(outOff, out, outOff, rc);
            }
            return rc;
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI DH_kexDerive", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }
}
