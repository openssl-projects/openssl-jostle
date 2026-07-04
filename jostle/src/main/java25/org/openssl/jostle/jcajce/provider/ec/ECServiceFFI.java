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

package org.openssl.jostle.jcajce.provider.ec;

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
 * FFI binding for the {@code JoEC_*} symbols exported by
 * {@code interface/ffi/ec_ni_ffi.c}.
 */
// Symbol resolution is parameterised by a SymbolLookup so the same
// marshalling serves both interface libraries (see MDServiceFFI).
public class ECServiceFFI implements ECServiceNI
{
    private static final Logger L = Logger.getLogger("EC_NI_FFI");
    private static final Linker linker = Linker.nativeLinker();

    private final MethodHandle curveSupportedH;
    private final MethodHandle generateKeyPairH;
    private final MethodHandle makePrivateFromComponentsH;
    private final MethodHandle getComponentH;
    private final MethodHandle allocSignerH;
    private final MethodHandle disposeSignerH;
    private final MethodHandle initSignH;
    private final MethodHandle initVerifyH;
    private final MethodHandle updateH;
    private final MethodHandle signH;
    private final MethodHandle verifyH;
    private final MethodHandle allocKexH;
    private final MethodHandle disposeKexH;
    private final MethodHandle kexInitH;
    private final MethodHandle kexSetPeerH;
    private final MethodHandle kexDeriveH;

    // Lookup-independent constants for the RandSource entropy upcall stub.
    private static final FunctionDescriptor entropyFd = FunctionDescriptor.of(
            ValueLayout.JAVA_INT,
            ValueLayout.ADDRESS,
            ValueLayout.JAVA_INT,
            ValueLayout.JAVA_INT,
            ValueLayout.JAVA_BOOLEAN);
    private static final MethodType entropyMt = MethodType.methodType(
            int.class,
            MemorySegment.class,
            int.class,
            int.class,
            boolean.class);


    public ECServiceFFI()
    {
        this(SymbolLookup.loaderLookup());
    }

    public ECServiceFFI(SymbolLookup lookup)
    {
        curveSupportedH = bind(lookup, "JoEC_curveSupported",
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));

        // JoEC_generateKeyPair(const char* curve_name, int32_t* err, void* rnd_src) -> key_spec*
        generateKeyPairH = bind(lookup, "JoEC_generateKeyPair",
                FunctionDescriptor.of(
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,    // curve_name
                        ValueLayout.ADDRESS,    // err out
                        ValueLayout.ADDRESS));  // rnd_src upcall

        // JoEC_makePrivateFromComponents(curve_name, scalar, scalar_size,
        //                                err_out, rnd_src) -> key_spec*
        // NON-critical: OpenSSL's public-key re-derivation makes a Java
        // RAND upcall during EVP_PKEY_fromdata, same rationale as verify
        // / kex_derive.
        makePrivateFromComponentsH = bind(lookup, "JoEC_makePrivateFromComponents",
                FunctionDescriptor.of(
                        ValueLayout.ADDRESS,    // returns key_spec*
                        ValueLayout.ADDRESS,    // curve_name
                        ValueLayout.ADDRESS,    // scalar bytes
                        ValueLayout.JAVA_LONG,  // scalar_size
                        ValueLayout.ADDRESS,    // err out
                        ValueLayout.ADDRESS));  // rnd_src upcall

        // JoEC_getComponent(key_spec*, int32_t, uint8_t*, size_t) -> int32_t
        getComponentH = bind(lookup, "JoEC_getComponent",
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG),
                /* critical */ true);

        allocSignerH = bind(lookup, "JoEC_allocateSigner",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));

        disposeSignerH = linker.downcallHandle(
                lookup.find("JoEC_disposeSigner").orElseThrow(),
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));

        // JoEC_initSign(ec_ctx*, key_spec*, const char* digest, void* rnd_src) -> int
        initSignH = bind(lookup, "JoEC_initSign",
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS));

        initVerifyH = bind(lookup, "JoEC_initVerify",
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS));

        // JoEC_update(ec_ctx*, uint8_t* in, size_t in_size, int32_t off, int32_t len) -> int
        updateH = bind(lookup, "JoEC_update",
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_INT),
                /* critical */ true);

        // JoEC_sign(ec_ctx*, uint8_t* out, size_t out_size, int32_t out_off, void* rnd_src) -> int
        signH = bind(lookup, "JoEC_sign",
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS));

        // JoEC_verify(ec_ctx*, uint8_t* sig, size_t sig_size, int32_t sig_len,
        //             void* rnd_src) -> int
        //
        // NON-critical: EC verify uses RAND internally for point-blinding
        // (a side-channel mitigation), and that path makes a Java upcall
        // through the lib-ctx-bound RAND provider. Upcalls are forbidden
        // inside critical regions, so we trade the critical-mode speedup
        // for correctness here.
        verifyH = bind(lookup, "JoEC_verify",
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS));

        allocKexH = bind(lookup, "JoEC_allocateKex",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));

        disposeKexH = linker.downcallHandle(
                lookup.find("JoEC_disposeKex").orElseThrow(),
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));

        // JoEC_kexInit(ec_kex_ctx*, key_spec*, void* rnd_src) -> int
        kexInitH = bind(lookup, "JoEC_kexInit",
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS));

        // JoEC_kexSetPeer(ec_kex_ctx*, key_spec*, void* rnd_src) -> int
        // NON-critical: binary-field curves trigger an internal
        // EVP_PKEY_public_check that consumes RAND. Same rationale
        // as verify / kex_derive.
        kexSetPeerH = bind(lookup, "JoEC_kexSetPeer",
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS));

        // JoEC_kexDerive(ec_kex_ctx*, uint8_t* out, size_t out_size,
        //                int32_t out_off, void* rnd_src) -> int
        // NON-critical: derive consumes RAND for point blinding, same
        // rationale as verify.
        kexDeriveH = bind(lookup, "JoEC_kexDerive",
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS));

        // Entropy upcall: int(uint8_t* buf, int len, int strength, bool predRes).
    }

    private static MethodHandle bind(SymbolLookup lookup, String symbol, FunctionDescriptor fd)
    {
        return linker.downcallHandle(lookup.find(symbol).orElseThrow(), fd);
    }

    private static MethodHandle bind(SymbolLookup lookup, String symbol, FunctionDescriptor fd, boolean critical)
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


    @Override
    public int ni_curveSupported(String curveName)
    {
        try (Arena a = Arena.ofConfined())
        {
            return (int) curveSupportedH.invokeExact(nativeString(a, curveName));
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI EC_curveSupported", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public long ni_generateKeyPair(String curveName, int[] err, RandSource rndSource)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment errSeg = a.allocate(ValueLayout.JAVA_INT);
            MemorySegment ref = (MemorySegment) generateKeyPairH.invokeExact(
                    nativeString(a, curveName), errSeg, entropyStub(a, rndSource));
            err[0] = errSeg.get(ValueLayout.JAVA_INT, 0);
            return ref.address();
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI EC_generateKeyPair", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public long ni_makePrivateFromComponents(String curveName, byte[] scalarBE,
                                             int[] err, RandSource rndSource)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment errSeg = a.allocate(ValueLayout.JAVA_INT);
            // The handle is non-critical (entropy upcall must run)
            // so heap segments aren't legal — copy the scalar into a
            // confined-arena native segment.
            MemorySegment scalarSeg;
            long scalarSize;
            if (scalarBE == null)
            {
                scalarSeg = MemorySegment.NULL;
                scalarSize = 0L;
            }
            else
            {
                scalarSeg = a.allocate(scalarBE.length);
                scalarSeg.asByteBuffer().put(scalarBE);
                scalarSize = scalarBE.length;
            }
            MemorySegment ref = (MemorySegment) makePrivateFromComponentsH.invokeExact(
                    nativeString(a, curveName), scalarSeg, scalarSize,
                    errSeg, entropyStub(a, rndSource));
            err[0] = errSeg.get(ValueLayout.JAVA_INT, 0);
            return ref.address();
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI EC_makePrivateFromComponents", t);
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
            L.log(Level.WARNING, "FFI EC_getComponent", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }


    // =================================================================
    // Sign / verify session
    // =================================================================

    @Override
    public long ni_allocateSigner(int[] err)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment errSeg = a.allocate(ValueLayout.JAVA_INT);
            MemorySegment ref = (MemorySegment) allocSignerH.invokeExact(errSeg);
            err[0] = errSeg.get(ValueLayout.JAVA_INT, 0);
            return ref.address();
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI EC_allocateSigner", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public void ni_disposeSigner(long reference)
    {
        try
        {
            disposeSignerH.invokeExact(MemorySegment.ofAddress(reference));
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI EC_disposeSigner", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_initSign(long ref, long keyRef, String digestName, RandSource rndSource)
    {
        try (Arena a = Arena.ofConfined())
        {
            return (int) initSignH.invokeExact(
                    MemorySegment.ofAddress(ref),
                    MemorySegment.ofAddress(keyRef),
                    nativeString(a, digestName),
                    entropyStub(a, rndSource));
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI EC_initSign", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_initVerify(long ref, long keyRef, String digestName)
    {
        try (Arena a = Arena.ofConfined())
        {
            return (int) initVerifyH.invokeExact(
                    MemorySegment.ofAddress(ref),
                    MemorySegment.ofAddress(keyRef),
                    nativeString(a, digestName));
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI EC_initVerify", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_update(long ref, byte[] input, int inOff, int inLen)
    {
        try
        {
            MemorySegment ctx = MemorySegment.ofAddress(ref);
            MemorySegment inSeg = input == null ? MemorySegment.NULL : MemorySegment.ofArray(input);
            long inSize = input == null ? 0L : inSeg.byteSize();
            return (int) updateH.invokeExact(ctx, inSeg, inSize, inOff, inLen);
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI EC_update", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_sign(long ref, byte[] sig, int outOff, RandSource rndSource)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment ctx = MemorySegment.ofAddress(ref);
            // sign uses a non-critical handle (entropy upcall must run);
            // copy bytes through a native segment when needed.
            MemorySegment sigSeg;
            long sigSize;
            if (sig == null)
            {
                sigSeg = MemorySegment.NULL;
                sigSize = 0L;
            }
            else
            {
                sigSeg = a.allocate(sig.length);
                sigSize = sig.length;
            }
            int rc = (int) signH.invokeExact(ctx, sigSeg, sigSize, outOff, entropyStub(a, rndSource));
            // Copy the signature bytes back into the caller's array.
            // Native side wrote `rc` bytes starting at outOff (when sig != null).
            if (sig != null && rc > 0)
            {
                sigSeg.asByteBuffer().get(outOff, sig, outOff, rc);
            }
            return rc;
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI EC_sign", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_verify(long ref, byte[] sig, int sigLen, RandSource rndSource)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment ctx = MemorySegment.ofAddress(ref);
            // Heap segments aren't legal across non-critical handles —
            // copy the signature bytes into a confined-arena native
            // segment for the call.
            MemorySegment sigSeg;
            long sigSize;
            if (sig == null)
            {
                sigSeg = MemorySegment.NULL;
                sigSize = 0L;
            }
            else
            {
                sigSeg = a.allocate(sig.length);
                sigSeg.asByteBuffer().put(sig);
                sigSize = sig.length;
            }
            return (int) verifyH.invokeExact(ctx, sigSeg, sigSize, sigLen,
                    entropyStub(a, rndSource));
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI EC_verify", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }


    // =================================================================
    // Key agreement (ECDH) session
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
            L.log(Level.WARNING, "FFI EC_allocateKex", t);
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
            L.log(Level.WARNING, "FFI EC_disposeKex", t);
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
            L.log(Level.WARNING, "FFI EC_kexInit", t);
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
            L.log(Level.WARNING, "FFI EC_kexSetPeer", t);
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
            L.log(Level.WARNING, "FFI EC_kexDerive", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }
}
