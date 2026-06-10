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

package org.openssl.jostle.jcajce.provider.dsa;

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
 * FFI binding for the {@code JoDSA_*} symbols exported by
 * {@code interface/ffi/dsa_ni_ffi.c}.
 */
public class DSAServiceFFI implements DSAServiceNI
{
    private static final Logger L = Logger.getLogger("DSA_NI_FFI");
    private static final SymbolLookup lookup = SymbolLookup.loaderLookup();
    private static final Linker linker = Linker.nativeLinker();

    private static final MethodHandle generateParametersH;
    private static final MethodHandle makeParamsFromComponentsH;
    private static final MethodHandle generateKeyPairH;
    private static final MethodHandle makePrivateFromComponentsH;
    private static final MethodHandle makePublicFromComponentsH;
    private static final MethodHandle getComponentH;
    private static final MethodHandle allocSignerH;
    private static final MethodHandle disposeSignerH;
    private static final MethodHandle initSignH;
    private static final MethodHandle initVerifyH;
    private static final MethodHandle updateH;
    private static final MethodHandle signH;
    private static final MethodHandle verifyH;

    private static final FunctionDescriptor entropyFd;
    private static final MethodType entropyMt;


    static
    {
        // JoDSA_generateParameters(int32_t p_bits, int32_t q_bits,
        //                          int32_t* err, void* rnd_src) -> key_spec*
        // NON-critical: paramgen's prime search draws from the Java RAND
        // upcall.
        generateParametersH = bind("JoDSA_generateParameters",
                FunctionDescriptor.of(
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_INT,   // p_bits
                        ValueLayout.JAVA_INT,   // q_bits
                        ValueLayout.ADDRESS,    // err out
                        ValueLayout.ADDRESS));  // rnd_src upcall

        // JoDSA_makeParamsFromComponents(p, p_size, q, q_size, g, g_size,
        //                                err_out) -> key_spec*
        makeParamsFromComponentsH = bind("JoDSA_makeParamsFromComponents",
                FunctionDescriptor.of(
                        ValueLayout.ADDRESS,    // returns key_spec*
                        ValueLayout.ADDRESS,    // p bytes
                        ValueLayout.JAVA_LONG,  // p_size
                        ValueLayout.ADDRESS,    // q bytes
                        ValueLayout.JAVA_LONG,  // q_size
                        ValueLayout.ADDRESS,    // g bytes
                        ValueLayout.JAVA_LONG,  // g_size
                        ValueLayout.ADDRESS));  // err out

        // JoDSA_generateKeyPair(key_spec* params, int32_t* err,
        //                       void* rnd_src) -> key_spec*
        generateKeyPairH = bind("JoDSA_generateKeyPair",
                FunctionDescriptor.of(
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,    // params spec
                        ValueLayout.ADDRESS,    // err out
                        ValueLayout.ADDRESS));  // rnd_src upcall

        // JoDSA_makePrivateFromComponents(p, p_size, q, q_size, g, g_size,
        //                                 x, x_size, err_out, rnd_src) -> key_spec*
        // NON-critical: the entropy upcall must be allowed during import.
        makePrivateFromComponentsH = bind("JoDSA_makePrivateFromComponents",
                FunctionDescriptor.of(
                        ValueLayout.ADDRESS,    // returns key_spec*
                        ValueLayout.ADDRESS,    // p bytes
                        ValueLayout.JAVA_LONG,  // p_size
                        ValueLayout.ADDRESS,    // q bytes
                        ValueLayout.JAVA_LONG,  // q_size
                        ValueLayout.ADDRESS,    // g bytes
                        ValueLayout.JAVA_LONG,  // g_size
                        ValueLayout.ADDRESS,    // x bytes
                        ValueLayout.JAVA_LONG,  // x_size
                        ValueLayout.ADDRESS,    // err out
                        ValueLayout.ADDRESS));  // rnd_src upcall

        // JoDSA_makePublicFromComponents(p, p_size, q, q_size, g, g_size,
        //                                y, y_size, err_out) -> key_spec*
        makePublicFromComponentsH = bind("JoDSA_makePublicFromComponents",
                FunctionDescriptor.of(
                        ValueLayout.ADDRESS,    // returns key_spec*
                        ValueLayout.ADDRESS,    // p bytes
                        ValueLayout.JAVA_LONG,  // p_size
                        ValueLayout.ADDRESS,    // q bytes
                        ValueLayout.JAVA_LONG,  // q_size
                        ValueLayout.ADDRESS,    // g bytes
                        ValueLayout.JAVA_LONG,  // g_size
                        ValueLayout.ADDRESS,    // y bytes
                        ValueLayout.JAVA_LONG,  // y_size
                        ValueLayout.ADDRESS));  // err out

        // JoDSA_getComponent(key_spec*, int32_t, uint8_t*, size_t) -> int32_t
        getComponentH = bind("JoDSA_getComponent",
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG),
                /* critical */ true);

        allocSignerH = bind("JoDSA_allocateSigner",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));

        disposeSignerH = linker.downcallHandle(
                lookup.find("JoDSA_disposeSigner").orElseThrow(),
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));

        // JoDSA_initSign(dsa_ctx*, key_spec*, const char* digest, void* rnd_src) -> int
        initSignH = bind("JoDSA_initSign",
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS));

        initVerifyH = bind("JoDSA_initVerify",
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS));

        // JoDSA_update(dsa_ctx*, uint8_t* in, size_t in_size, int32_t off, int32_t len) -> int
        updateH = bind("JoDSA_update",
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_INT),
                /* critical */ true);

        // JoDSA_sign(dsa_ctx*, uint8_t* out, size_t out_size, int32_t out_off,
        //            void* rnd_src) -> int
        // NON-critical: DSA signing consumes RAND for the per-signature
        // nonce, and the entropy upcall is forbidden inside critical
        // regions.
        signH = bind("JoDSA_sign",
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS));

        // JoDSA_verify(dsa_ctx*, uint8_t* sig, size_t sig_size, int32_t sig_len,
        //              void* rnd_src) -> int
        // NON-critical: the RAND upcall is bound on the verify path for
        // parity with EC (see DSAServiceNI.ni_verify).
        verifyH = bind("JoDSA_verify",
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
    public long ni_generateParameters(int pBits, int qBits, int[] err, RandSource rndSource)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment errSeg = a.allocate(ValueLayout.JAVA_INT);
            MemorySegment ref = (MemorySegment) generateParametersH.invokeExact(
                    pBits, qBits, errSeg, entropyStub(a, rndSource));
            err[0] = errSeg.get(ValueLayout.JAVA_INT, 0);
            return ref.address();
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI DSA_generateParameters", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public long ni_makeParamsFromComponents(byte[] p, byte[] q, byte[] g, int[] err)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment errSeg = a.allocate(ValueLayout.JAVA_INT);
            MemorySegment ref = (MemorySegment) makeParamsFromComponentsH.invokeExact(
                    nativeBytes(a, p), sizeOf(p),
                    nativeBytes(a, q), sizeOf(q),
                    nativeBytes(a, g), sizeOf(g),
                    errSeg);
            err[0] = errSeg.get(ValueLayout.JAVA_INT, 0);
            return ref.address();
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI DSA_makeParamsFromComponents", t);
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
            L.log(Level.WARNING, "FFI DSA_generateKeyPair", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public long ni_makePrivateFromComponents(byte[] p, byte[] q, byte[] g, byte[] x,
                                             int[] err, RandSource rndSource)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment errSeg = a.allocate(ValueLayout.JAVA_INT);
            MemorySegment ref = (MemorySegment) makePrivateFromComponentsH.invokeExact(
                    nativeBytes(a, p), sizeOf(p),
                    nativeBytes(a, q), sizeOf(q),
                    nativeBytes(a, g), sizeOf(g),
                    nativeBytes(a, x), sizeOf(x),
                    errSeg, entropyStub(a, rndSource));
            err[0] = errSeg.get(ValueLayout.JAVA_INT, 0);
            return ref.address();
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI DSA_makePrivateFromComponents", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public long ni_makePublicFromComponents(byte[] p, byte[] q, byte[] g, byte[] y,
                                            int[] err)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment errSeg = a.allocate(ValueLayout.JAVA_INT);
            MemorySegment ref = (MemorySegment) makePublicFromComponentsH.invokeExact(
                    nativeBytes(a, p), sizeOf(p),
                    nativeBytes(a, q), sizeOf(q),
                    nativeBytes(a, g), sizeOf(g),
                    nativeBytes(a, y), sizeOf(y),
                    errSeg);
            err[0] = errSeg.get(ValueLayout.JAVA_INT, 0);
            return ref.address();
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI DSA_makePublicFromComponents", t);
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
            L.log(Level.WARNING, "FFI DSA_getComponent", t);
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
            L.log(Level.WARNING, "FFI DSA_allocateSigner", t);
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
            L.log(Level.WARNING, "FFI DSA_disposeSigner", t);
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
            L.log(Level.WARNING, "FFI DSA_initSign", t);
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
            L.log(Level.WARNING, "FFI DSA_initVerify", t);
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
            L.log(Level.WARNING, "FFI DSA_update", t);
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
            L.log(Level.WARNING, "FFI DSA_sign", t);
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
            L.log(Level.WARNING, "FFI DSA_verify", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }
}
