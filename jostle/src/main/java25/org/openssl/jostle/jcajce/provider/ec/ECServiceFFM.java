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

import org.openssl.jostle.rand.EntropyUpcall;
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
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * FFM binding for the {@code JoEC_*} symbols exported by
 * {@code interface/nonfips/ffm/ec_ni_ffm.c}.
 */
// Symbol resolution is parameterised by a SymbolLookup so the same
// marshalling serves both interface libraries (see MDServiceFFM).
public class ECServiceFFM implements ECServiceNI
{
    private static final Logger L = Logger.getLogger("EC_NI_FFM");
    private static final Linker linker = Linker.nativeLinker();

    private final MethodHandle curveSupportedH;
    private final MethodHandle generateKeyPairH;
    private final MethodHandle makePrivateFromComponentsH;
    private final MethodHandle makePublicFromComponentsH;
    private final MethodHandle getComponentH;
    private final MethodHandle getCurveComponentH;
    private final MethodHandle findCurveNameH;
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
    private static final FunctionDescriptor entropyFd = EntropyUpcall.DESCRIPTOR;
    private static final MethodType entropyMt = EntropyUpcall.METHOD_TYPE;


    public ECServiceFFM()
    {
        this(SymbolLookup.loaderLookup());
    }

    public ECServiceFFM(SymbolLookup lookup)
    {
        this(lookup, "");
    }

    /**
     * @param lookup    the library to resolve against.
     * @param symPrefix prepended to every symbol name. Empty for the base
     *                  library; {@code "JoFIPS_"} for the FIPS one, whose
     *                  exports are renamed by the {@code <x>_fips_ffm.c}
     *                  wrappers. Deliberately SEPARATE from {@code lookup}:
     *                  two independent values mean either mistake alone
     *                  still resolves correctly or fails loudly, where a
     *                  single bundled value made a wrong lookup silently
     *                  run base-library crypto.
     */
    public ECServiceFFM(SymbolLookup lookup, String symPrefix)
    {
        // Every name crosses as a NUL-terminated copy plus its UTF-8 byte count (see nameSeg).
        curveSupportedH = bind(lookup, symPrefix + "JoEC_curveSupported",
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));

        // JoEC_generateKeyPair(const char* curve_name, size_t name_len, int32_t* err, void* rnd_src) -> key_spec*
        generateKeyPairH = bind(lookup, symPrefix + "JoEC_generateKeyPair",
                FunctionDescriptor.of(
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,    // curve_name
                        ValueLayout.JAVA_LONG,  // name_len
                        ValueLayout.ADDRESS,    // err out
                        ValueLayout.ADDRESS));  // rnd_src upcall

        // JoEC_makePrivateFromComponents(curve_name, name_len, scalar, scalar_size,
        //                                err_out, rnd_src) -> key_spec*
        // NON-critical: OpenSSL's public-key re-derivation makes a Java
        // RAND upcall during EVP_PKEY_fromdata, same rationale as verify
        // / kex_derive.
        makePrivateFromComponentsH = bind(lookup, symPrefix + "JoEC_makePrivateFromComponents",
                FunctionDescriptor.of(
                        ValueLayout.ADDRESS,    // returns key_spec*
                        ValueLayout.ADDRESS,    // curve_name
                        ValueLayout.JAVA_LONG,  // name_len
                        ValueLayout.ADDRESS,    // scalar bytes
                        ValueLayout.JAVA_LONG,  // scalar_size
                        ValueLayout.ADDRESS,    // err out
                        ValueLayout.ADDRESS));  // rnd_src upcall

        // JoEC_makePublicFromComponents(curve_name, name_len, point, point_size,
        //                               err_out, rnd_src) -> key_spec*
        // NON-critical: EVP_PKEY_public_check makes a Java RAND upcall
        // during its point-blinded scalar mul, same rationale as the
        // private-components handle above.
        makePublicFromComponentsH = bind(lookup, symPrefix + "JoEC_makePublicFromComponents",
                FunctionDescriptor.of(
                        ValueLayout.ADDRESS,    // returns key_spec*
                        ValueLayout.ADDRESS,    // curve_name
                        ValueLayout.JAVA_LONG,  // name_len
                        ValueLayout.ADDRESS,    // point bytes
                        ValueLayout.JAVA_LONG,  // point_size
                        ValueLayout.ADDRESS,    // err out
                        ValueLayout.ADDRESS));  // rnd_src upcall

        // JoEC_getComponent(key_spec*, int32_t, uint8_t*, size_t) -> int32_t
        getComponentH = bind(lookup, symPrefix + "JoEC_getComponent",
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG),
                /* critical */ true);

        // JoEC_getCurveComponent(const char* name, size_t name_len, int32_t comp, uint8_t* out, size_t out_len)
        // NOT critical: the name crosses as an arena segment and the output is
        // copied back, so there is no heap segment to pin. These are cached
        // per curve, so the copy is paid once.
        getCurveComponentH = bind(lookup, symPrefix + "JoEC_getCurveComponent",
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG));

        // JoEC_findCurveName(int32_t field_type, seven (ptr,len) pairs,
        //                    uint8_t* out, size_t out_len) -> int
        findCurveNameH = bind(lookup, symPrefix + "JoEC_findCurveName",
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));

        allocSignerH = bind(lookup, symPrefix + "JoEC_allocateSigner",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));

        disposeSignerH = linker.downcallHandle(
                lookup.find(symPrefix + "JoEC_disposeSigner").orElseThrow(),
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));

        // JoEC_initSign(ec_ctx*, key_spec*, const char* digest, size_t digest_len, void* rnd_src) -> int
        initSignH = bind(lookup, symPrefix + "JoEC_initSign",
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.ADDRESS));

        // JoEC_initVerify(ec_ctx*, key_spec*, const char* digest, size_t digest_len) -> int
        initVerifyH = bind(lookup, symPrefix + "JoEC_initVerify",
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG));

        // JoEC_update(ec_ctx*, uint8_t* in, size_t in_size, int32_t off, int32_t len) -> int
        updateH = bind(lookup, symPrefix + "JoEC_update",
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_INT),
                /* critical */ true);

        // JoEC_sign(ec_ctx*, uint8_t* out, size_t out_size, int32_t out_off, void* rnd_src) -> int
        signH = bind(lookup, symPrefix + "JoEC_sign",
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
        verifyH = bind(lookup, symPrefix + "JoEC_verify",
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS));

        allocKexH = bind(lookup, symPrefix + "JoEC_allocateKex",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));

        disposeKexH = linker.downcallHandle(
                lookup.find(symPrefix + "JoEC_disposeKex").orElseThrow(),
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));

        // JoEC_kexInit(ec_kex_ctx*, key_spec*, void* rnd_src) -> int
        kexInitH = bind(lookup, symPrefix + "JoEC_kexInit",
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS));

        // JoEC_kexSetPeer(ec_kex_ctx*, key_spec*, void* rnd_src) -> int
        // NON-critical: binary-field curves trigger an internal
        // EVP_PKEY_public_check that consumes RAND. Same rationale
        // as verify / kex_derive.
        kexSetPeerH = bind(lookup, symPrefix + "JoEC_kexSetPeer",
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS));

        // JoEC_kexDerive(ec_kex_ctx*, uint8_t* out, size_t out_size,
        //                int32_t out_off, void* rnd_src) -> int
        // NON-critical: derive consumes RAND for point blinding, same
        // rationale as verify.
        kexDeriveH = bind(lookup, symPrefix + "JoEC_kexDerive",
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
                    .findVirtual(RandSource.class, "getRandomSegment", entropyMt)
                    .bindTo(src);
            return linker.upcallStub(h, entropyFd, arena);
        }
        catch (Throwable t)
        {
            throw new RuntimeException("unable to create entropy upcall stub", t);
        }
    }

    /**
     * Copy an input array into the confined arena: NULL for a null array, at least one byte for an empty one so
     * the C can tell null from empty. The true length crosses separately (see {@link #len(byte[])}).
     */
    private static MemorySegment copyIn(Arena a, byte[] src)
    {
        if (src == null)
        {
            return MemorySegment.NULL;
        }
        MemorySegment seg = a.allocate(src.length == 0 ? 1L : src.length);
        if (src.length > 0)
        {
            MemorySegment.copy(src, 0, seg, ValueLayout.JAVA_BYTE, 0L, src.length);
        }
        return seg;
    }

    /** Zero-filled output segment, at least one byte so a non-null caller buffer has a non-NULL address. */
    private static MemorySegment outSeg(Arena a, byte[] out)
    {
        if (out == null)
        {
            return MemorySegment.NULL;
        }
        return a.allocate(out.length == 0 ? 1L : out.length);
    }

    private static long len(byte[] a)
    {
        return a == null ? 0L : a.length;
    }

    /** A name as its UTF-8 bytes, or null; the C takes a NUL-terminated copy plus this count. */
    private static byte[] utf8(String name)
    {
        return name == null ? null : name.getBytes(StandardCharsets.UTF_8);
    }

    private static MemorySegment nameSeg(Arena a, byte[] utf8)
    {
        return utf8 == null ? MemorySegment.NULL
                : a.allocateFrom(ValueLayout.JAVA_BYTE, Arrays.copyOf(utf8, utf8.length + 1));
    }

    /** Fills each non-NULL segment with zero. */
    private static void zero(MemorySegment... segs)
    {
        for (MemorySegment seg : segs)
        {
            if (seg.address() != 0)
            {
                seg.fill((byte) 0);
            }
        }
    }

    /**
     * Copy rc bytes written at off back to the caller. A positive rc with no room at off is a size query, not a
     * write, so nothing is copied then; a negative rc wrote nothing.
     */
    private static void copyOutBack(int rc, MemorySegment output, byte[] out, int off)
    {
        if (out != null && rc > 0 && off >= 0 && off < out.length && rc <= out.length - off)
        {
            MemorySegment.copy(output, ValueLayout.JAVA_BYTE, off, out, off, rc);
        }
    }


    @Override
    public int ni_curveSupported(String curveName)
    {
        try (Arena a = Arena.ofConfined())
        {
            byte[] name = utf8(curveName);
            return (int) curveSupportedH.invokeExact(nameSeg(a, name), len(name));
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFM EC_curveSupported", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public long ni_generateKeyPair(String curveName, int[] err, RandSource rndSource)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment errSeg = a.allocate(ValueLayout.JAVA_INT);
            byte[] name = utf8(curveName);
            MemorySegment ref = (MemorySegment) generateKeyPairH.invokeExact(
                    nameSeg(a, name), len(name), errSeg, entropyStub(a, rndSource));
            err[0] = errSeg.get(ValueLayout.JAVA_INT, 0);
            return ref.address();
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFM EC_generateKeyPair", t);
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
            byte[] name = utf8(curveName);
            // Non-critical handle (the entropy upcall must run), so the scalar is copied into the arena.
            MemorySegment scalarSeg = copyIn(a, scalarBE);
            try
            {
                MemorySegment ref = (MemorySegment) makePrivateFromComponentsH.invokeExact(
                        nameSeg(a, name), len(name), scalarSeg, len(scalarBE),
                        errSeg, entropyStub(a, rndSource));
                err[0] = errSeg.get(ValueLayout.JAVA_INT, 0);
                return ref.address();
            }
            finally
            {
                // Arena.close() frees but does not cleanse: scrub the private scalar first.
                zero(scalarSeg);
            }
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFM EC_makePrivateFromComponents", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public long ni_makePublicFromComponents(String curveName, byte[] pointUncompressed,
                                            int[] err, RandSource rndSource)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment errSeg = a.allocate(ValueLayout.JAVA_INT);
            byte[] name = utf8(curveName);
            // Non-critical handle (the entropy upcall must run), so the point is copied into the arena; it is
            // public, so no scrub.
            MemorySegment ref = (MemorySegment) makePublicFromComponentsH.invokeExact(
                    nameSeg(a, name), len(name), copyIn(a, pointUncompressed), len(pointUncompressed),
                    errSeg, entropyStub(a, rndSource));
            err[0] = errSeg.get(ValueLayout.JAVA_INT, 0);
            return ref.address();
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFM EC_makePublicFromComponents", t);
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
            L.log(Level.WARNING, "FFM EC_getComponent", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_getCurveComponent(String curveName, int component, byte[] out)
    {
        try (Arena a = Arena.ofConfined())
        {
            byte[] name = utf8(curveName);
            MemorySegment outSeg = outSeg(a, out);
            int rc = (int) getCurveComponentH.invokeExact(nameSeg(a, name), len(name), component, outSeg, len(out));
            // A zero-length out is a size query: the C reports the length and writes nothing.
            copyOutBack(rc, outSeg, out, 0);
            return rc;
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFM EC_getCurveComponent", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_findCurveName(int fieldType, byte[] p, byte[] a, byte[] b,
                                byte[] gx, byte[] gy, byte[] order,
                                byte[] cofactor, byte[] out)
    {
        try (Arena arena = Arena.ofConfined())
        {
            // copyIn gives an empty input (a == 0 on secp256k1) a one-byte segment and a null input NULL, which
            // JoEC_findCurveName refuses with JO_INPUT_IS_NULL.
            MemorySegment outSeg = outSeg(arena, out);
            int written = (int) findCurveNameH.invokeExact(fieldType,
                    copyIn(arena, p), len(p),
                    copyIn(arena, a), len(a),
                    copyIn(arena, b), len(b),
                    copyIn(arena, gx), len(gx),
                    copyIn(arena, gy), len(gy),
                    copyIn(arena, order), len(order),
                    copyIn(arena, cofactor), len(cofactor),
                    outSeg, len(out));
            // A zero-length out is a size query: the C reports the length and writes nothing.
            copyOutBack(written, outSeg, out, 0);
            return written;
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFM EC_findCurveName", t);
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
            L.log(Level.WARNING, "FFM EC_allocateSigner", t);
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
            L.log(Level.WARNING, "FFM EC_disposeSigner", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_initSign(long ref, long keyRef, String digestName, RandSource rndSource)
    {
        try (Arena a = Arena.ofConfined())
        {
            byte[] digest = utf8(digestName);
            return (int) initSignH.invokeExact(
                    MemorySegment.ofAddress(ref),
                    MemorySegment.ofAddress(keyRef),
                    nameSeg(a, digest), len(digest),
                    entropyStub(a, rndSource));
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFM EC_initSign", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_initVerify(long ref, long keyRef, String digestName)
    {
        try (Arena a = Arena.ofConfined())
        {
            byte[] digest = utf8(digestName);
            return (int) initVerifyH.invokeExact(
                    MemorySegment.ofAddress(ref),
                    MemorySegment.ofAddress(keyRef),
                    nameSeg(a, digest), len(digest));
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFM EC_initVerify", t);
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
            L.log(Level.WARNING, "FFM EC_update", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_sign(long ref, byte[] sig, int outOff, RandSource rndSource)
    {
        try (Arena a = Arena.ofConfined())
        {
            // Non-critical handle (the entropy upcall must run): the signature is written into the arena and
            // copied back. A signature is not secret, so no scrub.
            MemorySegment sigSeg = outSeg(a, sig);
            int rc = (int) signH.invokeExact(MemorySegment.ofAddress(ref), sigSeg, len(sig), outOff,
                    entropyStub(a, rndSource));
            copyOutBack(rc, sigSeg, sig, outOff);
            return rc;
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFM EC_sign", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_verify(long ref, byte[] sig, int sigLen, RandSource rndSource)
    {
        try (Arena a = Arena.ofConfined())
        {
            // Non-critical handle (the entropy upcall must run), so the signature is copied into the arena.
            return (int) verifyH.invokeExact(MemorySegment.ofAddress(ref), copyIn(a, sig), len(sig), sigLen,
                    entropyStub(a, rndSource));
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFM EC_verify", t);
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
            L.log(Level.WARNING, "FFM EC_allocateKex", t);
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
            L.log(Level.WARNING, "FFM EC_disposeKex", t);
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
            L.log(Level.WARNING, "FFM EC_kexInit", t);
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
            L.log(Level.WARNING, "FFM EC_kexSetPeer", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_kexDerive(long ref, byte[] out, int outOff, RandSource rndSource)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment outSeg = outSeg(a, out);
            try
            {
                int rc = (int) kexDeriveH.invokeExact(MemorySegment.ofAddress(ref), outSeg, len(out), outOff,
                        entropyStub(a, rndSource));
                // outOff == out.length is a size query: the C reports the length and writes nothing.
                copyOutBack(rc, outSeg, out, outOff);
                return rc;
            }
            finally
            {
                // Arena.close() frees but does not cleanse: scrub the shared secret first.
                zero(outSeg);
            }
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFM EC_kexDerive", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }
}
