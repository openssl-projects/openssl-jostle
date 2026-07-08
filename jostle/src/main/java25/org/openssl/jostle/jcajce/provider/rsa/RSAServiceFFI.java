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

package org.openssl.jostle.jcajce.provider.rsa;

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
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * FFI binding for the {@code RSA_*} symbols exported by
 * {@code interface/nonfips/ffi/rsa_ni_ffi.c}. Mirrors the structure of
 * {@link org.openssl.jostle.jcajce.provider.ed.EdDSAServiceFFI};
 * each native call is wrapped to translate Java byte[]/String into
 * MemorySegments and convert the entropy upcall.
 */
// Symbol resolution is parameterised by a SymbolLookup so the same
// marshalling serves both interface libraries (see MDServiceFFI).
public class RSAServiceFFI implements RSAServiceNI
{
    private static final Logger L = Logger.getLogger("RSA_NI_FFI");
    private static final Linker linker = Linker.nativeLinker();

    // ---- function handles ----
    private final MethodHandle allocSignerH;
    private final MethodHandle disposeSignerH;
    private final MethodHandle generateKeyPairH;
    private final MethodHandle decodePublicComponentsH;
    private final MethodHandle decodePrivateComponentsH;
    private final MethodHandle decodePrivateComponentsCrtH;
    private final MethodHandle getComponentH;
    private final MethodHandle initSignH;
    private final MethodHandle initVerifyH;
    private final MethodHandle updateH;
    private final MethodHandle signH;
    private final MethodHandle verifyH;

    // Entropy upcall stub descriptor (shared with EdDSA's pattern).
    // Lookup-independent constants for the RandSource entropy upcall stub.
    private static final FunctionDescriptor entropyFd = FunctionDescriptor.of(
            ValueLayout.JAVA_INT,
            ValueLayout.ADDRESS.withTargetLayout(ValueLayout.JAVA_BYTE),
            ValueLayout.JAVA_INT,
            ValueLayout.JAVA_INT,
            ValueLayout.JAVA_BOOLEAN);
    private static final MethodType entropyMt = MethodType.methodType(
            int.class,
            MemorySegment.class,
            int.class,
            int.class,
            boolean.class);


    public RSAServiceFFI()
    {
        this(SymbolLookup.loaderLookup());
    }

    public RSAServiceFFI(SymbolLookup lookup)
    {
        allocSignerH = bind(lookup, "JoRSA_allocateSigner",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));

        disposeSignerH = linker.downcallHandle(
                lookup.find("JoRSA_disposeSigner").orElseThrow(),
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));

        // RSA_generateKeyPair(int bits, uint8_t* pubexp, size_t pubexp_len,
        //                    int32_t* err, void* rnd_src) -> key_spec*
        generateKeyPairH = bind(lookup, "JoRSA_generateKeyPair",
                FunctionDescriptor.of(
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_INT,    // bits
                        ValueLayout.ADDRESS,     // pubexp ptr
                        ValueLayout.JAVA_LONG,   // pubexp_len
                        ValueLayout.ADDRESS,     // err out
                        ValueLayout.ADDRESS));   // rnd_src upcall

        decodePublicComponentsH = bind(lookup, "JoRSA_decodePublicComponents",
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_LONG),
                /* critical */ true);

        decodePrivateComponentsH = bind(lookup, "JoRSA_decodePrivateComponents",
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_LONG),
                /* critical */ true);

        // 8 (ptr,len) pairs after the spec pointer.
        decodePrivateComponentsCrtH = bind(lookup, "JoRSA_decodePrivateComponentsCrt",
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_LONG),
                /* critical */ true);

        // RSA_getComponent(key_spec*, int32_t component, uint8_t* out, size_t out_len)
        getComponentH = bind(lookup, "JoRSA_getComponent",
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG),
                /* critical */ true);

        // RSA_initSign(rsa_ctx*, key_spec*, const char* digest, int padding,
        //              const char* mgf1, int salt_len, void* rnd_src)
        initSignH = bind(lookup, "JoRSA_initSign",
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,    // ctx
                        ValueLayout.ADDRESS,    // key
                        ValueLayout.ADDRESS,    // digest_name
                        ValueLayout.JAVA_INT,   // padding_mode
                        ValueLayout.ADDRESS,    // mgf1_md_name (nullable)
                        ValueLayout.JAVA_INT,   // salt_len
                        ValueLayout.ADDRESS));  // rnd_src upcall

        initVerifyH = bind(lookup, "JoRSA_initVerify",
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_INT));

        // RSA_update(rsa_ctx*, uint8_t* in, size_t in_size, int in_off, int in_len)
        updateH = bind(lookup, "JoRSA_update",
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_INT),
                /* critical */ true);

        // RSA_sign(rsa_ctx*, uint8_t* out, size_t out_size, int out_off, void* rnd_src)
        signH = bind(lookup, "JoRSA_sign",
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS));

        // RSA_verify(rsa_ctx*, uint8_t* sig, size_t sig_size, int sig_len)
        verifyH = bind(lookup, "JoRSA_verify",
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.JAVA_INT),
                /* critical */ true);

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

    /**
     * Build a per-call entropy upcall stub bound to the given RandSource.
     * Returns MemorySegment.NULL when the source is null — the native side
     * detects that and surfaces JO_RAND_NO_RAND_UP_CALL.
     */
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


    // ===============================================================
    // Lifecycle
    // ===============================================================

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
            L.log(Level.WARNING, "FFI RSA_allocateSigner", t);
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
            L.log(Level.WARNING, "FFI RSA_disposeSigner", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }


    // ===============================================================
    // Key generation
    // ===============================================================

    @Override
    public long ni_generateKeyPair(int bits, byte[] pubExp, int[] err, RandSource rndSource)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment errSeg = a.allocate(ValueLayout.JAVA_INT);
            // generateKeyPair is non-critical (entropy upcall); heap segments
            // are forbidden, so allocate a native copy of pubExp.
            MemorySegment pubExpSeg;
            long pubExpLen;
            if (pubExp == null)
            {
                pubExpSeg = MemorySegment.NULL;
                pubExpLen = 0L;
            }
            else
            {
                pubExpSeg = a.allocate(pubExp.length);
                pubExpSeg.asByteBuffer().put(pubExp);
                pubExpLen = pubExp.length;
            }

            MemorySegment ref = (MemorySegment) generateKeyPairH.invokeExact(
                    bits, pubExpSeg, pubExpLen, errSeg, entropyStub(a, rndSource));

            err[0] = errSeg.get(ValueLayout.JAVA_INT, 0);
            return ref.address();
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI RSA_generateKeyPair", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }


    // ===============================================================
    // Component-based decoding
    // ===============================================================

    @Override
    public int ni_decodePublicComponents(long specRef, byte[] n, byte[] e)
    {
        try
        {
            MemorySegment spec = MemorySegment.ofAddress(specRef);
            MemorySegment nSeg = arrayOrNull(n);
            MemorySegment eSeg = arrayOrNull(e);
            return (int) decodePublicComponentsH.invokeExact(spec,
                    nSeg, nSeg.byteSize(),
                    eSeg, eSeg.byteSize());
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI RSA_decodePublicComponents", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_decodePrivateComponents(long specRef, byte[] n, byte[] e, byte[] d)
    {
        try
        {
            MemorySegment spec = MemorySegment.ofAddress(specRef);
            MemorySegment nSeg = arrayOrNull(n);
            MemorySegment eSeg = arrayOrNull(e);
            MemorySegment dSeg = arrayOrNull(d);
            return (int) decodePrivateComponentsH.invokeExact(spec,
                    nSeg, nSeg.byteSize(),
                    eSeg, eSeg.byteSize(),
                    dSeg, dSeg.byteSize());
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI RSA_decodePrivateComponents", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_decodePrivateComponentsCrt(long specRef,
                                             byte[] n, byte[] e, byte[] d,
                                             byte[] p, byte[] q,
                                             byte[] dp, byte[] dq, byte[] qinv)
    {
        try
        {
            MemorySegment spec = MemorySegment.ofAddress(specRef);
            MemorySegment nS = arrayOrNull(n),    eS = arrayOrNull(e),    dS = arrayOrNull(d);
            MemorySegment pS = arrayOrNull(p),    qS = arrayOrNull(q);
            MemorySegment dpS = arrayOrNull(dp),  dqS = arrayOrNull(dq),  qiS = arrayOrNull(qinv);
            return (int) decodePrivateComponentsCrtH.invokeExact(spec,
                    nS,  nS.byteSize(),
                    eS,  eS.byteSize(),
                    dS,  dS.byteSize(),
                    pS,  pS.byteSize(),
                    qS,  qS.byteSize(),
                    dpS, dpS.byteSize(),
                    dqS, dqS.byteSize(),
                    qiS, qiS.byteSize());
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI RSA_decodePrivateComponentsCrt", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }


    // ===============================================================
    // Component getter
    // ===============================================================

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
            L.log(Level.WARNING, "FFI RSA_getComponent", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }


    // ===============================================================
    // Sign / verify session
    // ===============================================================

    @Override
    public int ni_initSign(long ref, long keyRef, String digestName,
                           int paddingMode, String mgf1MdName, int saltLen,
                           RandSource rndSource)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment ctx = MemorySegment.ofAddress(ref);
            MemorySegment key = MemorySegment.ofAddress(keyRef);
            MemorySegment digestSeg = digestName == null ? MemorySegment.NULL : a.allocateFrom(digestName);
            MemorySegment mgfSeg = mgf1MdName == null ? MemorySegment.NULL : a.allocateFrom(mgf1MdName);

            return (int) initSignH.invokeExact(ctx, key,
                    digestSeg, paddingMode,
                    mgfSeg, saltLen,
                    entropyStub(a, rndSource));
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI RSA_initSign", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_initVerify(long ref, long keyRef, String digestName,
                             int paddingMode, String mgf1MdName, int saltLen)
    {
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment ctx = MemorySegment.ofAddress(ref);
            MemorySegment key = MemorySegment.ofAddress(keyRef);
            MemorySegment digestSeg = digestName == null ? MemorySegment.NULL : a.allocateFrom(digestName);
            MemorySegment mgfSeg = mgf1MdName == null ? MemorySegment.NULL : a.allocateFrom(mgf1MdName);

            return (int) initVerifyH.invokeExact(ctx, key,
                    digestSeg, paddingMode,
                    mgfSeg, saltLen);
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI RSA_initVerify", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_update(long ref, byte[] input, int inOff, int inLen)
    {
        try
        {
            MemorySegment ctx = MemorySegment.ofAddress(ref);
            MemorySegment inSeg = arrayOrNull(input);
            return (int) updateH.invokeExact(ctx, inSeg, inSeg.byteSize(), inOff, inLen);
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI RSA_update", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_sign(long ref, byte[] sig, int outOff, RandSource rndSource)
    {
        // sign is two-phase: first call with sig=null returns required size,
        // second call writes. We allocate a transient buffer via the Arena
        // when sig is non-null to keep the FFI side from needing to know
        // about Java byte[] layouts (matches EdDSA's pattern).
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment ctx = MemorySegment.ofAddress(ref);
            MemorySegment outSeg;
            long outSize;
            if (sig == null)
            {
                outSeg = MemorySegment.NULL;
                outSize = 0L;
            }
            else
            {
                outSeg = a.allocate(sig.length);
                outSize = outSeg.byteSize();
            }

            int code = (int) signH.invokeExact(ctx, outSeg, outSize, outOff,
                    entropyStub(a, rndSource));

            // Copy back only the bytes the C side actually wrote, at
            // their original offset. A blanket get(sig) would clobber
            // caller-provided bytes preceding outOff.
            if (sig != null && code > 0)
            {
                outSeg.asByteBuffer().get(outOff, sig, outOff, code);
            }
            return code;
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI RSA_sign", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_verify(long ref, byte[] sig, int sigLen)
    {
        try
        {
            MemorySegment ctx = MemorySegment.ofAddress(ref);
            MemorySegment sigSeg = arrayOrNull(sig);
            return (int) verifyH.invokeExact(ctx, sigSeg, sigSeg.byteSize(), sigLen);
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI RSA_verify", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }


    private static MemorySegment arrayOrNull(byte[] a)
    {
        return a == null ? MemorySegment.NULL : MemorySegment.ofArray(a);
    }
}
