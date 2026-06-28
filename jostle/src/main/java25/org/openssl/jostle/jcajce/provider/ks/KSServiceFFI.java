/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.ks;

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

import org.openssl.jostle.rand.RandSource;

public class KSServiceFFI
    implements KSServiceNI
{
    private static final Logger L = Logger.getLogger("KS_NI_FFI");
    private static final SymbolLookup lookup = SymbolLookup.loaderLookup();
    private static final Linker linker = Linker.nativeLinker();

    private static final MethodHandle allocateH = linker.downcallHandle(
            lookup.find("JoKS_Allocate").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS),
            Linker.Option.critical(true));
    private static final MethodHandle disposeH = linker.downcallHandle(
            lookup.find("JoKS_Dispose").orElseThrow(),
            FunctionDescriptor.ofVoid(ValueLayout.ADDRESS),
            Linker.Option.critical(true));
    private static final MethodHandle loadH = linker.downcallHandle(
            lookup.find("JoKS_Load").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG),
            Linker.Option.critical(true));
    // storeLenH / storeH are deliberately NOT critical: ks_store generates
    // PKCS#12 salts via the Jostle lib ctx, which up-calls Java for entropy --
    // forbidden from a critical downcall. Buffers are passed off-heap (see
    // ni_store), and the trailing ADDRESS before output/err is the entropy
    // upcall stub.
    private static final MethodHandle storeLenH = linker.downcallHandle(
            lookup.find("JoKS_StoreLen").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
                    ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT,
                    ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    private static final MethodHandle storeH = linker.downcallHandle(
            lookup.find("JoKS_Store").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
                    ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT,
                    ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));
    private static final FunctionDescriptor entropyFd = FunctionDescriptor.of(
            ValueLayout.JAVA_INT,
            ValueLayout.ADDRESS.withTargetLayout(ValueLayout.JAVA_BYTE),
            ValueLayout.JAVA_INT,
            ValueLayout.JAVA_INT,
            ValueLayout.JAVA_BOOLEAN);
    private static final MethodType entropyMt = MethodType.methodType(
            int.class, MemorySegment.class, int.class, int.class, boolean.class);
    private static final MethodHandle getKeyLenH = linker.downcallHandle(
            lookup.find("JoKS_GetKeyLen").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS),
            Linker.Option.critical(true));
    private static final MethodHandle getKeyH = linker.downcallHandle(
            lookup.find("JoKS_GetKey").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG),
            Linker.Option.critical(true));
    private static final MethodHandle setKeyH = linker.downcallHandle(
            lookup.find("JoKS_SetKey").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG),
            Linker.Option.critical(true));
    private static final MethodHandle getCertificateChainLenH = linker.downcallHandle(
            lookup.find("JoKS_GetCertificateChainLen").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS),
            Linker.Option.critical(true));
    private static final MethodHandle getCertificateChainH = linker.downcallHandle(
            lookup.find("JoKS_GetCertificateChain").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG),
            Linker.Option.critical(true));
    private static final MethodHandle setCertificateChainH = linker.downcallHandle(
            lookup.find("JoKS_SetCertificateChain").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG),
            Linker.Option.critical(true));
    private static final MethodHandle setCertificateEntryH = linker.downcallHandle(
            lookup.find("JoKS_SetCertificateEntry").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG),
            Linker.Option.critical(true));
    private static final MethodHandle deleteEntryH = linker.downcallHandle(
            lookup.find("JoKS_DeleteEntry").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS),
            Linker.Option.critical(true));
    private static final MethodHandle getAliasesLenH = linker.downcallHandle(
            lookup.find("JoKS_GetAliasesLen").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS),
            Linker.Option.critical(true));
    private static final MethodHandle getAliasesH = linker.downcallHandle(
            lookup.find("JoKS_GetAliases").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG),
            Linker.Option.critical(true));
    private static final MethodHandle containsAliasH = linker.downcallHandle(
            lookup.find("JoKS_ContainsAlias").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS),
            Linker.Option.critical(true));
    private static final MethodHandle sizeH = linker.downcallHandle(
            lookup.find("JoKS_Size").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS),
            Linker.Option.critical(true));
    private static final MethodHandle isKeyEntryH = linker.downcallHandle(
            lookup.find("JoKS_IsKeyEntry").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS),
            Linker.Option.critical(true));
    private static final MethodHandle isCertificateEntryH = linker.downcallHandle(
            lookup.find("JoKS_IsCertificateEntry").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS),
            Linker.Option.critical(true));
    private static final MethodHandle getCreationDateH = linker.downcallHandle(
            lookup.find("JoKS_GetCreationDate").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS),
            Linker.Option.critical(true));

    @Override
    public long ni_allocateKeyStore(String type, int[] err)
    {
        try (Arena arena = Arena.ofConfined())
        {
            MemorySegment typeSeg = type == null ? MemorySegment.NULL : arena.allocateFrom(type);
            MemorySegment errSeg = errSegment(err);
            MemorySegment ctx = (MemorySegment) allocateH.invokeExact(typeSeg, errSeg);
            return ctx.address();
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI JoKS_Allocate", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public void ni_dispose(long ref)
    {
        try
        {
            disposeH.invokeExact(MemorySegment.ofAddress(ref));
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI JoKS_Dispose", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_load(long ref, byte[] input, byte[] password)
    {
        try
        {
            MemorySegment inputSeg = input == null ? MemorySegment.NULL : MemorySegment.ofArray(input);
            MemorySegment passwordSeg = password == null ? MemorySegment.NULL : MemorySegment.ofArray(password);
            return (int) loadH.invokeExact(MemorySegment.ofAddress(ref),
                    inputSeg, inputSeg.byteSize(), passwordSeg, passwordSeg.byteSize());
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI JoKS_Load", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public byte[] ni_store(long ref, byte[] password, int keyPbe, int certPbe, int macScheme,
                           int macDigest, int pbeIter, int macIter, int[] err, RandSource randSource)
    {
        // Non-critical downcalls (ks_store up-calls Java for entropy), so every
        // buffer is passed off-heap from a confined arena.
        try (Arena a = Arena.ofConfined())
        {
            MemorySegment passwordSeg = (password == null || password.length == 0)
                    ? MemorySegment.NULL : a.allocate(password.length);
            MemorySegment outSeg = MemorySegment.NULL;
            try
            {
                if (password != null && password.length > 0)
                {
                    passwordSeg.asByteBuffer().put(password);
                }
                MemorySegment errSeg = a.allocate(ValueLayout.JAVA_INT);

                MemorySegment randSeg;
                if (randSource == null)
                {
                    randSeg = MemorySegment.NULL;
                }
                else
                {
                    var gHandle = MethodHandles.lookup().findVirtual(
                            randSource.getClass(), "getRandomSegment", entropyMt).bindTo(randSource);
                    randSeg = linker.upcallStub(gHandle, entropyFd, a);
                }

                MemorySegment ctx = MemorySegment.ofAddress(ref);
                int len = (int) storeLenH.invokeExact(ctx, passwordSeg, passwordSeg.byteSize(),
                        keyPbe, certPbe, macScheme, macDigest, pbeIter, macIter, randSeg, errSeg);
                err[0] = errSeg.get(ValueLayout.JAVA_INT, 0);
                if (err[0] != 0 || len == 0)
                {
                    return null;
                }

                outSeg = a.allocate(len);
                err[0] = (int) storeH.invokeExact(ctx, passwordSeg, passwordSeg.byteSize(),
                        keyPbe, certPbe, macScheme, macDigest, pbeIter, macIter, randSeg, outSeg, outSeg.byteSize());
                if (err[0] != 0)
                {
                    return null;
                }
                byte[] out = new byte[len];
                outSeg.asByteBuffer().get(out);
                return out;
            }
            finally
            {
                // Arena.close() frees but does NOT cleanse the backing memory.
                // Scrub the plaintext store password (and the serialized
                // keystore, which contains the shrouded key) from the off-heap
                // segments before the arena releases them. Any future non-critical
                // FFI downcall that copies secret material into an Arena must do
                // the same fill-before-close.
                if (passwordSeg.byteSize() > 0)
                {
                    passwordSeg.fill((byte) 0);
                }
                if (outSeg.byteSize() > 0)
                {
                    outSeg.fill((byte) 0);
                }
            }
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI JoKS_Store", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public byte[] ni_getKey(long ref, String alias, byte[] password, int[] err)
    {
        try (Arena arena = Arena.ofConfined())
        {
            MemorySegment aliasSeg = alias == null ? MemorySegment.NULL : arena.allocateFrom(alias);
            MemorySegment passwordSeg = password == null ? MemorySegment.NULL : MemorySegment.ofArray(password);
            MemorySegment errSeg = errSegment(err);
            MemorySegment ctx = MemorySegment.ofAddress(ref);
            int len = (int) getKeyLenH.invokeExact(ctx, aliasSeg,
                    passwordSeg, passwordSeg.byteSize(), errSeg);
            if (err[0] != 0 || len == 0)
            {
                return null;
            }

            byte[] key = new byte[len];
            MemorySegment keySeg = MemorySegment.ofArray(key);
            err[0] = (int) getKeyH.invokeExact(ctx, aliasSeg,
                    passwordSeg, passwordSeg.byteSize(), keySeg, keySeg.byteSize());
            return err[0] == 0 ? key : null;
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI JoKS_GetKey", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_setKey(long ref, String alias, byte[] key, byte[] password)
    {
        try (Arena arena = Arena.ofConfined())
        {
            MemorySegment aliasSeg = alias == null ? MemorySegment.NULL : arena.allocateFrom(alias);
            MemorySegment keySeg = key == null ? MemorySegment.NULL : MemorySegment.ofArray(key);
            MemorySegment passwordSeg = password == null ? MemorySegment.NULL : MemorySegment.ofArray(password);
            return (int) setKeyH.invokeExact(MemorySegment.ofAddress(ref),
                    aliasSeg, keySeg, keySeg.byteSize(),
                    passwordSeg, passwordSeg.byteSize());
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI JoKS_SetKey", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public byte[] ni_getCertificateChain(long ref, String alias, int[] err)
    {
        try (Arena arena = Arena.ofConfined())
        {
            MemorySegment aliasSeg = alias == null ? MemorySegment.NULL : arena.allocateFrom(alias);
            MemorySegment errSeg = errSegment(err);
            MemorySegment ctx = MemorySegment.ofAddress(ref);
            int len = (int) getCertificateChainLenH.invokeExact(ctx, aliasSeg, errSeg);
            if (err[0] != 0 || len == 0)
            {
                return null;
            }

            byte[] chain = new byte[len];
            MemorySegment chainSeg = MemorySegment.ofArray(chain);
            err[0] = (int) getCertificateChainH.invokeExact(ctx, aliasSeg, chainSeg, chainSeg.byteSize());
            return err[0] == 0 ? chain : null;
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI JoKS_GetCertificateChain", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_setCertificateChain(long ref, String alias, byte[] chain)
    {
        try (Arena arena = Arena.ofConfined())
        {
            MemorySegment aliasSeg = alias == null ? MemorySegment.NULL : arena.allocateFrom(alias);
            MemorySegment chainSeg = chain == null ? MemorySegment.NULL : MemorySegment.ofArray(chain);
            return (int) setCertificateChainH.invokeExact(MemorySegment.ofAddress(ref), aliasSeg, chainSeg, chainSeg.byteSize());
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI JoKS_SetCertificateChain", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_setCertificateEntry(long ref, String alias, byte[] certificate)
    {
        try (Arena arena = Arena.ofConfined())
        {
            MemorySegment aliasSeg = alias == null ? MemorySegment.NULL : arena.allocateFrom(alias);
            MemorySegment certificateSeg = certificate == null ? MemorySegment.NULL : MemorySegment.ofArray(certificate);
            return (int) setCertificateEntryH.invokeExact(MemorySegment.ofAddress(ref),
                    aliasSeg, certificateSeg, certificateSeg.byteSize());
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI JoKS_SetCertificateEntry", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_deleteEntry(long ref, String alias)
    {
        try (Arena arena = Arena.ofConfined())
        {
            MemorySegment aliasSeg = alias == null ? MemorySegment.NULL : arena.allocateFrom(alias);
            return (int) deleteEntryH.invokeExact(MemorySegment.ofAddress(ref), aliasSeg);
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI JoKS_DeleteEntry", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public byte[] ni_getAliases(long ref, int[] err)
    {
        try
        {
            MemorySegment errSeg = errSegment(err);
            MemorySegment ctx = MemorySegment.ofAddress(ref);
            int len = (int) getAliasesLenH.invokeExact(ctx, errSeg);
            if (err[0] != 0 || len == 0)
            {
                return null;
            }

            byte[] aliases = new byte[len];
            MemorySegment aliasesSeg = MemorySegment.ofArray(aliases);
            err[0] = (int) getAliasesH.invokeExact(ctx, aliasesSeg, aliasesSeg.byteSize());
            return err[0] == 0 ? aliases : null;
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI JoKS_GetAliases", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_containsAlias(long ref, String alias)
    {
        try (Arena arena = Arena.ofConfined())
        {
            MemorySegment aliasSeg = alias == null ? MemorySegment.NULL : arena.allocateFrom(alias);
            return (int) containsAliasH.invokeExact(MemorySegment.ofAddress(ref), aliasSeg);
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI JoKS_ContainsAlias", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_size(long ref)
    {
        try
        {
            return (int) sizeH.invokeExact(MemorySegment.ofAddress(ref));
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI JoKS_Size", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_isKeyEntry(long ref, String alias)
    {
        try (Arena arena = Arena.ofConfined())
        {
            MemorySegment aliasSeg = alias == null ? MemorySegment.NULL : arena.allocateFrom(alias);
            return (int) isKeyEntryH.invokeExact(MemorySegment.ofAddress(ref), aliasSeg);
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI JoKS_IsKeyEntry", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public int ni_isCertificateEntry(long ref, String alias)
    {
        try (Arena arena = Arena.ofConfined())
        {
            MemorySegment aliasSeg = alias == null ? MemorySegment.NULL : arena.allocateFrom(alias);
            return (int) isCertificateEntryH.invokeExact(MemorySegment.ofAddress(ref), aliasSeg);
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI JoKS_IsCertificateEntry", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    @Override
    public long ni_getCreationDate(long ref, String alias, int[] err)
    {
        try (Arena arena = Arena.ofConfined())
        {
            MemorySegment aliasSeg = alias == null ? MemorySegment.NULL : arena.allocateFrom(alias);
            MemorySegment errSeg = errSegment(err);
            return (long) getCreationDateH.invokeExact(MemorySegment.ofAddress(ref), aliasSeg, errSeg);
        }
        catch (Throwable t)
        {
            L.log(Level.WARNING, "FFI JoKS_GetCreationDate", t);
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    private static MemorySegment errSegment(int[] err)
    {
        if (err == null || err.length == 0)
        {
            throw new NullPointerException("error array must not be null or empty");
        }
        return MemorySegment.ofArray(err);
    }
}
