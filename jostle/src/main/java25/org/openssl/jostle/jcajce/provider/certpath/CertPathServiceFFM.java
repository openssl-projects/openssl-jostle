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

package org.openssl.jostle.jcajce.provider.certpath;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;

/**
 * FFM binding for {@code JoCertPath_verify}, exported by
 * {@code interface/nonfips/ffm/certpath_ni_ffm.c}.
 * <p>
 * No RandSource crosses here, so no upcall can occur and the call would be
 * eligible for {@code Linker.Option.critical}. It is not used: the entry point
 * writes several outputs, and confined-arena copies keep the marshalling the
 * same shape as every other bridge that has out-parameters. The policy tree
 * comes back as a native buffer, copied and freed here.
 */
public class CertPathServiceFFM implements CertPathNI
{
    private static final Linker linker = Linker.nativeLinker();

    private final MethodHandle verifyH;
    private final MethodHandle errorTextH;
    private final MethodHandle freeTreeH;

    public CertPathServiceFFM()
    {
        this(SymbolLookup.loaderLookup());
    }

    public CertPathServiceFFM(SymbolLookup lookup)
    {
        this(lookup, "");
    }

    /**
     * @param symPrefix prepended to every symbol name; empty for the base
     *                  library. Deliberately separate from {@code lookup}, per
     *                  {@code FIPSLibraryLookup} — two independent values mean
     *                  either mistake alone fails loudly.
     */
    public CertPathServiceFFM(SymbolLookup lookup, String symPrefix)
    {
        // int32_t JoCertPath_verify(const uint8_t*, int32_t, const int32_t*, int32_t,
        //                           int32_t, int32_t, int32_t, int64_t, int32_t, int32_t,
        //                           int32_t, const uint8_t*, int32_t, int32_t,
        //                           uint8_t*, int32_t, int32_t*, int32_t,
        //                           uint8_t**, int32_t*, int32_t)
        verifyH = linker.downcallHandle(
                lookup.find(symPrefix + "JoCertPath_verify").orElseThrow(),
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,      // return
                        ValueLayout.ADDRESS,       // der
                        ValueLayout.JAVA_INT,      // der_len
                        ValueLayout.ADDRESS,       // sizes
                        ValueLayout.JAVA_INT,      // sizes_len
                        ValueLayout.JAVA_INT,      // count
                        ValueLayout.JAVA_INT,      // crl_count
                        ValueLayout.JAVA_INT,      // anchor_count
                        ValueLayout.JAVA_LONG,     // time_secs
                        ValueLayout.JAVA_INT,      // strict
                        ValueLayout.JAVA_INT,      // revocation
                        ValueLayout.JAVA_INT,      // policy_flags
                        ValueLayout.ADDRESS,       // policies
                        ValueLayout.JAVA_INT,      // policies_len
                        ValueLayout.JAVA_INT,      // policy_count
                        ValueLayout.ADDRESS,       // chain_out
                        ValueLayout.JAVA_INT,      // chain_out_len
                        ValueLayout.ADDRESS,       // out_info
                        ValueLayout.JAVA_INT,      // out_info_len
                        ValueLayout.ADDRESS,       // tree_out
                        ValueLayout.ADDRESS,       // tree_len
                        ValueLayout.JAVA_INT));    // tree_slots

        // const char *JoCertPath_errorText(int32_t)
        errorTextH = linker.downcallHandle(
                lookup.find(symPrefix + "JoCertPath_errorText").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.JAVA_INT));

        // void JoCertPath_freeTree(uint8_t*)
        freeTreeH = linker.downcallHandle(
                lookup.find(symPrefix + "JoCertPath_freeTree").orElseThrow(),
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));
    }

    @Override
    public int ni_verify(byte[] der, int[] sizes, int count, int crlCount, int anchorCount,
                         long timeSecs, int strict, int revocation,
                         int policyFlags, byte[] policies, int policyCount,
                         byte[] chainOut, int[] outInfo, byte[][] treeOut)
    {
        try (Arena arena = Arena.ofConfined())
        {
            // A null array travels as MemorySegment.NULL with a zero length,
            // so the refusal is C's and both bridges answer the same code:
            // JoCertPath_verify takes der first (JO_INPUT_IS_NULL), then the
            // three output arrays together (JO_OUTPUT_IS_NULL).
            MemorySegment derSeg = der == null
                    ? MemorySegment.NULL : arena.allocateFrom(ValueLayout.JAVA_BYTE, der);
            MemorySegment sizesSeg = sizes == null
                    ? MemorySegment.NULL : arena.allocateFrom(ValueLayout.JAVA_INT, sizes);
            MemorySegment policiesSeg = policies == null
                    ? MemorySegment.NULL : arena.allocateFrom(ValueLayout.JAVA_BYTE, policies);
            MemorySegment chainSeg = chainOut == null
                    ? MemorySegment.NULL : arena.allocate(Math.max(chainOut.length, 1));
            // outInfo is copied IN as well as back, so the entries C does not
            // write keep the caller's values, as on the JNI twin.
            MemorySegment infoSeg = outInfo == null
                    ? MemorySegment.NULL
                    : outInfo.length == 0
                    ? arena.allocate(ValueLayout.JAVA_INT, 1)
                    : arena.allocateFrom(ValueLayout.JAVA_INT, outInfo);
            // The tree comes back as a native buffer and its length, through two cells.
            MemorySegment treeSeg = treeOut == null ? MemorySegment.NULL : arena.allocate(ValueLayout.ADDRESS);
            MemorySegment treeLenSeg = treeOut == null ? MemorySegment.NULL : arena.allocate(ValueLayout.JAVA_INT);

            int rc = (int) verifyH.invokeExact(derSeg, der == null ? 0 : der.length,
                    sizesSeg, sizes == null ? 0 : sizes.length,
                    count, crlCount, anchorCount, timeSecs, strict, revocation,
                    policyFlags, policiesSeg, policies == null ? 0 : policies.length, policyCount,
                    chainSeg, chainOut == null ? 0 : chainOut.length,
                    infoSeg, outInfo == null ? 0 : outInfo.length,
                    treeSeg, treeLenSeg, treeOut == null ? 0 : treeOut.length);

            // outInfo comes back on the failure paths too: the decode failure
            // reports WHICH certificate in it. Only the chain is success-only.
            if (outInfo != null)
            {
                MemorySegment.copy(infoSeg, ValueLayout.JAVA_INT, 0, outInfo, 0, outInfo.length);
            }
            if (rc == 0 && chainOut != null)
            {
                MemorySegment.copy(chainSeg, ValueLayout.JAVA_BYTE, 0, chainOut, 0, chainOut.length);
            }
            if (rc == 0 && treeOut != null)
            {
                MemorySegment tree = treeSeg.get(ValueLayout.ADDRESS, 0);
                try
                {
                    if (tree.address() != 0)
                    {
                        int len = treeLenSeg.get(ValueLayout.JAVA_INT, 0);
                        treeOut[0] = tree.reinterpret(len).toArray(ValueLayout.JAVA_BYTE);
                    }
                }
                finally
                {
                    freeTreeH.invokeExact(tree);
                }
            }
            return rc;
        }
        catch (Throwable t)
        {
            throw new RuntimeException("JoCertPath_verify failed", t);
        }
    }

    @Override
    public String ni_errorText(int error)
    {
        try
        {
            MemorySegment text = (MemorySegment) errorTextH.invokeExact(error);
            return text.reinterpret(Long.MAX_VALUE).getString(0);
        }
        catch (Throwable t)
        {
            throw new RuntimeException("JoCertPath_errorText failed", t);
        }
    }
}
