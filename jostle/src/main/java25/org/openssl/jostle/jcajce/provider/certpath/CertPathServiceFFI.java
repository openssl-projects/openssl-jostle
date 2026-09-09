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
 * FFI binding for {@code JoCertPath_verify}, exported by
 * {@code interface/nonfips/ffi/certpath_ni_ffi.c}.
 * <p>
 * No RandSource crosses here, so no upcall can occur and the call would be
 * eligible for {@code Linker.Option.critical}. It is not used: the entry point
 * writes two output arrays, and confined-arena copies keep the marshalling the
 * same shape as every other bridge that has out-parameters.
 */
public class CertPathServiceFFI implements CertPathNI
{
    private static final Linker linker = Linker.nativeLinker();

    private final MethodHandle verifyH;

    public CertPathServiceFFI()
    {
        this(SymbolLookup.loaderLookup());
    }

    public CertPathServiceFFI(SymbolLookup lookup)
    {
        this(lookup, "");
    }

    /**
     * @param symPrefix prepended to every symbol name; empty for the base
     *                  library. Deliberately separate from {@code lookup}, per
     *                  {@code FIPSLibraryLookup} — two independent values mean
     *                  either mistake alone fails loudly.
     */
    public CertPathServiceFFI(SymbolLookup lookup, String symPrefix)
    {
        // int32_t JoCertPath_verify(const uint8_t*, int32_t, const int32_t*, int32_t,
        //                           int32_t, int32_t, int64_t, int32_t,
        //                           uint8_t*, int32_t, int32_t*, int32_t)
        verifyH = linker.downcallHandle(
                lookup.find(symPrefix + "JoCertPath_verify").orElseThrow(),
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,      // return
                        ValueLayout.ADDRESS,       // der
                        ValueLayout.JAVA_INT,      // der_len
                        ValueLayout.ADDRESS,       // sizes
                        ValueLayout.JAVA_INT,      // sizes_len
                        ValueLayout.JAVA_INT,      // count
                        ValueLayout.JAVA_INT,      // anchor_count
                        ValueLayout.JAVA_LONG,     // time_secs
                        ValueLayout.JAVA_INT,      // strict
                        ValueLayout.ADDRESS,       // chain_out
                        ValueLayout.JAVA_INT,      // chain_out_len
                        ValueLayout.ADDRESS,       // out_info
                        ValueLayout.JAVA_INT));    // out_info_len
    }

    @Override
    public int ni_verify(byte[] der, int[] sizes, int count, int anchorCount,
                         long timeSecs, int strict, byte[] chainOut, int[] outInfo)
    {
        // A null array cannot become a MemorySegment, and MemorySegment.ofArray
        // would NPE and surface as a bare RuntimeException — the shape the FFI
        // bridge was corrected for once already. Refuse with the code the JNI
        // bridge returns for the same input.
        if (der == null)
        {
            return org.openssl.jostle.jcajce.provider.ErrorCode.JO_INPUT_IS_NULL.getCode();
        }
        if (sizes == null || outInfo == null || chainOut == null)
        {
            return org.openssl.jostle.jcajce.provider.ErrorCode.JO_OUTPUT_IS_NULL.getCode();
        }

        try (Arena arena = Arena.ofConfined())
        {
            MemorySegment derSeg = arena.allocateFrom(ValueLayout.JAVA_BYTE, der);
            MemorySegment sizesSeg = arena.allocateFrom(ValueLayout.JAVA_INT, sizes);
            MemorySegment chainSeg = arena.allocate(Math.max(chainOut.length, 1));
            MemorySegment infoSeg = arena.allocate(ValueLayout.JAVA_INT, Math.max(outInfo.length, 1));

            int rc = (int) verifyH.invokeExact(derSeg, der.length,
                    sizesSeg, sizes.length,
                    count, anchorCount, timeSecs, strict,
                    chainSeg, chainOut.length,
                    infoSeg, outInfo.length);

            // outInfo comes back on the failure paths too: the decode failure
            // reports WHICH certificate in it, and returning rc alone would
            // lose that. Only the chain is success-only.
            MemorySegment.copy(infoSeg, ValueLayout.JAVA_INT, 0, outInfo, 0, outInfo.length);
            if (rc == 0)
            {
                MemorySegment.copy(chainSeg, ValueLayout.JAVA_BYTE, 0, chainOut, 0, chainOut.length);
            }
            return rc;
        }
        catch (Throwable t)
        {
            throw new RuntimeException("JoCertPath_verify failed", t);
        }
    }
}
