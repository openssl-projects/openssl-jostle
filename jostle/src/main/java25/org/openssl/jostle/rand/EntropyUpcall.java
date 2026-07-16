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

package org.openssl.jostle.rand;

import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodType;

/**
 * Single source of truth for the {@link RandSource} entropy up-call ABI shared
 * by every FFI service class.
 *
 * <p>Each {@code *ServiceFFI} used to declare its own {@code entropyFd} /
 * {@code entropyMt} copies; they drifted (some declared the {@code out} pointer
 * as a bare {@code ADDRESS}, others as
 * {@code ADDRESS.withTargetLayout(JAVA_BYTE)} — functionally identical for this
 * up-call, since {@link RandSource#getRandomSegment} reinterprets the segment,
 * but a drift surface all the same). Centralising them here removes that.
 *
 * <p>Mirrors the C typedef {@code ffi_get_rand} in {@code rand_upcall_ffi.h}:
 * {@code int32_t (*)(uint8_t *out, size_t len, int32_t strength, int32_t predictionResistance)}.
 * Java-25 only (FFI), so it lives alongside the Java-25 {@code RandSource}
 * override.
 */
public final class EntropyUpcall
{
    private EntropyUpcall()
    {
    }

    /** Native function signature of {@link RandSource#getRandomSegment}. */
    public static final FunctionDescriptor DESCRIPTOR = FunctionDescriptor.of(
            ValueLayout.JAVA_INT,                                        // return code
            ValueLayout.ADDRESS.withTargetLayout(ValueLayout.JAVA_BYTE), // out array
            ValueLayout.JAVA_LONG,                                       // len (size_t)
            ValueLayout.JAVA_INT,                                        // strength
            ValueLayout.JAVA_INT);                                       // prediction resistance

    /** Java method type of {@link RandSource#getRandomSegment}. */
    public static final MethodType METHOD_TYPE = MethodType.methodType(
            int.class,           // return
            MemorySegment.class, // out
            long.class,          // len
            int.class,           // strength
            int.class);          // prediction resistance
}
