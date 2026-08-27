/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 *  This class is a Jostle port of BouncyCastle's internal
 *  ExposedByteArrayOutputStream (private nested class inside
 *  CCMBlockCipher / KCCMBlockCipher / KGCMBlockCipher). It exists to
 *  avoid the per-call array copy that ByteArrayOutputStream.toByteArray()
 *  forces — handing the underlying buffer directly to a JNI / FFI call
 *  paired with size() saves an allocation + memcpy proportional to the
 *  buffered payload. For CCM/AEAD modes where the entire plaintext and
 *  AAD must be buffered until doFinal, the saving compounds.
 */
package org.openssl.jostle.util.io;

import java.io.ByteArrayOutputStream;

/**
 * A {@link ByteArrayOutputStream} that exposes its internal buffer
 * directly via {@link #getBuffer()}.
 *
 * <p>Callers reading the buffer MUST also consult {@link #size()} for
 * the number of valid bytes — the returned array is the internal
 * growable storage, which is typically larger than {@code size()}.
 *
 * <p>Writes (via the inherited {@code write} methods) may reallocate
 * the underlying buffer, so a reference obtained from {@link
 * #getBuffer()} is only valid until the next write.
 *
 * <p>Intended use: one-shot AEAD modes (CCM in particular) where the
 * AAD and plaintext are accumulated incrementally at the SPI surface
 * but must be passed through to the native layer as single contiguous
 * buffers at finalisation. Using {@code getBuffer()} + {@code size()}
 * avoids the redundant copy that {@link #toByteArray()} performs.
 */
public class ExposedByteArrayOutputStream
    extends ByteArrayOutputStream
{
    /**
     * Construct with the default initial capacity.
     */
    public ExposedByteArrayOutputStream()
    {
        super();
    }

    /**
     * Construct with the specified initial capacity.
     *
     * @param size initial buffer size in bytes
     * @throws IllegalArgumentException if {@code size} is negative
     */
    public ExposedByteArrayOutputStream(int size)
    {
        super(size);
    }

    /**
     * Return the underlying growable buffer.
     *
     * <p>The returned array is the live internal buffer, not a copy.
     * Its length is the current allocated capacity, which is
     * typically greater than {@link #size()}. Callers must use
     * {@code size()} to determine how many bytes at the start of the
     * returned array are valid.
     *
     * <p>The reference is invalidated by any subsequent write to this
     * stream, since {@link ByteArrayOutputStream} may reallocate to
     * grow.
     *
     * @return the live internal buffer
     */
    public byte[] getBuffer()
    {
        return this.buf;
    }

    /**
     * Zero the internal buffer in place.
     *
     * <p>Call this in a {@code finally} once the bytes have been consumed,
     * whenever secret or potentially-sensitive material has passed through the
     * stream. Neither {@link #reset()} nor {@link #toByteArray()} clears
     * anything: {@code reset()} only moves the count back to zero, and
     * {@code toByteArray()} takes a COPY and leaves the original contents in
     * the internal buffer until garbage collection.
     *
     * <p><b>Growth caveat — presize where you can.</b> This zeroes only the
     * buffer that exists NOW. {@link java.io.ByteArrayOutputStream} grows via
     * {@code Arrays.copyOf}, which abandons each previous buffer with its
     * contents intact and unreachable, so a stream that grew has already left
     * copies behind that no {@code erase()} can reach. Where the final length
     * is computable, construct with
     * {@link #ExposedByteArrayOutputStream(int)} at that capacity so no growth
     * occurs. This is the Java twin of the native rule that a buffer holding
     * secrets must grow by malloc + copy + {@code OPENSSL_clear_free} rather
     * than a bare {@code realloc} (see native-code.md).
     */
    public void erase()
    {
        java.util.Arrays.fill(this.buf, (byte) 0);
        this.count = 0;
    }
}
