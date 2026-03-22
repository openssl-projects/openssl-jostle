/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.digest;

import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.OpenSSL;
import org.openssl.jostle.jcajce.provider.OpenSSLException;

/**
 * Low-level native interface for MessageDigest operations.
 * <p>
 * Implementations (JNI/FFI) create and operate on a native
 * digest context, returning a long that represents a native
 * pointer/handle. Callers must ensure {@link #dispose(long)}
 * is invoked to free the native resource when it is no
 * longer needed.
 */
public interface DigestNI
{
    /**
     * Create a native digest context for the provided canonical
     * algorithm name.
     *
     * @param canonicalAlgName canonical algorithm name (e.g.
     *                         "SHA-256"). May be null if the native
     *                         side supports a default.
     * @return native handle (non-zero) on success, or 0L on failure
     */
    long makeInstance(String canonicalAlgName);
    /**
     * Update the digest state with input bytes.
     *
     * @param ref   native digest handle
     * @param in    input buffer (may be null to signal no-op
     *              depending on native impl)
     * @param inOff offset into input
     * @param inLen length of input
     * @return non-negative on success; negative error code mapped by
     *         {@link #handleUpdateCodes(int)}
     */
    int update(long ref, byte[] in, int inOff, int inLen);

    /**
     * Finalize the digest and write the result into the provided
     * buffer.
     *
     * @param ref    native digest handle
     * @param out    output buffer (must be large enough for digest)
     * @param outOff offset into output buffer
     * @return number of bytes written (>= 0) or negative error code
     *         mapped by {@link #handleFinalCodes(int)}
     */
    int doFinal(long ref, byte[] out, int outOff);

    /**
     * Return the digest length in bytes for the given native
     * context.
     *
     * @param ref native digest handle
     * @return digest length (>= 0) or negative error code
     */
    int getDigestLength(long ref);

    /**
     * Reset the native digest context to its initial state for
     * reuse.
     *
     * @param ref native digest handle
     */
    void reset(long ref);

    /**
        * Free the native digest context and release associated
        * resources.
        *
        * @param ref native digest handle
        */
    void dispose(long ref);

    /**
     * Deep-copy the native digest context, returning a new context handle.
     * @param ref source native digest handle
     * @return new native handle on success, or 0L on failure
     */
    long copy(long ref);

    static void handleUpdateCodes(int code)
    {
        if (code >= 0)
        {
            return;
        }
        ErrorCode ec = ErrorCode.forCode(code);
        switch (ec)
        {
            case JO_INPUT_IS_NULL: throw new IllegalArgumentException("input is null");
            case JO_INPUT_OFFSET_IS_NEGATIVE: throw new IllegalArgumentException("input offset is negative");
            case JO_INPUT_LEN_IS_NEGATIVE: throw new IllegalArgumentException("input length is negative");
            case JO_INPUT_OUT_OF_RANGE: throw new IllegalArgumentException("input out of range");
            case JO_FAILED_ACCESS_INPUT: throw new IllegalStateException("unable to access input array");
            case JO_OPENSSL_ERROR: throw new OpenSSLException(OpenSSL.getOpenSSLErrors());
            default: throw new IllegalStateException("unexpected error code: " + ec + " (" + code + ")");
        }
    }

    static void handleFinalCodes(int code)
    {
        if (code >= 0)
        {
            return;
        }
        ErrorCode ec = ErrorCode.forCode(code);
        switch (ec)
        {
            case JO_OUTPUT_IS_NULL: throw new IllegalArgumentException("output is null");
            case JO_OUTPUT_OFFSET_IS_NEGATIVE: throw new IllegalArgumentException("output offset is negative");
            case JO_OUTPUT_LEN_IS_NEGATIVE: throw new IllegalArgumentException("output length is negative");
            case JO_OUTPUT_OUT_OF_RANGE: throw new IllegalArgumentException("output out of range");
            case JO_FAILED_ACCESS_OUTPUT: throw new IllegalStateException("unable to access output array");
            case JO_OUTPUT_TOO_SMALL: throw new IllegalArgumentException("output too small");
            case JO_OPENSSL_ERROR: throw new OpenSSLException(OpenSSL.getOpenSSLErrors());
            default: throw new IllegalStateException("unexpected error code: " + ec + " (" + code + ")");
        }
    }
}
