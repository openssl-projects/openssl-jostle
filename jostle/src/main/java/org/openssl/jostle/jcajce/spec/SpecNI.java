/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.spec;

import org.openssl.jostle.jcajce.provider.*;

public interface SpecNI
{
    /**
     * Dispose of a OpenSSL PKEY
     *
     * @param reference the reference
     */
    void dispose(long reference);

    /**
     * Allocate a key spec
     *
     * @return reference to allocated key spec
     */
    long allocate();



    String getName(long keyRef);

    int encap(long keyRef, String opt, byte[] input, int intOff, int inLen, byte[] out, int off, int len);

    int decap(long keyRef, String opt, byte[] input, int inOff, int inLen, byte[] out, int off, int len);

    default long handleErrors(long code)
    {
        if (code >= 0)
        {
            return code;
        }
        ErrorCode errorCode = ErrorCode.forCode(code);
        switch (errorCode)
        {
            case JO_FAIL:
                return code;
            case JO_OPENSSL_ERROR:
                throw new OpenSSLException(String.format("OpenSSL Error: %s", OpenSSL.getOpenSSLErrors()));
            case JO_INCORRECT_KEY_TYPE:
                throw new IllegalArgumentException("invalid key type");
            case JO_SPEC_HAS_NULL_KEY:
                throw new IllegalArgumentException("key spec is null");
            case JO_KEY_SPEC_HAS_NULL_KEY:
                throw new IllegalArgumentException("key spec has null key");
            case JO_FAILED_ACCESS_OUTPUT:
                throw new AccessException("unable to access output array");
            case JO_FAILED_ACCESS_INPUT:
                throw new AccessException("unable to access input array");
            case JO_OUTPUT_SIZE_INT_OVERFLOW:
                throw new OverflowException("output size overflow");
            case JO_OUTPUT_TOO_SMALL:
                throw new IllegalArgumentException("output too small");
            case JO_INPUT_IS_NULL:
                throw new IllegalArgumentException("input is null");
            case JO_INPUT_LEN_IS_NEGATIVE:
                throw new IllegalArgumentException("input len is negative");
            case JO_OUTPUT_LEN_IS_NEGATIVE:
                throw new IllegalArgumentException("output len is negative");
            case JO_INPUT_OFFSET_IS_NEGATIVE:
                throw new IllegalArgumentException("input offset is negative");
            case JO_INPUT_OUT_OF_RANGE:
                throw new IllegalArgumentException("input offset + length are out of range");
            case JO_UNKNOWN_KEY_LEN:
                throw new IllegalArgumentException("unknown key length");
            case JO_ENCODED_PUBLIC_KEY_LEN:
                throw new IllegalArgumentException("incorrect public key length");
            case JO_ENCODED_PRIVATE_KEY_LEN:
                throw new IllegalArgumentException("incorrect private key length");
            case JO_FAILED_ACCESS_CONTEXT:
                throw new AccessException("unable to access context array");
            case JO_CONTEXT_BYTES_NULL:
                throw new IllegalArgumentException("context array is null but length >=0");
            case JO_CONTEXT_LEN_PAST_END:
                throw new IllegalArgumentException("context length is past end of context");
            case JO_CONTEXT_BYTES_TOO_LONG:
                throw new IllegalArgumentException("context length is too long");
            case JO_NOT_INITIALIZED:
                throw new IllegalStateException("not initialized");
            case JO_INPUT_TOO_LONG_INT32:
                throw new IllegalArgumentException("input too long int32");
            case JO_OUTPUT_OFFSET_IS_NEGATIVE:
                throw new IllegalArgumentException("output offset is negative");
            case JO_OUTPUT_OUT_OF_RANGE:
                throw new IllegalArgumentException("output offset + length are out of range");
            case JO_FAILED_ACCESS_ENCAP_OPP:
                throw new AccessException("unable to access operation string");
            default:
                throw new IllegalStateException("unexpected error code " + errorCode + ": " + code);
        }
    }
}
