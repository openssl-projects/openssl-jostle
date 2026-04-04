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

package org.openssl.jostle.jcajce.provider;

public interface DefaultServiceNI
{

    default long baseErrorHandler(long code)
    {

        if (code >= 0)
        {
            return code;
        }

        ErrorCode errorCode = ErrorCode.forCode(code);
        switch (errorCode)
        {
            case JO_SUCCESS:
                return code;
            case JO_OPENSSL_ERROR:
                throw new OpenSSLException(String.format("OpenSSL Error: %s", OpenSSL.getOpenSSLErrors()));
            case JO_SPEC_HAS_NULL_KEY:
                throw new IllegalArgumentException("key spec is null");
            case JO_KEY_SPEC_HAS_NULL_KEY:
                throw new IllegalArgumentException("key spec has null key");
            case JO_FAILED_ACCESS_OUTPUT:
                throw new AccessException("unable to access output array");
            case JO_FAILED_ACCESS_INPUT:
                throw new AccessException("unable to access input array");
            case JO_OUTPUT_IS_NULL:
                throw new NullPointerException("output is null");
            case JO_OUTPUT_SIZE_INT_OVERFLOW:
                throw new OverflowException("output too long int32");
            case JO_OUTPUT_TOO_SMALL:
                throw new IllegalArgumentException("output too small");
            case JO_INPUT_IS_NULL:
                throw new NullPointerException("input is null");
            case JO_INPUT_LEN_IS_NEGATIVE:
                throw new IllegalArgumentException("input len is negative");
            case JO_INPUT_OFFSET_IS_NEGATIVE:
                throw new IllegalArgumentException("input offset is negative");
            case JO_INPUT_OUT_OF_RANGE:
                throw new IllegalArgumentException("input offset + length is out of range");
            case JO_UNKNOWN_KEY_LEN:
                throw new IllegalArgumentException("unknown key length");
            case JO_INCORRECT_KEY_TYPE:
                throw new IllegalArgumentException("invalid key type");
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
                throw new OverflowException("input too long int32");
            case JO_OUTPUT_OFFSET_IS_NEGATIVE:
                throw new IllegalArgumentException("output offset is negative");
            case JO_OUTPUT_OUT_OF_RANGE:
                throw new IllegalArgumentException("output offset + length is out of range");
            case JO_OUTPUT_LEN_IS_NEGATIVE:
                throw new IllegalArgumentException("output len negative");
            case JO_OUTPUT_TOO_LONG_INT32: // need to use a special FFI call to test this
                throw new OverflowException("output too long int32");
            case JO_UNEXPECTED_STATE:
                throw new IllegalStateException("unexpected state");
            case JO_UNEXPECTED_SIG_LEN_CHANGE:
                throw new IllegalStateException("unexpected sig length change");
            case JO_SIG_IS_NULL:
                throw new IllegalArgumentException("sig is null");
            case JO_SIG_LENGTH_IS_ZERO:
                throw new IllegalArgumentException("sig length is zero");
            case JO_SIG_LENGTH_IS_NEGATIVE:
                throw new IllegalArgumentException("sig length is negative");
            case JO_SIG_OUT_OF_RANGE:
                throw new IllegalArgumentException("sig out of range");
            case JO_FAILED_ACCESS_SIG:
                throw new AccessException("unable to access signature array");
            case JO_INVALID_SEED_LEN:
                throw new IllegalArgumentException("invalid seed length");
            case JO_SEED_IS_NULL:
                throw new IllegalArgumentException("seed is null");
            case JO_SEED_LEN_IS_NEGATIVE:
                throw new IllegalArgumentException("seed len is negative");
            case JO_FAILED_ACCESS_SEED:
                throw new AccessException("unable to access seed array");
            case JO_INVALID_SEED_LEN_OUT_OF_RANGE:
                throw new IllegalArgumentException("seed length is out of range");
            case JO_NAME_IS_NULL:
                throw new NullPointerException("name is null");
            case JO_NAME_NOT_FOUND:
                throw new IllegalArgumentException("name not found");
            case JO_UNABLE_TO_ACCESS_NAME:
                throw new IllegalStateException("unable to access name");
            case JO_KEY_IS_NULL:
                throw new IllegalArgumentException("key reference is null");
            case JO_INVALID_KEY_LEN:
                throw new IllegalArgumentException("key length is invalid");
            case JO_UNEXPECTED_POINTER_CHANGE:
                throw new UnexpectedPointerChangeException("a returned pointer changed unexpectedly");

            case JO_RAND_NO_RAND_METHOD:
                throw new IllegalArgumentException("supplied random source was null");
            default:
                throw new IllegalStateException("unexpected error code " + errorCode + ": " + code);
        }

    }
}
