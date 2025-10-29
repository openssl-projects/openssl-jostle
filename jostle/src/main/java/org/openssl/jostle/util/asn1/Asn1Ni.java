/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.util.asn1;

import org.openssl.jostle.jcajce.provider.*;

public interface Asn1Ni
{

    void dispose(long reference);

    long allocate();

    int encodePublicKey(long ref, long keyRef);

    int encodePrivateKey(long ref, long keyRef);

    int getData(long ref, byte[] out);

    long fromPrivateKeyInfo(byte[] data, int start, int len);

    long fromPublicKeyInfo(byte[] data, int start, int len);

    default long handleErrors(long code)
    {
        if (code >= 0)
        {
            return code;
        }

        ErrorCode errorCode = ErrorCode.forCode(code);
        switch (errorCode)
        {
            case JO_OPENSSL_ERROR:
                throw new OpenSSLException(String.format("OpenSSL Error: %s", OpenSSL.getOpenSSLErrors()));
            case JO_KEY_IS_NULL:
                throw new IllegalArgumentException("key reference is null");
            case JO_KEY_SPEC_HAS_NULL_KEY:
                throw new IllegalArgumentException("key spec has null key");
            case JO_INVALID_KEY_LEN:
                throw new IllegalArgumentException("key length is invalid");
            case JO_UNEXPECTED_POINTER_CHANGE:
                throw new UnexpectedPointerChangeException("a returned pointer changed unexpectedly");
            case JO_UNEXPECTED_STATE:
                throw new IllegalStateException("unexpected state"); // Basically native layer is set up differently to expected
            case JO_SPEC_HAS_NULL_KEY:
                throw new NullPointerException("key spec is null");
            case JO_INPUT_IS_NULL:
                throw new IllegalArgumentException("input is null");
            case JO_INPUT_OFFSET_IS_NEGATIVE:
                throw new IllegalArgumentException("input offset is negative");
            case JO_INPUT_LEN_IS_NEGATIVE:
                throw new IllegalArgumentException("input length is negative");
            case JO_INPUT_OUT_OF_RANGE:
                throw new IllegalArgumentException("input out of range");
            case JO_OUTPUT_SIZE_INT_OVERFLOW:
                throw new OverflowException("output size int32 overflow");
            case JO_FAILED_ACCESS_OUTPUT:
                throw new AccessException("unable to access output array");
            case JO_OUTPUT_OUT_OF_RANGE:
                throw new AccessException("output is out of range");
            case JO_INPUT_TOO_LONG_INT32:
                throw new OverflowException("input size int32 overflow");
            default:
                throw new IllegalStateException("unexpected error code: " + errorCode.name() + " " + code);
        }
    }


}
