/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.mac;

import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.AccessException;
import org.openssl.jostle.jcajce.provider.OpenSSL;
import org.openssl.jostle.jcajce.provider.OpenSSLException;

import java.security.InvalidKeyException;

public interface MacServiceNI
{
    long ni_allocateMac(String macName, String canonicalDigestName, int[] err);

    int ni_init(long ref, byte[] keyBytes);

    int ni_updateByte(long ref, byte b);

    int ni_updateBytes(long ref, byte[] in, int inOff, int inLen);

    int ni_doFinal(long ref, byte[] out, int outOff);

    int ni_getMacLength(long ref);

    void ni_reset(long ref);

    void ni_dispose(long ref);

    long ni_copy(long ref, int[] err);


    default long allocateMac(String macName, String canonicalDigestName)
    {
        int[] err = new int[1];
        long v = ni_allocateMac(macName, canonicalDigestName, err);
        handleErrors(err[0]);
        return v;
    }

    default void engineInit(long ref, byte[] keyBytes)
        throws InvalidKeyException
    {
        handleInitErrors(ni_init(ref, keyBytes));
    }

    default void engineUpdate(long ref, byte b)
    {
        handleErrors(ni_updateByte(ref, b));
    }

    default void engineUpdate(long ref, byte[] in, int inOff, int inLen)
    {
        handleErrors(ni_updateBytes(ref, in, inOff, inLen));
    }

    default int doFinal(long ref, byte[] out, int outOff)
    {
        return (int)handleErrors(ni_doFinal(ref, out, outOff));
    }

    default int getMacLength(long ref)
    {
        return (int)handleErrors(ni_getMacLength(ref));
    }

    default void reset(long ref)
    {
        ni_reset(ref);
    }

    default void dispose(long ref)
    {
        ni_dispose(ref);
    }

    default long copy(long ref)
    {
        int[] err = new int[1];
        long v = ni_copy(ref, err);
        handleErrors(err[0]);
        return v;
    }


    static void handleInitErrors(int code)
        throws InvalidKeyException
    {
        if (code >= 0)
        {
            return;
        }

        ErrorCode ec = ErrorCode.forCode(code);
        switch (ec)
        {
            case JO_KEY_IS_NULL:
                throw new InvalidKeyException("key is null");
            case JO_FAILED_ACCESS_KEY:
                throw new InvalidKeyException("unable to access key bytes");
            case JO_OPENSSL_ERROR:
                throw new OpenSSLException(String.format("OpenSSL Error: %s", OpenSSL.getOpenSSLErrors()));
            default:
                handleErrors(code);
        }
    }

    static long handleErrors(long code)
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
            case JO_NAME_IS_NULL:
            case JO_PROV_NAME_NULL:
                throw new NullPointerException("name is null");
            case JO_NAME_NOT_FOUND:
            case JO_PROV_NAME_EMPTY:
                throw new IllegalArgumentException("name not found");
            case JO_UNABLE_TO_ACCESS_NAME:
                throw new IllegalStateException("unable to access name");
            case JO_FAIL:
                throw new IllegalStateException("mac operation failed");
            case JO_INPUT_IS_NULL:
                throw new IllegalArgumentException("input is null");
            case JO_INPUT_OFFSET_IS_NEGATIVE:
                throw new IllegalArgumentException("input offset is negative");
            case JO_INPUT_LEN_IS_NEGATIVE:
                throw new IllegalArgumentException("input length is negative");
            case JO_INPUT_OUT_OF_RANGE:
                throw new IllegalArgumentException("input out of range");
            case JO_FAILED_ACCESS_INPUT:
                throw new AccessException("unable to access input array");
            case JO_OUTPUT_IS_NULL:
                throw new IllegalArgumentException("output is null");
            case JO_OUTPUT_OFFSET_IS_NEGATIVE:
                throw new IllegalArgumentException("output offset is negative");
            case JO_OUTPUT_OUT_OF_RANGE:
                throw new IllegalArgumentException("output out of range");
            case JO_OUTPUT_TOO_SMALL:
                throw new IllegalArgumentException("output too small");
            case JO_FAILED_ACCESS_OUTPUT:
                throw new AccessException("unable to access output array");
            case JO_NOT_INITIALIZED:
                throw new IllegalStateException("mac not initialized");
            case JO_OPENSSL_ERROR:
                throw new OpenSSLException(String.format("OpenSSL Error: %s", OpenSSL.getOpenSSLErrors()));
            default:
                throw new IllegalStateException(String.format("Unhandled Error: %s", errorCode));
        }
    }
}
