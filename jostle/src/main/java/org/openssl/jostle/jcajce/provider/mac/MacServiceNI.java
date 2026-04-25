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

import org.openssl.jostle.jcajce.provider.DefaultServiceNI;
import org.openssl.jostle.jcajce.provider.ErrorCode;

import java.security.InvalidKeyException;

public interface MacServiceNI extends DefaultServiceNI
{
    long ni_allocateMac(String macName, String canonicalDigestName, int[] err);

    int ni_init(long ref, byte[] keyBytes);

    int ni_updateByte(long ref, byte b);

    int ni_updateBytes(long ref, byte[] in, int inOff, int inLen);

    int ni_doFinal(long ref, byte[] out, int outOff);

    int ni_getMacLength(long ref);

    int ni_reset(long ref);

    void ni_dispose(long ref);



    default long allocateMac(String macName, String functionName)
    {
        int[] err = new int[1];
        long v = ni_allocateMac(macName, functionName, err);
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
        return (int) handleErrors(ni_doFinal(ref, out, outOff));
    }

    default int getMacLength(long ref)
    {
        return (int) handleErrors(ni_getMacLength(ref));
    }

    default void reset(long ref)
    {
        handleErrors( ni_reset(ref));
    }

    default void dispose(long ref)
    {
        ni_dispose(ref);
    }




    default long handleInitErrors(int code)
            throws InvalidKeyException
    {
        if (code >= 0)
        {
            return code;
        }

        ErrorCode ec = ErrorCode.forCode(code);
        switch (ec)
        {
            case JO_KEY_IS_NULL:
                throw new InvalidKeyException("key is null");
            case JO_FAILED_ACCESS_KEY:
                throw new InvalidKeyException("unable to access key bytes");
            case JO_UNKNOWN_KEY_LEN:
                throw new InvalidKeyException("invalid key length for mac type");

            default:

        }
        return baseErrorHandler(code);
    }

    default long handleErrors(long code)
    {
        if (code >= 0)
        {
            return code;
        }

        ErrorCode errorCode = ErrorCode.forCode(code);
        switch (errorCode)
        {
            case JO_MAC_FUNCTION_IS_NULL:
                throw new NullPointerException("mac function name is null");
            case JO_UNABLE_TO_ACCESS_FUNCTION:
                throw new IllegalStateException("unable to access function");
            case JO_OUTPUT_OUT_OF_RANGE:
                throw new IllegalArgumentException("output offset + mac len is out of range");
            default:

        }
        return baseErrorHandler(code);
    }
}
