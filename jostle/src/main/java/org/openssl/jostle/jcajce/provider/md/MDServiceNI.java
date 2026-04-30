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

package org.openssl.jostle.jcajce.provider.md;

import org.openssl.jostle.jcajce.provider.DefaultServiceNI;
import org.openssl.jostle.jcajce.provider.ErrorCode;


public interface MDServiceNI extends DefaultServiceNI
{

    long ni_allocateDigest(String name, int xofLen, int[] err);

    int ni_updateByte(long ref, byte b);

    int ni_updateBytes(long ref, byte[] input, int offset, int len);

    void ni_dispose(long reference);

    int ni_getDigestOutputLen(long ref);

    int ni_digest(long ref, byte[] out, int offset, int length);

    int ni_reset(long ref);


    // Allocate state for digest
    default long allocateDigest(String name, int xofLen)
    {
        int[] err = new int[1];
        long v = ni_allocateDigest(name, xofLen, err);
        handleErrors(err[0]);
        return v;
    }


    default void engineUpdate(long ref, byte b)
    {
        handleErrors(ni_updateByte(ref, b));
    }

    default void engineUpdate(long ref, byte[] input, int offset, int len)
    {
        handleErrors(ni_updateBytes(ref, input, offset, len));
    }

    default void dispose(long ref)
    {
        ni_dispose(ref);
    }

    default int getDigestOutputLen(long ref)
    {
        return (int) handleErrors(ni_getDigestOutputLen(ref));
    }

    default int digest(long ref, byte[] out, int offset, int length)
    {
        return (int) handleErrors(ni_digest(ref, out, offset, length));
    }

    default void reset(long ref)
    {
        handleErrors(ni_reset(ref));
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

            case JO_MD_CREATE_FAILED:
                throw new IllegalStateException("md create failed");
            case JO_MD_INIT_FAILED:
                throw new IllegalStateException("md init failed");
            case JO_MD_DIGEST_LEN_INT_OVERFLOW:
                throw new IllegalStateException("digest len overflow");
            case JO_MD_SET_PARAM_FAIL:
                throw new IllegalStateException("md unable to set param");
            case JO_MD_XOF_LEN_INVALID:
                throw new IllegalArgumentException("xof length inconsistent with algorithm");
            default:
                return baseErrorHandler(code);
        }


    }


}
