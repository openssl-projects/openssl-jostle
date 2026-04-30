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

import org.openssl.jostle.jcajce.provider.AccessException;
import org.openssl.jostle.jcajce.provider.DefaultServiceNI;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.rand.RandSource;

public interface SpecNI extends DefaultServiceNI
{

    void ni_dispose(long reference);

    long ni_allocate(int[] err);

    String ni_getName(long keyRef);

    int ni_encap(long keyRef, String opt, byte[] secret, int inOff, int inLen, byte[] out, int off, int len, RandSource randSource);

    int ni_decap(long keyRef, String opt, byte[] input, int inOff, int inLen, byte[] out, int off, int len);


    default void dispose(long reference)
    {
        ni_dispose(reference);
    }

    default long allocate()
    {
        int[] err = new int[1];
        long ref = ni_allocate(err);
        handleErrors(err[0]);
        return ref;
    }

    default String getName(long keyRef)
    {
        return ni_getName(keyRef);
    }

    default int encap(long keyRef, String opt, byte[] secret, int inOff, int inLen, byte[] out, int off, int len, RandSource randSource)
    {
        return (int)handleErrors(ni_encap(keyRef, opt, secret, inOff, inLen, out, off, len, randSource));
    }

    default int decap(long keyRef, String opt, byte[] input, int inOff, int inLen, byte[] out, int off, int len)
    {
        return (int)handleErrors( ni_decap(keyRef, opt, input, inOff, inLen, out, off, len));
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
            case JO_FAIL:
                return code;
            case JO_FAILED_ACCESS_ENCAP_OPP:
                throw new AccessException("unable to access operation string");

        }
        return baseErrorHandler(code);
    }
}
