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

import org.openssl.jostle.jcajce.provider.AccessException;
import org.openssl.jostle.jcajce.provider.DefaultServiceNI;
import org.openssl.jostle.jcajce.provider.ErrorCode;

public interface Asn1Ni extends DefaultServiceNI
{

    void ni_dispose(long reference);

    long ni_allocate(int[] err);

    int ni_encodePublicKey(long ref, long keyRef);

    int ni_encodePrivateKey(long ref, long keyRef, String option);

    int ni_getData(long ref, byte[] out);

    long ni_fromPrivateKeyInfo(byte[] data, int start, int len);

    long ni_fromPublicKeyInfo(byte[] data, int start, int len);


    default void dispose(long reference)
    {
        ni_dispose(reference);
    }

    default long allocate()
    {
        int[] err = new int[1];
        long ref = ni_allocate(err);
        handleErrors(ref);
        return ref;
    }

    default int encodePublicKey(long ref, long keyRef)
    {
        return (int) handleErrors(ni_encodePublicKey(ref, keyRef));
    }

    default int encodePrivateKey(long ref, long keyRef, String option)
    {
        return (int) handleErrors(ni_encodePrivateKey(ref, keyRef, option));
    }

    default int getData(long ref, byte[] out)
    {
        return (int) handleErrors(ni_getData(ref, out));
    }

    default long fromPrivateKeyInfo(byte[] data, int start, int len)
    {
        return handleErrors(ni_fromPrivateKeyInfo(data, start, len));
    }

    default long fromPublicKeyInfo(byte[] data, int start, int len)
    {
        return handleErrors(ni_fromPublicKeyInfo(data, start, len));
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
            case JO_INVALID_KEY_ENCODING_OPTION:
                throw new IllegalArgumentException("invalid key encoding option");
            case JO_FAILED_ACCESS_ENCODING_OPTION:
                throw new AccessException("unable to access string with encoding option");
            default:
        }
        return baseErrorHandler(code);
    }


}
