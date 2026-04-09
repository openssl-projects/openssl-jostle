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

package org.openssl.jostle.jcajce.provider.ed;

import org.openssl.jostle.jcajce.provider.DefaultServiceNI;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.rand.RandSource;

public interface EDServiceNI extends DefaultServiceNI
{

    long ni_generateKeyPair(int type, int[] err, RandSource randSource);

    default long generateKeyPair(int type, RandSource rndId)
    {
        int[] err = new int[1];
        long r = ni_generateKeyPair(type, err, rndId);
        handleErrors(err[0]);
        return r;
    }



    default long handleErrors(long code)
    {

        if (code >= 0)
        {
            return code;
        }

//        ErrorCode errorCode = ErrorCode.forCode(code);

//        switch (errorCode)
//        {
//            default:
//        }

        return baseErrorHandler(code);

    }
}
