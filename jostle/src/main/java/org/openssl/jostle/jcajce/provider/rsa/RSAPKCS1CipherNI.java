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

package org.openssl.jostle.jcajce.provider.rsa;

import org.openssl.jostle.jcajce.provider.DefaultServiceNI;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.rand.RandSource;

/**
 * Native interface for RSA PKCS#1 v1.5 encryption (RSAES-PKCS1-v1_5).
 * Op-mode constants mirror {@code interface/util/rsa_pkcs1.h}.
 *
 * <p>PKCS#1 v1.5 has no algorithmic parameters (no digest, no MGF, no
 * label) — it's a fixed transformation. The init function takes only
 * the key and op-mode; doFinal mirrors the OAEP cipher's two-call
 * size-then-write protocol.
 */
public interface RSAPKCS1CipherNI extends DefaultServiceNI
{
    int OP_ENCRYPT = 1;
    int OP_DECRYPT = 2;


    long ni_allocateCipher(int[] err);

    void ni_disposeCipher(long reference);

    int ni_init(long ref, long keyRef, int opMode, RandSource rndSource);

    int ni_doFinal(long ref,
                   byte[] input, int inOff, int inLen,
                   byte[] output, int outOff,
                   RandSource rndSource);


    default long allocateCipher()
    {
        int[] err = new int[1];
        long ref = ni_allocateCipher(err);
        handleErrors(err[0]);
        return ref;
    }

    default void disposeCipher(long reference)
    {
        ni_disposeCipher(reference);
    }

    default void init(long ref, long keyRef, int opMode, RandSource rndSource)
    {
        handleErrors(ni_init(ref, keyRef, opMode, rndSource));
    }

    default int doFinal(long ref,
                        byte[] input, int inOff, int inLen,
                        byte[] output, int outOff,
                        RandSource rndSource)
    {
        return (int) handleErrors(ni_doFinal(ref,
                input, inOff, inLen, output, outOff, rndSource));
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
            case JO_INCORRECT_KEY_TYPE:
                throw new IllegalArgumentException("invalid key type for RSA");
            default:
        }

        return baseErrorHandler(code);
    }
}
