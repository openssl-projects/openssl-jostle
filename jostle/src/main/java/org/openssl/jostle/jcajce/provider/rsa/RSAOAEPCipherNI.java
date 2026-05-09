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
import org.openssl.jostle.jcajce.provider.InvalidCipherTextException;
import org.openssl.jostle.rand.RandSource;

/**
 * Native interface for RSA-OAEP encrypt / decrypt. Op-mode constants
 * and the (digest, MGF1, label) parameters are mirrored from
 * {@code interface/util/rsa_oaep.h}.
 *
 * <p>The cipher is one-shot per init: the SPI buffers JCE
 * {@code update()} calls and routes the final accumulated input
 * through {@link #doFinal} on {@code engineDoFinal}.
 */
public interface RSAOAEPCipherNI extends DefaultServiceNI
{
    // Op modes. MUST match RSA_OAEP_OP_* in rsa_oaep.h.
    int OP_ENCRYPT = 1;
    int OP_DECRYPT = 2;


    long ni_allocateCipher(int[] err);

    void ni_disposeCipher(long reference);

    int ni_init(long ref, long keyRef, int opMode,
                String oaepMdName, String mgf1MdName,
                byte[] label,
                RandSource rndSource);

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

    default void init(long ref, long keyRef, int opMode,
                      String oaepMdName, String mgf1MdName,
                      byte[] label,
                      RandSource rndSource)
    {
        handleErrors(ni_init(ref, keyRef, opMode,
                oaepMdName, mgf1MdName, label, rndSource));
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
            case JO_INVALID_CIPHER_TEXT:
                // OAEP decrypt failure — padding-check failed or the
                // ciphertext is structurally invalid. Surface as the
                // dedicated InvalidCipherTextException (extends
                // OpenSSLException, so callers that handle the parent
                // type continue to work). The JCE SPI catches this and
                // translates to BadPaddingException at engineDoFinal.
                throw new InvalidCipherTextException(
                        String.format("invalid cipher text: %s",
                                org.openssl.jostle.jcajce.provider.OpenSSL.getOpenSSLErrors()));
            default:
        }

        return baseErrorHandler(code);
    }
}
