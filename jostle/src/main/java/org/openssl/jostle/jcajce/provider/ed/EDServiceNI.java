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

    long ni_allocateSigner(int[] err);

    void ni_disposeSigner(long reference);

    long ni_generateKeyPair(int type, int[] err, RandSource randSource);

    int ni_initSign(long reference, long keyRef, String name, byte[] context, int contextLen, RandSource randSource);

    int ni_sign(long reference, byte[] sig, int i, RandSource randSource);

    int ni_initVerify(long reference, long keyRef, String name, byte[] context, int contextLen);

    int ni_verify(long reference, byte[] sigBytes, int len);

    int ni_update(long reference, byte[] b, int off, int len);

    int ni_decode_publicKey(long spec_ref, int keyType, byte[] input, int inputOffset, int inputLen);

    int ni_decode_privateKey(long spec_ref, int keyType, byte[] input, int inputOffset, int inputLen);

    int ni_getPublicKey(long ref, byte[] output);

    int ni_getPrivateKey(long ref, byte[] output);

    default long allocateSigner()
    {
        int[] err = new int[1];
        long ref = ni_allocateSigner(err);
        handleErrors(err[0]);
        return ref;
    }

    default long generateKeyPair(int type, RandSource rndId)
    {
        int[] err = new int[1];
        long r = ni_generateKeyPair(type, err, rndId);
        handleErrors(err[0]);
        return r;
    }


    default void disposeSigner(long reference)
    {
        ni_disposeSigner(reference);
    }

    default int verify(long reference, byte[] sigBytes, int len)
    {
        long code = ni_verify(reference, sigBytes, len);
        if (code != ErrorCode.JO_FAIL.getCode())
        {
            return (int) handleErrors(code);
        }
        return (int) code;
    }


    default int sign(long reference, byte[] sig, int i, RandSource randSource)
    {
        return (int) handleErrors(ni_sign(reference, sig, i, randSource));
    }

    default int update(long reference, byte[] b, int off, int len)
    {
        return (int) handleErrors(ni_update(reference, b, off, len));
    }

    default void initSign(long reference, long keyRef, String name, byte[] context, int contextLen, RandSource randSource)
    {
        handleErrors(ni_initSign(reference, keyRef,name , context, contextLen, randSource));
    }

    default void initVerify(long reference, long keyRef, String name, byte[] context, int contextLen)
    {
        handleErrors(ni_initVerify(reference, keyRef,name, context, contextLen));
    }

    /**
     * Get the public key encoded
     *
     * @param ref    the reference
     * @param output the output array, use null to return length.
     * @return the length or an error code.
     */
    default int getPublicKey(long ref, byte[] output)
    {
        return (int) handleErrors(ni_getPublicKey(ref, output));
    }

    /**
     * Get the private key encoded.
     *
     * @param ref    the reference
     * @param output the output array, use null to return length
     * @return the length or an error code.
     */
    default int getPrivateKey(long ref, byte[] output)
    {
        return (int) handleErrors(ni_getPrivateKey(ref, output));
    }


    default int decode_publicKey(long spec_ref, int keyType, byte[] input, int inputOffset, int inputLen)
    {
        return (int) handleErrors(ni_decode_publicKey(spec_ref, keyType, input, inputOffset, inputLen));
    }

    default int decode_privateKey(long spec_ref, int keyType, byte[] input, int inputOffset, int inputLen)
    {
        return (int) handleErrors(ni_decode_privateKey(spec_ref, keyType, input, inputOffset, inputLen));
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
                throw new IllegalArgumentException("invalid key type for EDDSA");
            default:
        }

        return baseErrorHandler(code);

    }


}
