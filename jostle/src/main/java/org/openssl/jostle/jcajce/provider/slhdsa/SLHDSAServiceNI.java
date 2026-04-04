/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.slhdsa;

import org.openssl.jostle.jcajce.provider.DefaultServiceNI;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.rand.RandSource;

public interface SLHDSAServiceNI extends DefaultServiceNI
{
    /**
     * Generate a SLH-DSA Key pair
     *
     * @param type       the type
     * @param randSource
     * @return 0 for success, or less than 0 for failure
     */
    long generateKeyPair(int type, RandSource randSource);

    long generateKeyPair(int type, byte[] seed, int seedLen, RandSource randSource);

    int getPrivateKey(long reference, byte[] output);

    long getPublicKey(long reference, byte[] output);

    int decode_publicKey(long spec_ref, int keyType, byte[] input, int inputOffset, int inputLen);

    int decode_privateKey(long spec_ref, int keyType, byte[] input, int inputOffset, int inputLen);

    long allocateSigner();

    int initVerify(long ref, long keyRef, byte[] context, int contextLen, int messageEncoding, int deterministic);

    int update(long ref, byte[] b, int off, int len);

    long sign(long ref, byte[] sig, int offset, RandSource randSource);

    int verify(long reference, byte[] sigBytes, int len);

    long initSign(long reference, long keyRef, byte[] context, int contextLen, int messageEncoding, int deterministic, RandSource randSource);

    void disposeSigner(long reference);

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
            case JO_INCORRECT_KEY_TYPE:
                throw new IllegalArgumentException("invalid key type for SLH-DSA");
            case JO_INVALID_SLH_DSA_MSG_ENCODING_PARAM:
                throw new IllegalArgumentException("invalid message encoding param");
            case JO_INVALID_SLH_DSA_DETERMINISTIC_PARAM:
                throw new IllegalArgumentException("invalid deterministic param");
            default:
                return baseErrorHandler(code);
        }
    }
}
