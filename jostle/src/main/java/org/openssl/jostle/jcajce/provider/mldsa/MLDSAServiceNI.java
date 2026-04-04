/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.mldsa;

import org.openssl.jostle.jcajce.provider.DefaultServiceNI;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.rand.RandSource;

public interface MLDSAServiceNI extends DefaultServiceNI
{
    /**
     * Generate a ML-DSA Key pair
     *
     * @param type  the type
     * @param rndId
     * @return 0 for success, or less than 0 for failure
     */
    long generateKeyPair(int type, RandSource rndId);

    long generateKeyPair(int type, byte[] seed, int seedLen, RandSource rndSource);

    /**
     * Get the public key encoded
     *
     * @param ref    the reference
     * @param output the output array, use null to return length.
     * @return the length or an error code.
     */
    int getPublicKey(long ref, byte[] output);

    /**
     * Get the private key encoded.
     *
     * @param ref    the reference
     * @param output the output array, use null to return length
     * @return the length or an error code.
     */
    int getPrivateKey(long ref, byte[] output);

    /**
     * Get the seed.
     *
     * @param ref    The reference
     * @param output the output array, use null to get return length
     * @return the length or an error code
     */
    int getSeed(long ref, byte[] output);

    /**
     * Dispose of a signer
     *
     * @param reference the reference
     */
    void disposeSigner(long reference);

    /**
     * Allocate a signer
     *
     * @return
     */
    long allocateSigner();


    /**
     * @param ref               Signer Reference
     * @param keyReference      reference to key_spec type
     * @param context           context bytes
     * @param contextLen        length, use -1 to prevent initial updating of Mu generating xof
     * @param muHandlingOrdinal
     * @return response code
     */
    int initVerify(long ref, long keyReference, byte[] context, int contextLen, int muHandlingOrdinal);

    /**
     * Init signing
     *
     * @param reference         the signer reference
     * @param keyReference      reference to key_spec type
     * @param context           context bytes
     * @param contextLen        length, use -1 to prevent initial updating of Mu generating xof
     * @param muHandlingOrdinal
     * @param randSource
     * @return response code
     */
    int initSign(long reference, long keyReference, byte[] context, int contextLen, int muHandlingOrdinal, RandSource randSource);


    /**
     * Add input for signing / verification
     *
     * @param reference
     * @param input
     * @param inputOffset
     * @param inputLen
     * @return
     */
    int update(long reference, byte[] input, int inputOffset, int inputLen);


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
            case JO_UNKNOWN_MU_MODE:
                throw new IllegalArgumentException("unknown Mu mode");
            case JO_INVALID_MU_MODE_FOR_VERIFY:
                throw new IllegalArgumentException("invalid Mu mode for verify");
            case JO_INVALID_MU_MODE_FOR_SIGN:
                throw new IllegalArgumentException("invalid Mu mode for sign");
            case JO_EXTERNAL_MU_INVALID_LEN:
                throw new IllegalArgumentException("external Mu invalid length");
            case JO_INCORRECT_KEY_TYPE:
                throw new IllegalArgumentException("invalid key type for ML-DSA");
        }

        return baseErrorHandler(code);

    }

    int sign(long reference, byte[] output, int offset, RandSource randSource);

    int verify(long reference, byte[] sigBytes, int sigLen);

    int decode_publicKey(long spec_ref, int keyType, byte[] input, int inputOffset, int inputLen);

    int decode_privateKey(long spec_ref, int keyType, byte[] input, int inputOffset, int inputLen);
}
