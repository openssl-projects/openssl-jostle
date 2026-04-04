/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.mlkem;

import org.openssl.jostle.jcajce.provider.*;
import org.openssl.jostle.rand.RandSource;

import java.util.Objects;

public interface MLKEMServiceNI extends DefaultServiceNI
{


    /**
     * Generate an ML-KEM Key pair
     *
     * @param type       the type
     * @param randSource
     * @return 0 for success, or less than 0 for failure
     */
    long generateKeyPair(int type, RandSource randSource);

    long generateKeyPair(int type, byte[] seed, int seedLen, RandSource randSource);

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


    int decode_publicKey(long spec_ref, int keyType, byte[] input, int inputOffset, int inputLen);

    int decode_privateKey(long spec_ref, int keyType, byte[] input, int inputOffset, int inputLen);


    default long handleErrors(long code)
    {

        if (code >= 0)
        {
            return code;
        }

        ErrorCode errorCode = ErrorCode.forCode(code);
        if (Objects.requireNonNull(errorCode) == ErrorCode.JO_INCORRECT_KEY_TYPE)
        {
            throw new IllegalArgumentException("invalid key type for ML-KEM");
        }
        return baseErrorHandler(code);

    }
}
