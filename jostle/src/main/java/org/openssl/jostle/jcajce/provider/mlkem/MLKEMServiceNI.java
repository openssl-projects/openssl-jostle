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

import org.openssl.jostle.jcajce.provider.DefaultServiceNI;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.rand.RandSource;

import java.util.Objects;

public interface MLKEMServiceNI extends DefaultServiceNI
{


    long ni_generateKeyPair(int type, int[] err, RandSource randSource);

    long ni_generateKeyPair(int type, int[] err, byte[] seed, int seedLen, RandSource randSource);

    int ni_getPublicKey(long ref, byte[] output);

    int ni_getPrivateKey(long ref, byte[] output);

    int ni_getSeed(long ref, byte[] output);

    int ni_decode_publicKey(long spec_ref, int keyType, byte[] input, int inputOffset, int inputLen);

    int ni_decode_privateKey(long spec_ref, int keyType, byte[] input, int inputOffset, int inputLen);


    /**
     * Generate an ML-KEM Key pair
     *
     * @param type       the type
     * @param randSource
     * @return 0 for success, or less than 0 for failure
     */
    default long generateKeyPair(int type, RandSource randSource)
    {
        int[] err = new int[1];
        long ref = ni_generateKeyPair(type, err, randSource);
        handleErrors(err[0]);
        return ref;
    }

    default long generateKeyPair(int type, byte[] seed, int seedLen, RandSource randSource)
    {
        int[] err = new int[1];
        long ref = ni_generateKeyPair(type, err, seed, seedLen, randSource);
        handleErrors(err[0]);
        return ref;
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

    /**
     * Get the seed.
     *
     * @param ref    The reference
     * @param output the output array, use null to get return length
     * @return the length or an error code
     */
    default int getSeed(long ref, byte[] output)
    {
        return (int) handleErrors(ni_getSeed(ref, output));
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
        if (Objects.requireNonNull(errorCode) == ErrorCode.JO_INCORRECT_KEY_TYPE)
        {
            throw new IllegalArgumentException("invalid key type for ML-KEM");
        }
        return baseErrorHandler(code);

    }
}
