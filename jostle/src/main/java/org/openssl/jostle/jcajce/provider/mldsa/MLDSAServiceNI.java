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

    long ni_generateKeyPair(int type, int[] err, RandSource rndId);

    long ni_generateKeyPair(int type, int[] err, byte[] seed, int seedLen, RandSource rndSource);

    int ni_getPublicKey(long ref, byte[] output);

    int ni_getPrivateKey(long ref, byte[] output);

    int ni_getSeed(long ref, byte[] output);

    void ni_disposeSigner(long reference);

    long ni_allocateSigner(int[] err);

    int ni_initVerify(long ref, long keyReference, byte[] context, int contextLen, int muHandlingOrdinal);

    int ni_initSign(long reference, long keyReference, byte[] context, int contextLen, int muHandlingOrdinal, RandSource randSource);

    int ni_update(long reference, byte[] input, int inputOffset, int inputLen);

    int ni_sign(long reference, byte[] output, int offset, RandSource randSource);

    int ni_verify(long reference, byte[] sigBytes, int sigLen);

    int ni_decode_publicKey(long spec_ref, int keyType, byte[] input, int inputOffset, int inputLen);

    int ni_decode_privateKey(long spec_ref, int keyType, byte[] input, int inputOffset, int inputLen);


    /**
     * Generate a ML-DSA Key pair
     *
     * @param type  the type
     * @param rndId
     * @return 0 for success, or less than 0 for failure
     */
    default long generateKeyPair(int type, RandSource rndId)
    {
        int[] err = new int[1];
        long r = ni_generateKeyPair(type, err, rndId);
        handleErrors(err[0]);
        return r;
    }

    default long generateKeyPair(int type, byte[] seed, int seedLen, RandSource rndSource)
    {
        int[] err = new int[1];
        long r = ni_generateKeyPair(type, err, seed, seedLen, rndSource);
        handleErrors(err[0]);
        return r;
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

    /**
     * Dispose of a signer
     *
     * @param reference the reference
     */
    default void disposeSigner(long reference)
    {
        ni_disposeSigner(reference);
    }

    /**
     * Allocate a signer
     *
     * @return
     */
    default long allocateSigner()
    {
        int[] err = new int[1];
        long ref = ni_allocateSigner(err);
        handleErrors(err[0]);
        return ref;
    }


    /**
     * @param ref               Signer Reference
     * @param keyReference      reference to key_spec type
     * @param context           context bytes
     * @param contextLen        length, use -1 to prevent initial updating of Mu generating xof
     * @param muHandlingOrdinal
     * @return response code
     */
    default int initVerify(long ref, long keyReference, byte[] context, int contextLen, int muHandlingOrdinal)
    {
        return (int) handleErrors(ni_initVerify(ref, keyReference, context, contextLen, muHandlingOrdinal));
    }

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
    default int initSign(long reference, long keyReference, byte[] context, int contextLen, int muHandlingOrdinal, RandSource randSource)
    {
        return (int) handleErrors(ni_initSign(reference, keyReference, context, contextLen, muHandlingOrdinal, randSource));
    }


    /**
     * Add input for signing / verification
     *
     * @param reference
     * @param input
     * @param inputOffset
     * @param inputLen
     * @return
     */
    default int update(long reference, byte[] input, int inputOffset, int inputLen)
    {
        return (int) handleErrors(ni_update(reference, input, inputOffset, inputLen));
    }

    default int sign(long reference, byte[] output, int offset, RandSource randSource)
    {
        return (int) handleErrors(ni_sign(reference, output, offset, randSource));
    }

    default int verify(long reference, byte[] sigBytes, int sigLen)
    {
        long code = ni_verify(reference, sigBytes, sigLen);
        if (code == ErrorCode.JO_FAIL.getCode())
        { // Fail used for invalid signature
            return (int) code;
        }
        return (int) handleErrors(code);
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


}
