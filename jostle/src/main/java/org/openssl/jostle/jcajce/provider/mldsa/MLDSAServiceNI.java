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

import org.openssl.jostle.jcajce.provider.*;

public interface MLDSAServiceNI
{
    /**
     * Generate a ML-DSA Key pair
     *
     * @param type the type
     * @return 0 for success, or less than 0 for failure
     */
    long generateKeyPair(int type);

    long generateKeyPair(int type, byte[] seed, int seedLen);

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
     * @return response code
     */
    int initSign(long reference, long keyReference, byte[] context, int contextLen, int muHandlingOrdinal);


    /**
     * Add input for sining / verification
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
            case JO_OPENSSL_ERROR:
                throw new OpenSSLException(String.format("OpenSSL Error: %s", OpenSSL.getOpenSSLErrors()));
            case JO_INCORRECT_KEY_TYPE:
                throw new IllegalArgumentException("invalid key type for ML-DSA");
            case JO_SPEC_HAS_NULL_KEY:
                throw new IllegalArgumentException("key spec is null");
            case JO_KEY_SPEC_HAS_NULL_KEY:
                throw new IllegalArgumentException("key spec has null key");
            case JO_FAILED_ACCESS_OUTPUT:
                throw new AccessException("unable to access output array");
            case JO_FAILED_ACCESS_INPUT:
                throw new AccessException("unable to access input array");
            case JO_OUTPUT_SIZE_INT_OVERFLOW:
                throw new OverflowException("output size overflow");
            case JO_OUTPUT_TOO_SMALL:
                throw new IllegalArgumentException("output too small");
            case JO_INPUT_IS_NULL:
                throw new IllegalArgumentException("input is null");
            case JO_INPUT_LEN_IS_NEGATIVE:
                throw new IllegalArgumentException("input len is negative");
            case JO_INPUT_OFFSET_IS_NEGATIVE:
                throw new IllegalArgumentException("input offset is negative");
            case JO_INPUT_OUT_OF_RANGE:
                throw new IllegalArgumentException("input offset + length are out of range");
            case JO_UNKNOWN_KEY_LEN:
                throw new IllegalArgumentException("unknown key length");
            case JO_ENCODED_PUBLIC_KEY_LEN:
                throw new IllegalArgumentException("incorrect public key length");
            case JO_ENCODED_PRIVATE_KEY_LEN:
                throw new IllegalArgumentException("incorrect private key length");
            case JO_FAILED_ACCESS_CONTEXT:
                throw new AccessException("unable to access context array");
            case JO_CONTEXT_BYTES_NULL:
                throw new IllegalArgumentException("context array is null but length >=0");
            case JO_CONTEXT_LEN_PAST_END:
                throw new IllegalArgumentException("context length is past end of context");
            case JO_UNKNOWN_MU_MODE:
                throw new IllegalArgumentException("unknown Mu mode");
            case JO_INVALID_MU_MODE_FOR_VERIFY:
                throw new IllegalArgumentException("invalid Mu mode for verify");
            case JO_CONTEXT_BYTES_TOO_LONG:
                throw new IllegalArgumentException("context length is too long");
            case JO_NOT_INITIALIZED:
                throw new IllegalStateException("not initialized");
            case JO_INPUT_TOO_LONG_INT32:
                throw new IllegalArgumentException("input too long int32");
            case JO_OUTPUT_OFFSET_IS_NEGATIVE:
                throw new IllegalArgumentException("output offset is negative");
            case JO_OUTPUT_OUT_OF_RANGE:
                throw new IllegalArgumentException("output offset is out of range");
            case JO_UNEXPECTED_STATE:
                throw new IllegalStateException("unexpected state");
            case JO_UNEXPECTED_SIG_LEN_CHANGE:
                throw new IllegalStateException("unexpected sig length change");
            case JO_SIG_IS_NULL:
                throw new IllegalArgumentException("sig is null");
            case JO_SIG_LENGTH_IS_ZERO:
                throw new IllegalArgumentException("sig length is zero");
            case JO_SIG_LENGTH_IS_NEGATIVE:
                throw new IllegalArgumentException("sig length is negative");
            case JO_SIG_OUT_OF_RANGE:
                throw new IllegalArgumentException("sig out of range");
            case JO_FAILED_ACCESS_SIG:
                throw new AccessException("unable to access signature array");
            case JO_INVALID_SEED_LEN:
                throw new IllegalArgumentException("invalid seed length");
            case JO_SEED_IS_NULL:
                throw new IllegalArgumentException("seed is null");
            case JO_SEED_LEN_IS_NEGATIVE:
                throw new IllegalArgumentException("seed len is negative");
            case JO_FAILED_ACCESS_SEED:
                throw new AccessException("unable to access seed array");
            case JO_INVALID_SEED_LEN_OUT_OF_RANGE:
                throw new IllegalArgumentException("seed length is out of range");
            default:
                throw new IllegalStateException("unexpected error code " + errorCode + ": " + code);
        }
    }


    int sign(long reference, byte[] output, int offset);

    int verify(long reference, byte[] sigBytes, int sigLen);

    int decode_publicKey(long spec_ref, int keyType, byte[] input, int inputOffset, int inputLen);

    int decode_privateKey(long spec_ref, int keyType, byte[] input, int inputOffset, int inputLen);
}
