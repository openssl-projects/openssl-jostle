/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.blockcipher;

import org.openssl.jostle.jcajce.provider.DefaultServiceNI;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.OpenSSL;
import org.openssl.jostle.jcajce.provider.OpenSSLException;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;

/**
 * Implementation provide calls to native code.
 */
public interface BlockCipherNI extends DefaultServiceNI
{
    default long handleFinalErrorCodes(ErrorCode code) throws IllegalBlockSizeException, BadPaddingException
    {
        switch (code)
        {
            case JO_OUTPUT_TOO_SMALL:
                throw new IllegalBlockSizeException("output too small");
            case JO_INVALID_CIPHER_TEXT:
                throw new BadPaddingException("invalid cipher text");
            case JO_TAG_INVALID:
                throw new AEADBadTagException("bad tag");
            default:

        }
           return baseErrorHandler(code.getCode()); // TODO Refactor
    }

    default long handleUpdateErrorCodes(ErrorCode code) throws ShortBufferException, IllegalBlockSizeException
    {
        switch (code)
        {
            case JO_OUTPUT_OUT_OF_RANGE:
                throw new ShortBufferException("output offset + length is out of range");
            case JO_OUTPUT_TOO_SMALL:
                throw new ShortBufferException("output too small");
            case JO_INVALID_OP_MODE:
                throw new IllegalStateException("invalid operation mode");
            case JO_NOT_BLOCK_ALIGNED:
                throw new IllegalBlockSizeException("data not block size aligned");
            case JO_CTR_MODE_OVERFLOW:
                throw new IllegalStateException("ctr mode overflow");
            default:

        }
        return baseErrorHandler(code.getCode());
    }

    default long handleInitErrorCodes(ErrorCode codes, int keyLen, int ivLen) throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        switch (codes)
        {
            case JO_SUCCESS:
                break;
            case JO_FAILED_ACCESS_KEY:
                throw new IllegalStateException("native layer was unable to access key");
            case JO_FAILED_ACCESS_IV:
                throw new IllegalStateException("native layer was unable to access iv");
            case JO_KEY_IS_NULL:
                throw new InvalidKeyException("key is null");
            case JO_IV_IS_NULL:
                throw new InvalidAlgorithmParameterException("iv is null");
            case JO_MODE_TAKES_NO_IV:
                throw new InvalidAlgorithmParameterException("mode takes no iv");
            case JO_INVALID_CIPHER:
                throw new IllegalStateException("cipher not supported");
            case JO_INVALID_KEY_LEN:
                throw new InvalidKeyException("key length " + keyLen + " is invalid");
            case JO_INVALID_IV_LEN:
                throw new InvalidAlgorithmParameterException("iv len is invalid: " + ivLen);
            case JO_INVALID_MODE:
                throw new InvalidAlgorithmParameterException("mode not supported for cipher");
            case JO_INVALID_OP_MODE:
                throw new IllegalStateException("opmode not supported for cipher");
            case JO_INVALID_TAG_LEN:
                throw new IllegalArgumentException("invalid tag len");
            case JO_TAG_IS_NULL:
                throw new IllegalArgumentException("tag is null");
            default:

        }
        return baseErrorHandler(codes.getCode());
    }

    long makeInstance(int cipher, int mode, int padding);

    int init(long ref, int oppmode, byte[] keyBytes, byte[] iv, int tag_len);

    int getBlockSize(long ref);

    int update(long ref, byte[] output, int outputOffset, byte[] input, int inputOffset, int inputLen);

    int doFinal(long ref, byte[] output, int outputOffset);

    int updateAAD(long ref, byte[] input, int inputOffset, int inputLen);

    int getFinalSize(long ref, int length);

    int getUpdateSize(long ref, int length);

    void dispose(long ref);


}
