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

    long ni_makeInstance(int cipher, int mode, int padding, int[] err);

    int ni_init(long ref, int oppmode, byte[] keyBytes, byte[] iv, int tag_len);

    int ni_getBlockSize(long ref);

    int ni_update(long ref, byte[] output, int outputOffset, byte[] input, int inputOffset, int inputLen);

    int ni_doFinal(long ref, byte[] output, int outputOffset);

    int ni_updateAAD(long ref, byte[] input, int inputOffset, int inputLen);

    int ni_getFinalSize(long ref, int length);

    int ni_getUpdateSize(long ref, int length);

    void ni_dispose(long ref);


    //
    // NB: We are expected to throw some specific checked exceptions.
    //

    default long makeInstance(int cipher, int mode, int padding)
    {
        int[] err = new int[1];
        long ref = ni_makeInstance(cipher, mode, padding, err);
        if (err[0] != ErrorCode.JO_SUCCESS.getCode())
        {
            throw new IllegalStateException("Unable to create: " + OSSLCipher.values()[cipher].name() + " " + OSSLMode.values()[mode].name());
        }
        return ref;
    }

    default int init(long ref, int oppmode, byte[] keyBytes, byte[] iv, int tag_len) throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        try
        {
            return (int) handleError(ni_init(ref, oppmode, keyBytes, iv, tag_len));
        }
        catch (InvalidAlgorithmParameterException | InvalidKeyException ikex)
        {
            throw ikex;
        }
        catch (ShortBufferException | IllegalBlockSizeException | BadPaddingException others)
        {
            throw new RuntimeException(others.getMessage(), others);
        }

    }

    default int getBlockSize(long ref)
    {

        try
        {
            return (int) handleError(ni_getBlockSize(ref));
        }
        catch (InvalidKeyException | InvalidAlgorithmParameterException | ShortBufferException |
               IllegalBlockSizeException | BadPaddingException others)
        {
            throw new RuntimeException(others.getMessage(), others);
        }

    }

    default int update(long ref, byte[] output, int outputOffset, byte[] input, int inputOffset, int inputLen) throws ShortBufferException, IllegalBlockSizeException
    {
        try
        {
            return (int) handleError(ni_update(ref, output, outputOffset, input, inputOffset, inputLen));
        }
        catch (ShortBufferException | IllegalBlockSizeException ex)
        {
            throw ex;
        }
        catch (InvalidKeyException | InvalidAlgorithmParameterException |
               BadPaddingException others)
        {
            throw new RuntimeException(others.getMessage(), others);
        }

    }

    default int doFinal(long ref, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException
    {

        try
        {
            return (int) handleError(ni_doFinal(ref, output, outputOffset));
        }
        catch (ShortBufferException | IllegalBlockSizeException | BadPaddingException gsecEx)
        {
            throw gsecEx;
        }
        catch (InvalidKeyException | InvalidAlgorithmParameterException others)
        {
            throw new RuntimeException(others.getMessage(), others);
        }

    }

    default int updateAAD(long ref, byte[] input, int inputOffset, int inputLen)
    {
        try
        {
            return (int) handleError(ni_updateAAD(ref, input, inputOffset, inputLen));
        }
        catch (InvalidKeyException | InvalidAlgorithmParameterException | ShortBufferException |
               IllegalBlockSizeException | BadPaddingException others)
        {
            throw new RuntimeException(others.getMessage(), others);
        }
    }

    default int getFinalSize(long ref, int length)
    {
        try
        {
            return (int) handleError(ni_getFinalSize(ref, length));
        }
        catch (InvalidKeyException | InvalidAlgorithmParameterException | ShortBufferException |
               IllegalBlockSizeException | BadPaddingException others)
        {
            throw new RuntimeException(others.getMessage(), others);
        }
    }

    default int getUpdateSize(long ref, int length)
    {
        try
        {
            return (int) handleError(ni_getUpdateSize(ref, length));
        }
        catch (InvalidKeyException | InvalidAlgorithmParameterException | ShortBufferException |
               IllegalBlockSizeException | BadPaddingException others)
        {
            throw new RuntimeException(others.getMessage(), others);
        }
    }

    default void dispose(long ref)
    {
        ni_dispose(ref);
    }


    default long handleError(long code) throws InvalidKeyException, InvalidAlgorithmParameterException, ShortBufferException, IllegalBlockSizeException, BadPaddingException
    {

        if (code >= 0)
        {
            return code;
        }

        ErrorCode codes = ErrorCode.forCode(code);
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
                throw new InvalidKeyException("invalid key length");
            case JO_INVALID_IV_LEN:
                throw new InvalidAlgorithmParameterException("invalid iv length");
            case JO_INVALID_MODE: // CBC, ECB, etc
                throw new InvalidAlgorithmParameterException("mode not supported for cipher");
            case JO_INVALID_OP_MODE: // Encrypt, Decrypt, Wrap, Unwrap etc
                throw new IllegalStateException("invalid operation mode");
            case JO_INVALID_TAG_LEN:
                throw new IllegalArgumentException("invalid tag len");
            case JO_TAG_IS_NULL:
                throw new IllegalArgumentException("tag is null");
            case JO_OUTPUT_OUT_OF_RANGE:
                throw new IllegalArgumentException("output offset + length is out of range");
            case JO_OUTPUT_TOO_SMALL:
                throw new ShortBufferException("output too small");
            case JO_NOT_BLOCK_ALIGNED:
                throw new IllegalBlockSizeException("data not block size aligned");
            case JO_CTR_MODE_OVERFLOW:
                throw new IllegalStateException("ctr mode overflow");
            case JO_INVALID_CIPHER_TEXT:
                throw new BadPaddingException("invalid cipher text");
            case JO_TAG_INVALID:
                throw new AEADBadTagException("bad tag");
            default:

        }
        return baseErrorHandler(codes.getCode());
    }


}
