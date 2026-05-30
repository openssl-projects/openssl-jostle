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

package org.openssl.jostle.jcajce.provider.blockcipher;

import org.openssl.jostle.jcajce.provider.DefaultServiceNI;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.InvalidCipherTextException;
import org.openssl.jostle.jcajce.provider.OpenSSL;

/**
 * Native interface for the CCM authenticated-encryption mode. CCM
 * occupies its own NI surface (rather than going through
 * {@link BlockCipherNI}) because CCM is fundamentally one-shot — the
 * Java SPI buffers all AAD and plaintext / ciphertext, then hands
 * the complete buffers to {@link #ni_doFinal} in a single call.
 *
 * <p>See {@code interface/util/ccm_ctx.h} for the C-side mirror.
 */
public interface CCMCipherNI extends DefaultServiceNI
{
    // Cipher-family identifiers — mirror the constants in
    // interface/util/cipher_mode_pad.h.
    int AES128   = OSSLCipher.AES128.ordinal();
    int AES192   = OSSLCipher.AES192.ordinal();
    int AES256   = OSSLCipher.AES256.ordinal();
    int ARIA128  = OSSLCipher.ARIA128.ordinal();
    int ARIA192  = OSSLCipher.ARIA192.ordinal();
    int ARIA256  = OSSLCipher.ARIA256.ordinal();
    int SM4      = OSSLCipher.SM4.ordinal();

    // Op modes.
    int OP_ENCRYPT = javax.crypto.Cipher.ENCRYPT_MODE;
    int OP_DECRYPT = javax.crypto.Cipher.DECRYPT_MODE;


    long ni_makeInstance(int cipherId, int[] err);

    void ni_dispose(long ref);

    int ni_init(long ref, int opMode, byte[] key, byte[] iv, int tagLen);

    /**
     * Perform the full CCM operation in one shot.
     *
     * @param ref       native context ref
     * @param aad       AAD buffer (may be null when aadLen == 0)
     * @param aadLen    number of valid AAD bytes at start of {@code aad}
     * @param input     input buffer (plaintext for encrypt, ciphertext+tag for decrypt)
     * @param inOff     offset within {@code input}
     * @param inLen     valid bytes from {@code inOff}
     * @param output    output buffer
     * @param outOff    offset within {@code output}
     * @return bytes written on success; negative {@code JO_*} on failure
     *         ({@code JO_INVALID_CIPHER_TEXT} for decrypt-side tag check failure)
     */
    int ni_doFinal(long ref,
                   byte[] aad, int aadLen,
                   byte[] input, int inOff, int inLen,
                   byte[] output, int outOff);

    int ni_getOutputSize(long ref, int opMode, int inputLen);


    // Wrappers that map NI integer return codes to typed exceptions
    // via DefaultServiceNI.handleErrors. Mirrors RSAOAEPCipherNI's
    // pattern.

    default long makeInstance(int cipherId)
    {
        int[] err = new int[1];
        long ref = ni_makeInstance(cipherId, err);
        handleErrors(err[0]);
        return ref;
    }

    default void dispose(long ref)
    {
        ni_dispose(ref);
    }

    default void init(long ref, int opMode, byte[] key, byte[] iv, int tagLen)
    {
        handleErrors(ni_init(ref, opMode, key, iv, tagLen));
    }

    default int doFinal(long ref,
                        byte[] aad, int aadLen,
                        byte[] input, int inOff, int inLen,
                        byte[] output, int outOff)
    {
        return (int) handleErrors(
                ni_doFinal(ref, aad, aadLen, input, inOff, inLen, output, outOff));
    }

    default int getOutputSize(long ref, int opMode, int inputLen)
    {
        return (int) handleErrors(ni_getOutputSize(ref, opMode, inputLen));
    }


    /**
     * CCM-specific error mapping. The only CCM-specific case is
     * {@code JO_INVALID_CIPHER_TEXT} which the C side returns when
     * the tag check fails during decrypt — surfaced as
     * {@link InvalidCipherTextException} so the SPI can translate it
     * to {@link javax.crypto.AEADBadTagException} at the JCE layer.
     */
    default long handleErrors(long code)
    {
        if (code >= 0)
        {
            return code;
        }

        ErrorCode errorCode = ErrorCode.forCode(code);
        switch (errorCode)
        {
            case JO_INVALID_CIPHER_TEXT:
                throw new InvalidCipherTextException(
                        String.format("invalid cipher text: %s", OpenSSL.getOpenSSLErrors()));
            // The codes below are not handled by baseErrorHandler (it would
            // route them to its "unexpected error code" default arm), yet
            // they can surface through the CCM NI. Map them to the same
            // clean, unchecked exceptions BlockCipherNI uses. The checked
            // parameter-validation codes (JO_KEY_IS_NULL, JO_IV_IS_NULL,
            // JO_INVALID_IV_LEN, JO_INVALID_TAG_LEN, JO_INVALID_KEY_LEN) are
            // pre-validated by CCMCipherSpi, so they never reach here via
            // the JCE path and are intentionally not mapped (that would
            // force a checked-exception throws cascade on every wrapper).
            case JO_INVALID_OP_MODE:
                // CCM supports only ENCRYPT/DECRYPT, not WRAP/UNWRAP.
                throw new IllegalStateException("invalid operation mode");
            case JO_FAILED_ACCESS_KEY:
                throw new IllegalStateException("native layer was unable to access key");
            case JO_FAILED_ACCESS_IV:
                throw new IllegalStateException("native layer was unable to access iv");
            default:
        }

        return baseErrorHandler(code);
    }
}
