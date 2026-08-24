/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.mac;

import org.openssl.jostle.jcajce.provider.DefaultServiceNI;
import org.openssl.jostle.jcajce.provider.ErrorCode;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;

public interface MacServiceNI extends DefaultServiceNI
{
    long ni_allocateMac(String macName, String canonicalDigestName, int[] err);

    long ni_copyMac(long ref, int[] err);

    /**
     * @param iv     GMAC's nonce, or {@code null} for every other MAC. Carried
     *               on the init call rather than a separate entry point because
     *               the IV is an init-time input exactly like the key, and one
     *               door means "GMAC requires an IV" is a single check in the
     *               native GMAC arm rather than a rejection that a second entry
     *               point could bypass.
     * @param custom KMAC's customisation string {@code S}, or {@code null} for
     *               every other MAC — and legitimately {@code null} for KMAC
     *               too, where it is optional. Same one-door reasoning as the
     *               IV.
     * @param outLen KMAC's requested output length in bytes, or {@code 0} for
     *               "unspecified", which leaves the algorithm's own default in
     *               force. Never pass a caller's literal zero through as a
     *               length request: OpenSSL accepts {@code size=0} on most
     *               builds and then produces a zero-length MAC.
     */
    int ni_init(long ref, byte[] keyBytes, byte[] iv, byte[] custom, int outLen);

    int ni_updateByte(long ref, byte b);

    int ni_updateBytes(long ref, byte[] in, int inOff, int inLen);

    int ni_doFinal(long ref, byte[] out, int outOff);

    int ni_getMacLength(long ref);

    // Keyless MAC length from OpenSSL metadata (digest size / cipher block
    // size), usable before init. See native mac_len_for.
    int ni_macLengthMeta(long ref);

    int ni_reset(long ref);

    void ni_dispose(long ref);



    default long allocateMac(String macName, String functionName)
    {
        int[] err = new int[1];
        long v = ni_allocateMac(macName, functionName, err);
        handleErrors(err[0]);
        return v;
    }

    // Clone the native MAC state (EVP_MAC_CTX_dup). Returns a fresh native
    // handle that the caller wraps in its own NativeReference/Disposer.
    default long copyMac(long ref)
    {
        int[] err = new int[1];
        long v = ni_copyMac(ref, err);
        handleErrors(err[0]);
        return v;
    }

    default void engineInit(long ref, byte[] keyBytes, byte[] iv, byte[] custom, int outLen)
            throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        handleInitErrors(ni_init(ref, keyBytes, iv, custom, outLen));
    }

    default void engineUpdate(long ref, byte b)
    {
        handleErrors(ni_updateByte(ref, b));
    }

    default void engineUpdate(long ref, byte[] in, int inOff, int inLen)
    {
        handleErrors(ni_updateBytes(ref, in, inOff, inLen));
    }

    default int doFinal(long ref, byte[] out, int outOff)
    {
        return (int) handleErrors(ni_doFinal(ref, out, outOff));
    }

    default int getMacLength(long ref)
    {
        return (int) handleErrors(ni_getMacLength(ref));
    }

    default int macLengthMeta(long ref)
    {
        return (int) handleErrors(ni_macLengthMeta(ref));
    }

    default void reset(long ref)
    {
        handleErrors( ni_reset(ref));
    }

    default void dispose(long ref)
    {
        ni_dispose(ref);
    }




    default long handleInitErrors(int code)
            throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        if (code >= 0)
        {
            return code;
        }

        ErrorCode ec = ErrorCode.forCode(code);
        switch (ec)
        {
            case JO_KEY_IS_NULL:
                throw new InvalidKeyException("key is null");
            case JO_FAILED_ACCESS_KEY:
                throw new InvalidKeyException("unable to access key bytes");
            case JO_UNKNOWN_KEY_LEN:
                throw new InvalidKeyException("invalid key length for mac type");
            // GMAC only: the native GMAC arm is the sole place that knows this
            // MAC needs a nonce. Same message and type as BlockCipherNI's, so
            // an IV-less AEAD init reads identically wherever it is raised.
            case JO_IV_IS_NULL:
                throw new InvalidAlgorithmParameterException("iv is null");
            case JO_FAILED_ACCESS_IV:
                throw new IllegalStateException("native layer was unable to access iv");
            // NI surface only: MacServiceSPI refuses the spec for every MAC but
            // GMAC, so a caller reaches this by driving ni_init directly.
            case JO_MODE_TAKES_NO_IV:
                throw new InvalidAlgorithmParameterException("mac takes no iv");
            // KMAC only, and NI surface only for the same reason: the SPI
            // refuses a KMACParameterSpec for every other MAC, so these are
            // reached by driving ni_init directly.
            case JO_MAC_TAKES_NO_CUSTOM:
                throw new InvalidAlgorithmParameterException("mac takes no customisation string");
            case JO_MAC_TAKES_NO_OUTPUT_LEN:
                throw new InvalidAlgorithmParameterException("mac takes no output length");
            case JO_FAILED_ACCESS_CUSTOM:
                throw new IllegalStateException("native layer was unable to access customisation string");
            case JO_OUTPUT_LEN_IS_NEGATIVE:
                throw new InvalidAlgorithmParameterException("output length is negative");

            default:

        }
        return baseErrorHandler(code);
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
            case JO_MAC_FUNCTION_IS_NULL:
                throw new NullPointerException("mac function name is null");
            case JO_UNABLE_TO_ACCESS_FUNCTION:
                throw new IllegalStateException("unable to access function");
            case JO_OUTPUT_OUT_OF_RANGE:
                throw new IllegalArgumentException("output offset + mac len is out of range");
            default:

        }
        return baseErrorHandler(code);
    }
}
