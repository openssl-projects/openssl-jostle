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

import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.provider.cache.NativeLengthBound;
import org.openssl.jostle.jcajce.provider.cache.NativeLengthCache;
import org.openssl.jostle.jcajce.provider.DefaultServiceNI;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.rand.RandSource;

public interface SLHDSAServiceNI extends DefaultServiceNI
{

    long ni_generateKeyPair(int type, int[] err, RandSource randSource);

    long ni_generateKeyPair(int type, int[] err, byte[] seed, int seedLen, RandSource randSource);

    int ni_getPrivateKey(long reference, byte[] output);

    int ni_getPublicKey(long reference, byte[] output);

    int ni_decode_publicKey(long spec_ref, int keyType, byte[] input, int inputOffset, int inputLen);

    int ni_decode_privateKey(long spec_ref, int keyType, byte[] input, int inputOffset, int inputLen);

    long ni_allocateSigner(int[] err);

    int ni_initVerify(long ref, long keyRef, byte[] context, int contextLen, int messageEncoding, int deterministic);

    int ni_update(long ref, byte[] b, int off, int len);

    int ni_sign(long ref, byte[] sig, int offset, RandSource randSource);

    int ni_verify(long reference, byte[] sigBytes, int len);

    int ni_initSign(long reference, long keyRef, byte[] context, int contextLen, int messageEncoding, int deterministic, RandSource randSource);

    void ni_disposeSigner(long reference);


    default long generateKeyPair(int type, RandSource randSource)
    {
        int[] err = new int[1];
        long r = ni_generateKeyPair(type, err, randSource);
        handleErrors(err[0]);
        return r;
    }

    default long generateKeyPair(int type, byte[] seed, int seedLen, RandSource randSource)
    {
        int[] err = new int[1];
        long r = ni_generateKeyPair(type, err, seed, seedLen, randSource);
        handleErrors(err[0]);
        return r;
    }

    default int getPrivateKey(long reference, byte[] output)
    {
        return (int) handleErrors(ni_getPrivateKey(reference, output));
    }


    default int getPublicKey(long reference, byte[] output)
    {
        return (int) handleErrors(ni_getPublicKey(reference, output));
    }

    default int decode_publicKey(long spec_ref, int keyType, byte[] input, int inputOffset, int inputLen)
    {
        return (int) handleErrors(ni_decode_publicKey(spec_ref, keyType, input, inputOffset, inputLen));
    }

    default int decode_privateKey(long spec_ref, int keyType, byte[] input, int inputOffset, int inputLen)
    {
        return (int) handleErrors(ni_decode_privateKey(spec_ref, keyType, input, inputOffset, inputLen));
    }

    default long allocateSigner()
    {
        int[] err = new int[1];
        long r = ni_allocateSigner(err);
        handleErrors(err[0]);
        return r;
    }

    /** A contextLen of -1 is the same as a 0-byte context for this family. */
    default int initVerify(long ref, long keyRef, byte[] context, int contextLen, int messageEncoding, int deterministic)
    {
        return (int) handleErrors(ni_initVerify(ref, keyRef, context, contextLen, messageEncoding, deterministic));
    }

    default int update(long ref, byte[] b, int off, int len)
    {
        return (int) handleErrors(ni_update(ref, b, off, len));
    }

    default int sign(long ref, byte[] sig, int offset, RandSource randSource)
    {
        return (int) handleErrors(ni_sign(ref, sig, offset, randSource));
    }

    default int verify(long reference, byte[] sigBytes, int len)
    {
        int code = ni_verify(reference, sigBytes, len);
        if (code == ErrorCode.JO_FAIL.getCode())
        {
            // Fail is a signature that does not verify.
            return code;
        }
        return (int) handleErrors(code);
    }

    /** A contextLen of -1 is the same as a 0-byte context for this family. */
    default int initSign(long reference, long keyRef, byte[] context, int contextLen, int messageEncoding, int deterministic, RandSource randSource)
    {
        return (int) handleErrors(ni_initSign(reference, keyRef, context, contextLen, messageEncoding, deterministic, randSource));
    }

    default void disposeSigner(long reference)
    {
        ni_disposeSigner(reference);
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

    /** This implementation's memo; one per instance, so a length belongs to its library. */
    NativeLengthCache<OSSLKeyType> lengthCache();

    /**
     * The signature length for the signer {@code ref}, asked of this library once
     * per key type. A null type probes without caching (a variable-length path).
     */
    default int signatureLength(long ref, OSSLKeyType type, RandSource randSource)
    {
        int len = lengthCache().get(type);
        if (len == NativeLengthCache.UNKNOWN)
        {
            len = sign(ref, null, 0, randSource);
            lengthCache().cache(type, len);
        }
        return len;
    }

    /** The parts of an SLH-DSA key whose encoded length the library reports. */
    enum KeyPart
    {
        PUBLIC, PRIVATE
    }

    /** This implementation's memo of key encoding lengths, keyed by type and part. */
    NativeLengthCache<String> keyLengthCache();

    /** A key encoding length the library reported, bounded by the first answer for the type and part. */
    default int boundedKeyLength(OSSLKeyType type, KeyPart part, long reported)
    {
        return NativeLengthBound.bounded(keyLengthCache(), type.name(), part.name(), reported);
    }
}
