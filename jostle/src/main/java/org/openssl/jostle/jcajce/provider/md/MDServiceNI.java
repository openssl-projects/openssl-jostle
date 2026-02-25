package org.openssl.jostle.jcajce.provider.md;

import org.openssl.jostle.jcajce.provider.AccessException;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.OpenSSL;
import org.openssl.jostle.jcajce.provider.OpenSSLException;


public interface MDServiceNI
{

    long ni_allocateDigest(String name, int xofLen, int[] err);

    int ni_updateByte(long ref, byte b);

    int ni_updateBytes(long ref, byte[] input, int offset, int len);

    void ni_dispose(long reference);

    int ni_getDigestOutputLen(long ref);

    int ni_digest(long ref, byte[] out, int offset, int length);

    void ni_reset(long ref);


    // Allocate state for digest
    default long allocateDigest(String name, int xofLen)
    {
        int[] err = new int[1];
        long v = ni_allocateDigest(name, xofLen, err);
        handleErrors(err[0]);
        return v;
    }


    default void engineUpdate(long ref, byte b)
    {
        handleErrors(ni_updateByte(ref, b));
    }

    default void engineUpdate(long ref, byte[] input, int offset, int len)
    {
        handleErrors(ni_updateBytes(ref, input, offset, len));
    }

    default void dispose(long ref)
    {
        ni_dispose(ref);
    }

    default int getDigestOutputLen(long ref)
    {
        return (int) handleErrors(ni_getDigestOutputLen(ref));
    }

    default int digest(long ref, byte[] out, int offset, int length)
    {
        return (int) handleErrors(ni_digest(ref, out, offset, length));
    }

    default void reset(long ref)
    {
        ni_reset(ref);
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
            case JO_SUCCESS:
                return code;
            case JO_NOT_INITIALIZED:
                throw new IllegalStateException("not initialized");
            case JO_NAME_IS_NULL:
                throw new NullPointerException("name is null");
            case JO_NAME_NOT_FOUND:
                throw new IllegalArgumentException("name not found");
            case JO_UNABLE_TO_ACCESS_NAME:
                throw new IllegalStateException("unable to access name");
            case JO_MD_CREATE_FAILED:
                throw new IllegalStateException("md create failed");
            case JO_MD_INIT_FAILED:
                throw new IllegalStateException("md init failed");
            case JO_MD_DIGEST_LEN_INT_OVERFLOW:
                throw new IllegalStateException("digest len overflow");
            case JO_MD_SET_PARAM_FAIL:
                throw new IllegalStateException("md unable to set param");
            case JO_INPUT_IS_NULL:
                throw new NullPointerException("input is null");
            case JO_INPUT_OFFSET_IS_NEGATIVE:
                throw new IllegalArgumentException("input offset negative");
            case JO_INPUT_LEN_IS_NEGATIVE:
                throw new IllegalArgumentException("input len negative");
            case JO_INPUT_OUT_OF_RANGE:
                throw new IllegalArgumentException("input offset + length out of range");
            case JO_FAILED_ACCESS_INPUT:
                    throw new AccessException("unable to access input array");
            case JO_FAILED_ACCESS_OUTPUT:
                throw new AccessException("unable to access output array");
            case JO_OUTPUT_LEN_IS_NEGATIVE:
                throw new IllegalArgumentException("output len negative");
            case JO_OUTPUT_OFFSET_IS_NEGATIVE:
                throw new IllegalArgumentException("output offset negative");
            case JO_OUTPUT_TOO_SMALL:
                throw new IllegalArgumentException("output too small");
            case JO_OUTPUT_OUT_OF_RANGE:
                throw new IllegalArgumentException("output offset + length out of range");
            case JO_OPENSSL_ERROR:
                throw new OpenSSLException(String.format("OpenSSL Error: %s", OpenSSL.getOpenSSLErrors()));
            default:
        }

        throw new IllegalStateException(String.format("Unhandled Error: %s", errorCode));
    }


}
