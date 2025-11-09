package org.openssl.jostle.jcajce.provider.kdf;

import org.openssl.jostle.jcajce.provider.AccessException;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.OpenSSL;
import org.openssl.jostle.jcajce.provider.OpenSSLException;

public interface KdfNI
{
    int scrypt(byte[] password, byte[] salt, int n, int r, int p, byte[] out, int outOffset, int outLen);

    int pbkdf2(byte[] password, byte[] salt, int iter, String digest, byte[] out, int outOffset, int outLen);

    int pkcs12(byte[] password, byte[] salt, int iter, String digest, byte[] out, int outOffset, int outLen);

    default int handleErrorCodes(int code)
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
                throw new OpenSSLException(OpenSSL.getOpenSSLErrors());
            case JO_KDF_PASSWORD_FAILED_ACCESS:
                throw new AccessException("unable to access password array");
            case JO_KDF_SALT_FAILED_ACCESS:
                throw new AccessException("unable to access salt array");
            case JO_FAILED_ACCESS_OUTPUT:
                throw new AccessException("unable to access output array");
            case JO_KDF_PASSWORD_NULL:
                throw new IllegalArgumentException("password is null");
            case JO_KDF_SALT_NULL:
                throw new IllegalArgumentException("salt is null");
            case JO_KDF_SALT_EMPTY:
                throw new IllegalArgumentException("salt is empty");
            case JO_KDF_PBE_ITER_NEGATIVE:
                throw new IllegalArgumentException("iter is negative");
            case JO_OUTPUT_IS_NULL:
                throw new IllegalArgumentException("output is null");
            case JO_OUTPUT_OFFSET_IS_NEGATIVE:
                throw new IllegalArgumentException("output offset is negative");
            case JO_OUTPUT_LEN_IS_NEGATIVE:
                throw new IllegalArgumentException("output length is negative");
            case JO_OUTPUT_OUT_OF_RANGE:
                throw new IllegalArgumentException("output offset and length out of range");
            case JO_KDF_PBE_UNKNOWN_DIGEST:
                throw new IllegalArgumentException("unknown digest");
            case JO_KDF_SCRYPT_N_TOO_SMALL:
                throw new IllegalArgumentException("n is less than 2");
            case JO_KDF_SCRYPT_N_NOT_POW2:
                throw new IllegalArgumentException("n not power of 2");
            case JO_KDF_SCRYPT_R_NEGATIVE:
                throw new IllegalArgumentException("r is negative");
            case JO_KDF_SCRYPT_P_NEGATIVE:
                throw new IllegalArgumentException("p is negative");
            default:
                throw new IllegalStateException("unexpected error code " + errorCode + ": " + code);
        }
    }

}
