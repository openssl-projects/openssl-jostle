package org.openssl.jostle.jcajce.provider.kdf;

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
            default:
                throw new IllegalStateException("unexpected error code " + errorCode + ": " + code);
        }
    }

}
