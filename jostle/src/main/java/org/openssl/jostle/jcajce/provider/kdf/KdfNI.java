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

package org.openssl.jostle.jcajce.provider.kdf;

import org.openssl.jostle.jcajce.provider.*;

public interface KdfNI extends DefaultServiceNI
{
    int scrypt(byte[] password, byte[] salt, int n, int r, int p, byte[] out, int outOffset, int outLen);

    int pbkdf2(byte[] password, byte[] salt, int iter, String digest, byte[] out, int outOffset, int outLen);

    /**
     * HKDF (RFC 5869) extract-then-expand. Per the RFC, only IKM and the
     * digest name are mandatory; salt and info are optional and may be
     * passed as {@code null}.
     */
    int hkdf(byte[] ikm, byte[] salt, byte[] info, String digest, byte[] out, int outOffset, int outLen);

    /**
     * ANSI X9.63 KDF. {@code z} is the secret to derive from (typically
     * the raw bytes from an ECDH agreement); {@code sharedInfo} is the
     * optional context-binding "UserKeyingMaterial" — may be {@code null}.
     */
    int x963kdf(byte[] z, byte[] sharedInfo, String digest, byte[] out, int outOffset, int outLen);

    default long handleErrorCodes(int code)
    {
        if (code >= 0)
        {
            return code;
        }
        ErrorCode errorCode = ErrorCode.forCode(code);
        switch (errorCode)
        {
            case JO_KDF_PASSWORD_FAILED_ACCESS:
                throw new AccessException("unable to access password array");
            case JO_KDF_SALT_FAILED_ACCESS:
                throw new AccessException("unable to access salt array");
            case JO_KDF_PASSWORD_NULL:
                throw new IllegalArgumentException("password is null");
            case JO_KDF_SALT_NULL:
                throw new IllegalArgumentException("salt is null");
            case JO_KDF_SALT_EMPTY:
                throw new IllegalArgumentException("salt is empty");
            case JO_KDF_PBE_ITER_NEGATIVE:
                throw new IllegalArgumentException("iter is negative");
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
            case JO_KDF_HKDF_IKM_NULL:
                throw new IllegalArgumentException("HKDF IKM is null");
            case JO_KDF_HKDF_IKM_FAILED_ACCESS:
                throw new AccessException("unable to access HKDF IKM array");
            case JO_KDF_HKDF_INFO_FAILED_ACCESS:
                throw new AccessException("unable to access HKDF info array");
            case JO_KDF_X963KDF_Z_NULL:
                throw new IllegalArgumentException("X9.63 KDF Z is null");
            case JO_KDF_X963KDF_Z_FAILED_ACCESS:
                throw new AccessException("unable to access X9.63 KDF Z array");
            case JO_KDF_X963KDF_INFO_FAILED_ACCESS:
                throw new AccessException("unable to access X9.63 KDF shared-info array");
            default:
        }
        return baseErrorHandler(code);
    }

}
