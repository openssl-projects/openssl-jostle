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

/**
 * Native entry points for the KDFs both providers serve: PBKDF2 and HKDF, each
 * an approved service of the OpenSSL FIPS module.
 *
 * <p>The memory-hard password KDFs (scrypt, Argon2) are NOT here — they live on
 * {@link MemoryHardKdfNI} so the FIPS interface library carries no bridge code
 * for algorithms outside the validated boundary. See that interface for the
 * rationale.</p>
 */
public interface KdfNI extends DefaultServiceNI
{
    int pbkdf2(byte[] password, byte[] salt, int iter, String digest, byte[] out, int outOffset, int outLen);

    int hkdf(byte[] ikm, byte[] salt, byte[] info, String digest, byte[] out, int outOffset, int outLen);

    default long handleErrorCodes(int code)
    {
        if (code >= 0)
        {
            return code;
        }
        ErrorCode errorCode = ErrorCode.forCode(code);
        KdfInputErrors.throwIfInputError(errorCode);
        switch (errorCode)
        {
            case JO_KDF_PBE_ITER_NEGATIVE:
                throw new IllegalArgumentException("iter is negative");
            case JO_KDF_PBE_UNKNOWN_DIGEST:
                throw new IllegalArgumentException("unknown digest");
            case JO_KDF_HKDF_IKM_NULL:
                throw new IllegalArgumentException("ikm is null");
            case JO_KDF_HKDF_IKM_FAILED_ACCESS:
                throw new AccessException("unable to access ikm array");
            case JO_KDF_HKDF_INFO_FAILED_ACCESS:
                throw new AccessException("unable to access info array");
            default:
        }
        return baseErrorHandler(code);
    }

}
