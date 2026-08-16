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

import org.openssl.jostle.jcajce.provider.DefaultServiceNI;
import org.openssl.jostle.jcajce.provider.ErrorCode;

/**
 * Native entry points for the memory-hard password KDFs — scrypt (RFC 7914)
 * and Argon2 (RFC 9106).
 *
 * <p>These are split out of {@link KdfNI} rather than sharing it because
 * neither algorithm is served by the OpenSSL FIPS provider (in OpenSSL 3.6.2
 * both build only into {@code libdefault.a} and neither appears in
 * {@code fipsprov.c}), and neither is registered by {@code ProvFIPSKDF}. Keeping
 * them on their own interface means the FIPS interface library carries no
 * bridge code, and exports no symbols, for algorithms outside the validated
 * boundary — so an audit of that library finds only approved-algorithm glue.
 * {@link KdfNI} keeps PBKDF2 and HKDF, which the FIPS module does serve.</p>
 *
 * <p>Implemented only by the JSL bridges ({@code MemoryHardKdfNIJNI},
 * {@code MemoryHardKdfNIFFI}); there is deliberately no FIPS counterpart.</p>
 */
public interface MemoryHardKdfNI extends DefaultServiceNI
{
    int scrypt(byte[] password, byte[] salt, int n, int r, int p, byte[] out, int outOffset, int outLen);

    /**
     * Argon2 (RFC 9106). {@code type} is 0=Argon2d, 1=Argon2i, 2=Argon2id and
     * {@code version} is 0x10 or 0x13; the bridge validates both. {@code
     * memoryKiB} is the memory cost in kibibytes and must be at least
     * {@code 8 * lanes}.
     */
    int argon2(byte[] password, byte[] salt, int type, int version, int iterations, int memoryKiB,
               int lanes, byte[] out, int outOffset, int outLen);

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
            case JO_KDF_SCRYPT_N_TOO_SMALL:
                throw new IllegalArgumentException("n is less than 2");
            case JO_KDF_SCRYPT_N_NOT_POW2:
                throw new IllegalArgumentException("n not power of 2");
            case JO_KDF_SCRYPT_R_TOO_SMALL:
                throw new IllegalArgumentException("r is less than 1");
            case JO_KDF_SCRYPT_P_TOO_SMALL:
                throw new IllegalArgumentException("p is less than 1");
            case JO_KDF_ARGON2_TYPE_INVALID:
                throw new IllegalArgumentException("type is not a known Argon2 type");
            case JO_KDF_ARGON2_VERSION_INVALID:
                throw new IllegalArgumentException("version is not a known Argon2 version");
            case JO_KDF_ARGON2_ITER_TOO_SMALL:
                throw new IllegalArgumentException("iterations is less than 1");
            case JO_KDF_ARGON2_LANES_TOO_SMALL:
                throw new IllegalArgumentException("lanes is less than 1");
            case JO_KDF_ARGON2_MEMORY_TOO_SMALL:
                throw new IllegalArgumentException("memory is less than 8*lanes KiB");
            default:
        }
        return baseErrorHandler(code);
    }
}
