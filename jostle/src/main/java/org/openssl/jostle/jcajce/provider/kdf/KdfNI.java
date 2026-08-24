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

    /**
     * SP 800-108 KBKDF. {@code mode} is "COUNTER" or "FEEDBACK"; {@code mac} is
     * "HMAC" (with {@code digest}) or "CMAC" (with {@code cipher}) — the unused
     * one of the pair is null. {@code label} and {@code context} are optional.
     *
     * <p>{@code useL} and {@code useSeparator} are 0/1 and are always passed
     * explicitly: OpenSSL defaults both to 1 (the SP 800-108 fixed-input form)
     * while BouncyCastle and the NIST CAVP vectors use the raw form with
     * neither, and the difference is invisible in a round trip.</p>
     */
    int kbkdf(String mode, String mac, String digest, String cipher,
              byte[] key, byte[] label, byte[] context, byte[] seed,
              int r, int useL, int useSeparator,
              byte[] out, int outOffset, int outLen);

    /**
     * SP 800-56C one-step KDF over a digest. There is deliberately no salt
     * parameter — {@code OSSL_KDF_PARAM_SALT} is settable on the ctx but was
     * measured to be silently ignored in digest mode on every supported
     * OpenSSL build, so exposing it would let a caller vary a knob that does
     * nothing.
     */
    int sskdf(String digest, byte[] secret, byte[] info, byte[] out, int outOffset, int outLen);

    /**
     * RFC 4253 section 7.2 SSH key derivation. Every input is mandatory;
     * {@code type} is a single letter A–F selecting which of the six keys is
     * produced.
     */
    int sshkdf(String digest, byte[] key, byte[] xcghash, byte[] sessionId, String type,
               byte[] out, int outOffset, int outLen);

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
            case JO_KDF_SECRET_NULL:
                throw new IllegalArgumentException("secret is null");
            case JO_KDF_SECRET_FAILED_ACCESS:
                throw new AccessException("unable to access secret array");
            case JO_KDF_INFO_FAILED_ACCESS:
                throw new AccessException("unable to access context array");
            case JO_KDF_UNKNOWN_MODE:
                throw new IllegalArgumentException("unknown mode");
            case JO_KDF_UNKNOWN_MAC:
                throw new IllegalArgumentException("unknown mac");
            case JO_KDF_SSHKDF_TYPE_INVALID:
                throw new IllegalArgumentException("ssh key type is null or empty");
            case JO_KDF_SSHKDF_XCGHASH_NULL:
                throw new IllegalArgumentException("exchange hash is null");
            case JO_KDF_SSHKDF_XCGHASH_FAILED_ACCESS:
                throw new AccessException("unable to access exchange hash array");
            case JO_KDF_SSHKDF_SESSION_ID_NULL:
                throw new IllegalArgumentException("session id is null");
            case JO_KDF_SSHKDF_SESSION_ID_FAILED_ACCESS:
                throw new AccessException("unable to access session id array");
            case JO_OUTPUT_LEN_IS_ZERO:
                throw new IllegalArgumentException("output len is zero");
            case JO_KDF_SEED_FAILED_ACCESS:
                throw new AccessException("unable to access seed array");
            default:
        }
        return baseErrorHandler(code);
    }

}
