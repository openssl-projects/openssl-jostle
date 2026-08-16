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

import org.openssl.jostle.jcajce.provider.AccessException;
import org.openssl.jostle.jcajce.provider.ErrorCode;

/**
 * The password/salt bridge rejections shared by every password-based KDF.
 *
 * <p>{@link KdfNI} and {@link MemoryHardKdfNI} are deliberately separate
 * interfaces (see {@code MemoryHardKdfNI} for why), but both surface the same
 * codes for the same inputs — the C bridges use one set of password/salt
 * checks. Mapping them here keeps the two interfaces' messages from drifting,
 * which limit tests on both sides assert by exact text.</p>
 */
final class KdfInputErrors
{
    private KdfInputErrors()
    {
    }

    /**
     * Throws the typed exception for a shared password/salt rejection, or
     * returns normally if {@code errorCode} is not one of them.
     */
    static void throwIfInputError(ErrorCode errorCode)
    {
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
            default:
        }
    }
}
