/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.kts;

import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.rand.RandSource;

import java.security.ProviderException;

/**
 * The encapsulation and shared-secret lengths of a KEM key, asked of its own library once per key type through
 * the spec NI's caches, and bounded before anything is allocated from them. No per-type value lives here: a
 * length the library reports above a ceiling is refused, naming both.
 */
public final class KemSizes
{
    /** Largest FIPS 203 ciphertext (1568) plus the largest hybrid share, a SEC 1 uncompressed P-384 point (97). */
    static final int CIPHERTEXT_CEILING = 1568 + 97;

    /** Largest composed shared secret: ML-KEM (32) plus an X448 share (56). */
    static final int SECRET_CEILING = 32 + 56;

    private KemSizes()
    {
    }

    /**
     * The shared-secret length of the key, from its library's cached query.
     *
     * @throws ProviderException when the reported length is outside the ceiling.
     */
    public static int sharedSecretLength(PKEYKeySpec key, RandSource randSource)
    {
        return checkedSharedSecretLength(key.getType(),
                key.getSpecNI().sharedSecretLength(key.getReference(), key.getType(), randSource));
    }

    /**
     * The encapsulation length of the key, from its library's cached query.
     *
     * @throws ProviderException when the reported length is outside the ceiling.
     */
    public static int ciphertextLength(PKEYKeySpec key, RandSource randSource)
    {
        int secret = sharedSecretLength(key, randSource);
        return checkedCiphertextLength(key.getType(),
                key.getSpecNI().encapsulationLength(key.getReference(), key.getType(), secret, randSource));
    }

    /**
     * The queried encapsulation length, when it is within the ceiling.
     *
     * @throws ProviderException when it is not.
     */
    public static int checkedCiphertextLength(OSSLKeyType type, long queried)
    {
        return checked("encapsulation", type, queried, CIPHERTEXT_CEILING);
    }

    /**
     * The queried shared-secret length, when it is within the ceiling.
     *
     * @throws ProviderException when it is not.
     */
    public static int checkedSharedSecretLength(OSSLKeyType type, long queried)
    {
        return checked("shared secret", type, queried, SECRET_CEILING);
    }

    private static int checked(String what, OSSLKeyType type, long queried, int ceiling)
    {
        if (queried < 1 || queried > ceiling)
        {
            throw new ProviderException(type + " " + what + " length reported as " + queried
                    + ", outside the ceiling of " + ceiling);
        }
        return (int) queried;
    }
}
