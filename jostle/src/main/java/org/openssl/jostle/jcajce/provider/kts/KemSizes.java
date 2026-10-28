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

import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.rand.RandSource;

/**
 * The encapsulation and shared-secret lengths of a KEM key, asked of its own library once per key type and memoised
 * on that library's spec NI. No per-type value lives here: a later answer that disagrees with the memo is refused
 * before anything is allocated from it.
 */
public final class KemSizes
{
    private KemSizes()
    {
    }

    /** The shared-secret length of the key, from its library's memo. */
    public static int sharedSecretLength(PKEYKeySpec key, RandSource randSource)
    {
        return key.getSpecNI().sharedSecretLength(key.getReference(), key.getType(), randSource);
    }

    /** The encapsulation length of the key, from its library's memo. */
    public static int ciphertextLength(PKEYKeySpec key, RandSource randSource)
    {
        int secret = sharedSecretLength(key, randSource);
        return key.getSpecNI().encapsulationLength(key.getReference(), key.getType(), secret, randSource);
    }

    /**
     * An encapsulation length the key's library reported, when it agrees with that library's memo.
     *
     * @throws IllegalStateException when it does not.
     */
    public static int checkedCiphertextLength(PKEYKeySpec key, long reported)
    {
        return key.getSpecNI().boundedEncapsulationLength(key.getType(), reported);
    }

    /**
     * A shared-secret length the key's library reported, when it agrees with that library's memo.
     *
     * @throws IllegalStateException when it does not.
     */
    public static int checkedSharedSecretLength(PKEYKeySpec key, long reported)
    {
        return key.getSpecNI().boundedSharedSecretLength(key.getType(), reported);
    }
}
