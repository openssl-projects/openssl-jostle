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

package org.openssl.jostle.test.dh;

import javax.crypto.KeyAgreement;
import java.security.InvalidKeyException;
import java.security.Key;

/**
 * The phase call and the secret call, for the cells that drive them in a chosen order. Every such cell calls
 * these two methods rather than the KeyAgreement methods themselves.
 */
public final class KeyAgreementCalls
{
    private KeyAgreementCalls()
    {
    }

    /** The phase call, last phase. */
    public static void phase(KeyAgreement ka, Key key) throws InvalidKeyException
    {
        ka.doPhase(key, true);
    }

    /** The secret call. */
    public static byte[] secret(KeyAgreement ka)
    {
        return ka.generateSecret();
    }
}
