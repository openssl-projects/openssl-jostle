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

package org.openssl.jostle.jcajce.provider.ed;

import org.openssl.jostle.jcajce.spec.OSSLKeyType;

final class EdDSALengths
{
    static final int UNKNOWN_SIGNATURE_LENGTH = -1;

    private EdDSALengths()
    {
    }

    static int getSignatureLength(OSSLKeyType type)
    {
        if (type == null)
        {
            return UNKNOWN_SIGNATURE_LENGTH;
        }

        switch (type)
        {
            case ED25519:
            case Ed25519ctx:
            case Ed25519ph:
                return 64;
            case ED448:
            case ED448ph:
                return 114;
            default:
                return UNKNOWN_SIGNATURE_LENGTH;
        }
    }
}
