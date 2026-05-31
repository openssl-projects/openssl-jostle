/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.mlkem;

import org.openssl.jostle.jcajce.spec.OSSLKeyType;

final class MLKEMLengths
{
    static final int UNKNOWN_ENCAPSULATION_LENGTH = -1;

    private MLKEMLengths()
    {
    }

    static int getEncapsulationLength(OSSLKeyType type)
    {
        if (type == null)
        {
            return UNKNOWN_ENCAPSULATION_LENGTH;
        }

        switch (type)
        {
            case ML_KEM_512:
                return 768;
            case ML_KEM_768:
                return 1088;
            case ML_KEM_1024:
                return 1568;
            default:
                return UNKNOWN_ENCAPSULATION_LENGTH;
        }
    }
}
