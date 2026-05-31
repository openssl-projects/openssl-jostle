/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.mldsa;

import org.openssl.jostle.jcajce.spec.OSSLKeyType;

final class MLDSALengths
{
    static final int UNKNOWN_SIGNATURE_LENGTH = -1;

    private MLDSALengths()
    {
    }

    static int getSignatureLength(OSSLKeyType type, boolean calculateMu)
    {
        if (calculateMu)
        {
            return UNKNOWN_SIGNATURE_LENGTH;
        }

        if (type == null)
        {
            return UNKNOWN_SIGNATURE_LENGTH;
        }

        switch (type)
        {
            case ML_DSA_44:
                return 2420;
            case ML_DSA_65:
                return 3309;
            case ML_DSA_87:
                return 4627;
            default:
                return UNKNOWN_SIGNATURE_LENGTH;
        }
    }
}
