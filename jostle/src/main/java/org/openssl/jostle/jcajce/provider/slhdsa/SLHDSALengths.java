/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.slhdsa;

import org.openssl.jostle.jcajce.spec.OSSLKeyType;

final class SLHDSALengths
{
    static final int UNKNOWN_SIGNATURE_LENGTH = -1;

    private SLHDSALengths()
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
            case SLH_DSA_SHA2_128s:
            case SLH_DSA_SHAKE_128s:
                return 7856;
            case SLH_DSA_SHA2_128f:
            case SLH_DSA_SHAKE_128f:
                return 17088;
            case SLH_DSA_SHA2_192s:
            case SLH_DSA_SHAKE_192s:
                return 16224;
            case SLH_DSA_SHA2_192f:
            case SLH_DSA_SHAKE_192f:
                return 35664;
            case SLH_DSA_SHA2_256s:
            case SLH_DSA_SHAKE_256s:
                return 29792;
            case SLH_DSA_SHA2_256f:
            case SLH_DSA_SHAKE_256f:
                return 49856;
            default:
                return UNKNOWN_SIGNATURE_LENGTH;
        }
    }

}
