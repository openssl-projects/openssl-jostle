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

package org.openssl.jostle.jcajce.provider.rand;

import org.openssl.jostle.jcajce.provider.DefaultServiceNI;

public interface RandServiceNI extends DefaultServiceNI
{
    int ni_randomBytes(byte[] output, int outputLen, int strength);

    default void randomBytes(byte[] output, int outputLen, int strength)
    {
        handleErrors(ni_randomBytes(output, outputLen, strength));
    }

    default long handleErrors(long code)
    {
        if (code >= 0)
        {
            return code;
        }

        return baseErrorHandler(code);
    }
}
