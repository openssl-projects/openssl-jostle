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
import org.openssl.jostle.jcajce.provider.ErrorCode;

public interface RandServiceNI extends DefaultServiceNI
{
    int ni_randomBytes(byte[] output, int outputLen, int strength);

    int ni_instantiate(int strength, boolean predictionResistant);

    int ni_reseed(int strength, boolean predictionResistant);

    default void randomBytes(byte[] output, int outputLen, int strength)
    {
        handleErrors(ni_randomBytes(output, outputLen, strength));
    }

    default void instantiate(int strength, boolean predictionResistant)
    {
        handleErrors(ni_instantiate(strength, predictionResistant));
    }

    default void reseed(int strength, boolean predictionResistant)
    {
        handleErrors(ni_reseed(strength, predictionResistant));
    }

    default long handleErrors(long code)
    {
        if (code >= 0)
        {
            return code;
        }

        ErrorCode errorCode = ErrorCode.forCode(code);
        switch (errorCode)
        {
        case JO_RAND_INSUFFICIENT_STRENGTH:
            throw new IllegalArgumentException("insufficient random strength");
        case JO_RAND_NO_RESEED:
            throw new IllegalStateException("random reseed failed");
        default:
            break;
        }

        return baseErrorHandler(code);
    }
}
