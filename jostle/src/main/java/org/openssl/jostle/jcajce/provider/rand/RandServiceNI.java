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
    long ni_createContext(int strength, boolean predictionResistant, byte[] personalizationString, int[] err);

    void ni_disposeContext(long reference);

    int ni_contextRandomBytes(long reference, byte[] output, int outputLen, int strength,
                              boolean predictionResistant, byte[] additionalInput);

    int ni_contextReseed(long reference, int strength, boolean predictionResistant, byte[] additionalInput);

    default long createContext(int strength, boolean predictionResistant, byte[] personalizationString)
    {
        int[] err = new int[1];
        long reference = ni_createContext(strength, predictionResistant, personalizationString, err);
        handleErrors(err[0]);
        return reference;
    }

    default void disposeContext(long reference)
    {
        ni_disposeContext(reference);
    }

    default void contextRandomBytes(long reference, byte[] output, int outputLen, int strength,
                                    boolean predictionResistant, byte[] additionalInput)
    {
        handleErrors(ni_contextRandomBytes(reference, output, outputLen, strength,
                predictionResistant, additionalInput));
    }

    default void contextReseed(long reference, int strength, boolean predictionResistant,
                               byte[] additionalInput)
    {
        handleErrors(ni_contextReseed(reference, strength, predictionResistant, additionalInput));
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
