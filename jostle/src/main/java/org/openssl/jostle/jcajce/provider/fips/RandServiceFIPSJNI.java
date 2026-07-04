/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.fips;

import org.openssl.jostle.jcajce.provider.rand.RandServiceNI;

/**
 * JNI implementation of RandServiceNI backed by the FIPS interface library
 * (libinterface_fips_jni). Distinct FQCN gives the FIPS library its own
 * Java_*_fips_RandServiceFIPSJNI_* symbols; the glue
 * (interface/jni/rand_fips_jni.c) is the base rand_jni.c re-included under
 * renamed exports. DRBGs created here parent on the FIPS rand lib ctx's
 * primary DRBG - entropy stays inside the module boundary.
 */
class RandServiceFIPSJNI implements RandServiceNI
{
    @Override
    public native long ni_createContext(String mechanism, String variant, boolean useDerivationFunction,
                                        int strength, boolean predictionResistant,
                                        byte[] personalizationString, int[] err);

    @Override
    public native void ni_disposeContext(long reference);

    @Override
    public native int ni_contextRandomBytes(long reference, byte[] output, int outputLen, int strength,
                                            boolean predictionResistant, byte[] additionalInput);

    @Override
    public native int ni_contextReseed(long reference, int strength, boolean predictionResistant,
                                       byte[] additionalInput);

    @Override
    public native int ni_drbgStrength(String mechanism, String variant);
}
