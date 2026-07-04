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

import org.openssl.jostle.jcajce.provider.blockcipher.CCMCipherNI;

/**
 * JNI implementation of CCMCipherNI backed by the FIPS interface library
 * (libinterface_fips_jni). Distinct FQCN gives the FIPS library its own
 * Java_*_fips_CCMCipherFIPSJNI_* symbols; the glue
 * (interface/jni/ccm_fips_jni.c) is the base ccm_ni_jni.c re-included under
 * renamed exports.
 */
class CCMCipherFIPSJNI implements CCMCipherNI
{
    @Override
    public native long ni_makeInstance(int cipherId, int[] err);

    @Override
    public native void ni_dispose(long ref);

    @Override
    public native int ni_init(long ref, int opMode, byte[] key, byte[] iv, int tagLen);

    @Override
    public native int ni_doFinal(long ref,
                                 byte[] aad, int aadLen,
                                 byte[] input, int inOff, int inLen,
                                 byte[] output, int outOff);

    @Override
    public native int ni_getOutputSize(long ref, int opMode, int inputLen);
}
