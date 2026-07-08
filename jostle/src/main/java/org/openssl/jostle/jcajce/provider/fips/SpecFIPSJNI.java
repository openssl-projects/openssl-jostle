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

import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.rand.RandSource;

/**
 * JNI implementation of SpecNI backed by the FIPS interface library
 * (libinterface_fips_jni). Distinct FQCN gives the FIPS library its own
 * Java_*_fips_SpecFIPSJNI_* symbols; the glue
 * (interface/fips/jni/spec_fips_jni.c) is the base spec_ni_jni.c re-included
 * under renamed exports.
 */
class SpecFIPSJNI implements SpecNI
{
    @Override
    public native void ni_dispose(long reference);

    @Override
    public native long ni_allocate(int[] err);

    @Override
    public native String ni_getName(long keyRef);

    @Override
    public native int ni_encap(long keyRef, String opt, byte[] secret, int inOff, int inLen, byte[] out, int off, int len, RandSource randSource);

    @Override
    public native int ni_decap(long keyRef, String opt, byte[] input, int inOff, int inLen, byte[] out, int off, int len);
}
