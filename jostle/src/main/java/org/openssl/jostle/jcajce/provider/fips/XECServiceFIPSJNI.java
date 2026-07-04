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

package org.openssl.jostle.jcajce.provider.fips;

import org.openssl.jostle.jcajce.provider.xec.XECServiceNI;

import org.openssl.jostle.rand.RandSource;

/**
 * JNI binding for {@link XECServiceNI}. Native methods link to
 * {@code interface/jni/xec_ni_jni.c} by name.
 */
/**
 * JNI implementation of XECServiceNI backed by the FIPS interface library;
 * the glue is the base bridge re-included under renamed exports.
 */
class XECServiceFIPSJNI implements XECServiceNI
{
    @Override
    public native long ni_generateKeyPair(String name, int[] err, RandSource rndSource);
}
