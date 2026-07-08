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

import org.openssl.jostle.util.asn1.Asn1Ni;

/**
 * JNI implementation of Asn1Ni backed by the FIPS interface library
 * (libinterface_fips_jni). Distinct FQCN gives the FIPS library its own
 * Java_*_fips_Asn1FIPSJNI_* symbols; the glue
 * (interface/fips/jni/asn1_fips_jni.c) is the base asn1_ni_jni.c re-included
 * under renamed exports. Encoders/decoders resolve in the FIPS lib ctx
 * through its base provider.
 */
class Asn1FIPSJNI implements Asn1Ni
{
    @Override
    public native void ni_dispose(long reference);

    @Override
    public native long ni_allocate(int[] err);

    @Override
    public native int ni_encodePublicKey(long ref, long keyRef);

    @Override
    public native int ni_encodePrivateKey(long ref, long keyRef, String option);

    @Override
    public native int ni_getData(long ref, byte[] out);

    @Override
    public native long ni_fromPrivateKeyInfo(byte[] data, int start, int len);

    @Override
    public native long ni_fromPublicKeyInfo(byte[] data, int start, int len);
}
