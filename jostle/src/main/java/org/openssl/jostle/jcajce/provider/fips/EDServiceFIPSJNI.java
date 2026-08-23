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

import org.openssl.jostle.jcajce.provider.ed.EDServiceNI;
import org.openssl.jostle.rand.RandSource;

/**
 * JNI implementation of {@link EDServiceNI} backed by the FIPS interface
 * library; the glue is the base bridge re-included under renamed exports
 * ({@code interface/fips/jni/ed_fips_jni.c}).
 */
class EDServiceFIPSJNI implements EDServiceNI
{
    @Override
    public native long ni_allocateSigner(int[] err);

    @Override
    public native void ni_disposeSigner(long reference);

    @Override
    public native long ni_generateKeyPair(int type, int[] err, RandSource randSource);

    @Override
    public native int ni_initSign(long reference, long keyRef, String name, byte[] context, int contextLen, RandSource randSource);

    @Override
    public native int ni_sign(long reference, byte[] sig, int i, RandSource randSource);

    @Override
    public native int ni_initVerify(long reference, long keyRef, String name, byte[] context, int contextLen);

    @Override
    public native int ni_verify(long reference, byte[] sigBytes, int len);

    @Override
    public native int ni_update(long reference, byte[] b, int off, int len);

    @Override
    public native int ni_decode_publicKey(long spec_ref, int keyType, byte[] input, int inputOffset, int inputLen);

    @Override
    public native int ni_decode_privateKey(long spec_ref, int keyType, byte[] input, int inputOffset, int inputLen);

    @Override
    public native int ni_getPublicKey(long ref, byte[] output);

    @Override
    public native int ni_getPrivateKey(long ref, byte[] output);
}
