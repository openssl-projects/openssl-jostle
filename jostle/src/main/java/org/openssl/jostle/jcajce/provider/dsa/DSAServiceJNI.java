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

package org.openssl.jostle.jcajce.provider.dsa;

import org.openssl.jostle.rand.RandSource;

/**
 * JNI implementation of {@link DSAServiceNI}. Native bindings live in
 * {@code interface/jni/dsa_ni_jni.c}.
 */
public class DSAServiceJNI implements DSAServiceNI
{
    @Override
    public native long ni_generateParameters(int pBits, int qBits, int[] err, RandSource rndSource);

    @Override
    public native long ni_makeParamsFromComponents(byte[] p, byte[] q, byte[] g, int[] err);

    @Override
    public native long ni_generateKeyPair(long paramsRef, int[] err, RandSource rndSource);

    @Override
    public native long ni_makePrivateFromComponents(byte[] p, byte[] q, byte[] g, byte[] x,
                                                    int[] err, RandSource rndSource);

    @Override
    public native long ni_makePublicFromComponents(byte[] p, byte[] q, byte[] g, byte[] y,
                                                   int[] err);

    @Override
    public native int ni_getComponent(long specRef, int component, byte[] out);

    @Override
    public native long ni_allocateSigner(int[] err);

    @Override
    public native void ni_disposeSigner(long reference);

    @Override
    public native int ni_initSign(long ref, long keyRef, String digestName, RandSource rndSource);

    @Override
    public native int ni_initVerify(long ref, long keyRef, String digestName);

    @Override
    public native int ni_update(long ref, byte[] input, int inOff, int inLen);

    @Override
    public native int ni_sign(long ref, byte[] sig, int outOff, RandSource rndSource);

    @Override
    public native int ni_verify(long ref, byte[] sig, int sigLen, RandSource rndSource);
}
