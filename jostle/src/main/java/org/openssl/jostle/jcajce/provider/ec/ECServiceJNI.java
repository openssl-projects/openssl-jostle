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

package org.openssl.jostle.jcajce.provider.ec;

import org.openssl.jostle.rand.RandSource;

/**
 * JNI implementation of {@link ECServiceNI}. Native bindings live in
 * {@code interface/jni/ec_ni_jni.c}.
 */
public class ECServiceJNI implements ECServiceNI
{
    @Override
    public native int ni_curveSupported(String curveName);

    @Override
    public native long ni_generateKeyPair(String curveName, int[] err, RandSource rndSource);

    @Override
    public native long ni_makePrivateFromComponents(String curveName, byte[] scalarBE,
                                                    int[] err, RandSource rndSource);

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

    @Override
    public native long ni_allocateKex(int[] err);

    @Override
    public native void ni_disposeKex(long reference);

    @Override
    public native int ni_kexInit(long ref, long keyRef, RandSource rndSource);

    @Override
    public native int ni_kexSetPeer(long ref, long peerRef, RandSource rndSource);

    @Override
    public native int ni_kexDerive(long ref, byte[] out, int outOff, RandSource rndSource);
}
