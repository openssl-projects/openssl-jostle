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

package org.openssl.jostle.jcajce.provider.dh;

import org.openssl.jostle.rand.RandSource;

/**
 * JNI implementation of {@link DHServiceNI}. Native bindings live in
 * {@code interface/jni/dh_ni_jni.c}.
 */
public class DHServiceJNI implements DHServiceNI
{
    @Override
    public native int ni_groupSupported(String groupName);

    @Override
    public native long ni_generateKeyPairByGroup(String groupName, int[] err, RandSource rndSource);

    @Override
    public native long ni_generateParameters(int pBits, int[] err, RandSource rndSource);

    @Override
    public native long ni_makeParamsFromComponents(byte[] p, byte[] g, int[] err);

    @Override
    public native long ni_generateKeyPair(long paramsRef, int[] err, RandSource rndSource);

    @Override
    public native long ni_makePrivateFromComponents(byte[] p, byte[] g, byte[] x,
                                                    int[] err, RandSource rndSource);

    @Override
    public native long ni_makePublicFromComponents(byte[] p, byte[] g, byte[] y,
                                                   int[] err);

    @Override
    public native int ni_getComponent(long specRef, int component, byte[] out);

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
