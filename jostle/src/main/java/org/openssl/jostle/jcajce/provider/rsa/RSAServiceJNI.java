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

package org.openssl.jostle.jcajce.provider.rsa;

import org.openssl.jostle.rand.RandSource;

public class RSAServiceJNI implements RSAServiceNI
{
    @Override
    public native long ni_allocateSigner(int[] err);

    @Override
    public native void ni_disposeSigner(long reference);

    @Override
    public native long ni_generateKeyPair(int bits, byte[] pubExp, int[] err, RandSource rndSource);

    @Override
    public native int ni_decodePublicComponents(long specRef, byte[] n, byte[] e);

    @Override
    public native int ni_decodePrivateComponents(long specRef, byte[] n, byte[] e, byte[] d);

    @Override
    public native int ni_decodePrivateComponentsCrt(long specRef,
                                                    byte[] n, byte[] e, byte[] d,
                                                    byte[] p, byte[] q,
                                                    byte[] dp, byte[] dq, byte[] qinv);

    @Override
    public native int ni_getComponent(long specRef, int component, byte[] out);

    @Override
    public native int ni_initSign(long ref, long keyRef, String digestName,
                                  int paddingMode, String mgf1MdName, int saltLen,
                                  RandSource rndSource);

    @Override
    public native int ni_initVerify(long ref, long keyRef, String digestName,
                                    int paddingMode, String mgf1MdName, int saltLen);

    @Override
    public native int ni_update(long ref, byte[] input, int inOff, int inLen);

    @Override
    public native int ni_sign(long ref, byte[] sig, int outOff, RandSource rndSource);

    @Override
    public native int ni_verify(long ref, byte[] sig, int sigLen);
}
