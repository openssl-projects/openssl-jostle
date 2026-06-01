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

package org.openssl.jostle.jcajce.provider.blockcipher;

public class CCMCipherJNI implements CCMCipherNI
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
