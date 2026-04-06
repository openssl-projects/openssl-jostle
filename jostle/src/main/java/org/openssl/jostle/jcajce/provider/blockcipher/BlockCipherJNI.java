/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.blockcipher;

/**
 * JNI version of this class
 */
public class BlockCipherJNI implements BlockCipherNI
{
    @Override
    public native long ni_makeInstance(int cipher, int mode, int padding, int[] err);

    @Override
    public native int ni_init(long ref, int oppmode, byte[] keyBytes, byte[] iv, int tag_len);

    @Override
    public native int ni_getBlockSize(long ref);

    @Override
    public native int ni_update(long ref, byte[] output, int outputOffset, byte[] input, int inputOffset, int inputLen);

    @Override
    public native int ni_doFinal(long ref, byte[] output, int outputOffset);

    @Override
    public native int ni_updateAAD(long ref, byte[] input, int inputOffset, int inputLen);

    @Override
    public native int ni_getFinalSize(long ref, int length);

    @Override
    public native int ni_getUpdateSize(long ref, int length);

    @Override
    public native void ni_dispose(long ref);

}
