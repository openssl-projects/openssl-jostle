/*
 *  Copyright 2005-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://www.openssl.org/source/license.html
 *
 */

package org.openssl.jostle.jcajce.provider;

/**
 * JNI version of this class
 */
class BlockCipherJNI implements BlockCipherNI
{

    @Override
    public native long makeInstance(int cipher, int mode, int padding);

    @Override
    public native int init(long ref, int oppmode, byte[] keyBytes, byte[] iv, int tag_len);

    @Override
    public native int getBlockSize(long ref);

    @Override
    public native int update(long ref, byte[] output, int outputOffset, byte[] input, int inputOffset, int inputLen);

    @Override
    public native int doFinal(long ref, byte[] output, int outputOffset);

    @Override
    public native int getFinalSize(long ref, int length);

    @Override
    public native int getUpdateSize(long ref, int length);

    @Override
    public native int updateAAD(long ref, byte[] input, int inputOffset, int inputLen);

    @Override
    public native void dispose(long ref);

}
