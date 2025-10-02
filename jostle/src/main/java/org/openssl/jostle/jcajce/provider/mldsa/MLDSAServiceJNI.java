/*
 *  Copyright 2005-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://www.openssl.org/source/license.html
 *
 */

package org.openssl.jostle.jcajce.provider.mldsa;

public class MLDSAServiceJNI implements MLDSAServiceNI
{
    public native long generateKeyPair(int type);

    @Override
    public native long generateKeyPair(int type, byte[] seed, int seedLen);

    @Override
    public native int getPublicKey(long ref, byte[] output);

    @Override
    public native int  getPrivateKey(long ref, byte[] output);

    @Override
    public native int getSeed(long ref, byte[] output);

    @Override
    public native void disposeSigner(long reference);

    @Override
    public native long allocateSigner();

    @Override
    public native int initVerify(long ref, long keyReference, byte[] context, int contextLen, int muHandlingOrdinal);

    @Override
    public native int initSign(long reference, long keyReference, byte[] context, int contextLen, int muHandlingOrdinal);

    @Override
    public native int update(long reference, byte[] input, int inputOffset, int inputLen);

    @Override
    public native int sign(long reference, byte[] output, int offset);

    @Override
    public native int verify(long reference, byte[] sigBytes, int sigLen);

    @Override
    public native int decode_publicKey(long spec_ref, int keyType, byte[] input, int inputOffset, int inputLen);

    @Override
    public native int decode_privateKey(long spec_ref, int keyType, byte[] input, int inputOffset, int inputLen);
}
