/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.slhdsa;

import org.openssl.jostle.rand.RandSource;

public class SLHDSAServiceJNI implements SLHDSAServiceNI
{


    @Override
    public native long ni_generateKeyPair(int type, int[] err, RandSource randSource);

    @Override
    public native long ni_generateKeyPair(int type, int[] err, byte[] seed, int seedLen, RandSource randSource);

    @Override
    public native int ni_getPrivateKey(long reference, byte[] output);

    @Override
    public native int ni_getPublicKey(long reference, byte[] output);

    @Override
    public native int ni_decode_publicKey(long spec_ref, int keyType, byte[] input, int inputOffset, int inputLen);

    @Override
    public native int ni_decode_privateKey(long spec_ref, int keyType, byte[] input, int inputOffset, int inputLen);

    @Override
    public native long ni_allocateSigner(int[] err);

    @Override
    public native int ni_initVerify(long ref, long keyRef, byte[] context, int contextLen, int messageEncoding, int deterministic);

    @Override
    public native int ni_update(long ref, byte[] b, int off, int len);


    @Override
    public native long ni_sign(long ref, byte[] sig, int offset, RandSource randSource);

    @Override
    public native int ni_verify(long reference, byte[] sigBytes, int len);

    @Override
    public native int ni_initSign(long reference, long keyRef, byte[] context, int contextLen, int messageEncoding, int deterministic, RandSource randSource);

    @Override
    public native void ni_disposeSigner(long reference);
}
