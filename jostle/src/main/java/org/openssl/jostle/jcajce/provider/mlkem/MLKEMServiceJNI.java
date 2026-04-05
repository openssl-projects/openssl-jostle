/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.mlkem;

import org.openssl.jostle.rand.RandSource;

public class MLKEMServiceJNI implements MLKEMServiceNI
{
    @Override
    public native long ni_generateKeyPair(int type, int[] err, RandSource randSource);

    @Override
    public native long ni_generateKeyPair(int type, int[] err, byte[] seed, int seedLen, RandSource randSource);

    @Override
    public native int ni_getPublicKey(long ref, byte[] output);

    @Override
    public native int ni_getPrivateKey(long ref, byte[] output);

    @Override
    public native int ni_getSeed(long ref, byte[] output);

    @Override
    public native int ni_decode_publicKey(long spec_ref, int keyType, byte[] input, int inputOffset, int inputLen);

    @Override
    public native int ni_decode_privateKey(long spec_ref, int keyType, byte[] input, int inputOffset, int inputLen);
}
