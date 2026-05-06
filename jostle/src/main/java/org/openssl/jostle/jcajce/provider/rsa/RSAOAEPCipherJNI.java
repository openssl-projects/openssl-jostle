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

public class RSAOAEPCipherJNI implements RSAOAEPCipherNI
{
    @Override
    public native long ni_allocateCipher(int[] err);

    @Override
    public native void ni_disposeCipher(long reference);

    @Override
    public native int ni_init(long ref, long keyRef, int opMode,
                              String oaepMdName, String mgf1MdName,
                              byte[] label,
                              RandSource rndSource);

    @Override
    public native int ni_doFinal(long ref,
                                 byte[] input, int inOff, int inLen,
                                 byte[] output, int outOff,
                                 RandSource rndSource);
}
