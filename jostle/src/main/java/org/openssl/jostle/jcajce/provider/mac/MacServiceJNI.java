/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.mac;

public class MacServiceJNI implements MacServiceNI
{
    @Override
    public native long ni_allocateMac(String macName, String canonicalDigestName, int[] err);

    @Override
    public native int ni_init(long ref, byte[] keyBytes);

    @Override
    public native int ni_updateByte(long ref, byte b);

    @Override
    public native int ni_updateBytes(long ref, byte[] in, int inOff, int inLen);

    @Override
    public native int ni_doFinal(long ref, byte[] out, int outOff);

    @Override
    public native int ni_getMacLength(long ref);

    @Override
    public native void ni_reset(long ref);

    @Override
    public native void ni_dispose(long ref);

    @Override
    public native long ni_copy(long ref, int[] err);
}
