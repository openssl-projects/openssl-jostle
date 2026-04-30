/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.spec;

import org.openssl.jostle.rand.RandSource;

public class SpecJNI implements SpecNI
{
    @Override
    public native void ni_dispose(long reference);

    @Override
    public native long ni_allocate(int[] err);

    @Override
    public native String ni_getName(long keyRef);

    @Override
    public native int ni_encap(long keyRef, String opt, byte[] secret, int inOff, int inLen, byte[] out, int off, int len, RandSource randSource);

    @Override
    public native int ni_decap(long keyRef, String opt, byte[] input, int inOff, int inLen, byte[] out, int off, int len);
}
