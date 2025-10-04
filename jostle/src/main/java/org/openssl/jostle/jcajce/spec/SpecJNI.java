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

public class SpecJNI implements SpecNI
{
    @Override
    public native void dispose(long reference);

    @Override
    public native long allocate();

    @Override
    public native String getName(long keyRef);

    @Override
    public native int encap(long keyRef, String opt, byte[] input, int intOff, int inLen, byte[] out, int off, int len);

    @Override
    public native int decap(long keyRef, String opt, byte[] input, int inOff, int inLen, byte[] out, int off, int len);

}
