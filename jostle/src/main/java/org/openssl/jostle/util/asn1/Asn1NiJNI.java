/*
 *  Copyright 2005-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://www.openssl.org/source/license.html
 *
 */

package org.openssl.jostle.util.asn1;

public class Asn1NiJNI implements Asn1Ni
{
    @Override
    public native void dispose(long reference);

    @Override
    public native long allocate();

    @Override
    public native int encodePublicKey(long ref, long keyRef);

    @Override
    public native int encodePrivateKey(long ref, long keyRef);

    @Override
    public native int getData(long ref, byte[] out);

    @Override
    public native long fromPrivateKeyInfo(byte[] data, int start, int len);

    @Override
    public native long fromPublicKeyInfo(byte[] data, int start, int len);


}
