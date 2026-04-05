/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.util.asn1;

public class Asn1NiJNI implements Asn1Ni
{
    public native void ni_dispose(long reference);

    public native long ni_allocate(int[] err);

    public native int ni_encodePublicKey(long ref, long keyRef);

    public native int ni_encodePrivateKey(long ref, long keyRef, String option);

    public native int ni_getData(long ref, byte[] out);

    public native long ni_fromPrivateKeyInfo(byte[] data, int start, int len);

    public native long ni_fromPublicKeyInfo(byte[] data, int start, int len);

}
