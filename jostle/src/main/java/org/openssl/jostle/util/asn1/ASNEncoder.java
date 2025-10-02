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

import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;

public class ASNEncoder
{
    /**
     * Encode PKEY as SubjectPublicKeyInfo
     *
     * @param spec the PKEYSpec
     * @return a byte array with the encoding.
     */
    public static byte[] asSubjectPublicKeyInfo(PKEYKeySpec spec)
    {
        long ref = NISelector.Asn1NI.allocate();
        try
        {
            long len = NISelector.Asn1NI.handleErrors(NISelector.Asn1NI.encodePublicKey(ref, spec.getReference()));
            byte[] out = new byte[(int) len];
            NISelector.Asn1NI.handleErrors(NISelector.Asn1NI.getData(ref, out));

            return out;
        } finally
        {
            NISelector.Asn1NI.dispose(ref);
        }
    }

    public static byte[] asSubjectPrivateKeyInfo(PKEYKeySpec spec)
    {
        long ref = NISelector.Asn1NI.allocate();
        try
        {
            long len = NISelector.Asn1NI.handleErrors(NISelector.Asn1NI.encodePrivateKey(ref, spec.getReference()));
            byte[] out = new byte[(int) len];
            NISelector.Asn1NI.handleErrors(NISelector.Asn1NI.getData(ref, out));
            return out;
        } finally
        {
            NISelector.Asn1NI.dispose(ref);
        }
    }

    public static PKEYKeySpec fromPrivateKeyInfo(byte[] data, int start, int len)
    {
        long ref = NISelector.Asn1NI.handleErrors(NISelector.Asn1NI.fromPrivateKeyInfo(data, start, len));
        return new PKEYKeySpec(ref);
    }

    public static PKEYKeySpec fromPublicKeyInfo(byte[] data, int start, int len)
    {
        long ref = NISelector.Asn1NI.handleErrors(NISelector.Asn1NI.fromPublicKeyInfo(data, start, len));
        return new PKEYKeySpec(ref);
    }


}
