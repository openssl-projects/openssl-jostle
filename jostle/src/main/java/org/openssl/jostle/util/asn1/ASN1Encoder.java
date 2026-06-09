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

import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;

public class ASN1Encoder
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
            long len = NISelector.Asn1NI.encodePublicKey(ref, spec.getReference());
            byte[] out = new byte[(int) len];
            NISelector.Asn1NI.getData(ref, out);

            return out;
        }
        finally
        {
            NISelector.Asn1NI.dispose(ref);
        }
    }

    public static byte[] asPrivateKeyInfo(PKEYKeySpec spec, PrivateKeyOptions option)
    {
        if (option == null)
        {
            option = PrivateKeyOptions.DEFAULT;
        }

        long ref = NISelector.Asn1NI.allocate();
        try
        {
            long len = NISelector.Asn1NI.encodePrivateKey(ref, spec.getReference(), option.getValue());
            byte[] out = new byte[(int) len];
            NISelector.Asn1NI.getData(ref, out);
            return out;
        }
        finally
        {
            NISelector.Asn1NI.dispose(ref);
        }
    }

    /**
     * As {@link #asSubjectPublicKeyInfo(PKEYKeySpec)} but with the
     * AlgorithmIdentifier {@code parameters} guaranteed absent — for FIPS
     * 203/204/205 keys (ML-KEM, ML-DSA, SLH-DSA), where an explicit NULL is
     * forbidden. Strips a stray NULL the underlying encoder may emit so the
     * output is conformant regardless of OpenSSL version or provider install
     * state. Mirrors the input-side {@link KeyInfoCanonicalizer} the PQC
     * KeyFactories already apply. MUST NOT be used for RSA (rsaEncryption
     * requires the NULL).
     */
    public static byte[] asCanonicalSubjectPublicKeyInfo(PKEYKeySpec spec)
    {
        return KeyInfoCanonicalizer.subjectPublicKeyInfo(asSubjectPublicKeyInfo(spec));
    }

    /**
     * Private-key counterpart of {@link #asCanonicalSubjectPublicKeyInfo(PKEYKeySpec)}.
     */
    public static byte[] asCanonicalPrivateKeyInfo(PKEYKeySpec spec, PrivateKeyOptions option)
    {
        return KeyInfoCanonicalizer.privateKeyInfo(asPrivateKeyInfo(spec, option));
    }

    public static PKEYKeySpec fromPrivateKeyInfo(byte[] data, int start, int len)
    {
        long ref = NISelector.Asn1NI.fromPrivateKeyInfo(data, start, len);
        return new PKEYKeySpec(ref);
    }

    public static PKEYKeySpec fromSubjectPublicKeyInfo(byte[] data, int start, int len)
    {
        long ref = NISelector.Asn1NI.fromPublicKeyInfo(data, start, len);
        return new PKEYKeySpec(ref);
    }


}
