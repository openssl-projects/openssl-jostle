/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider;

import org.openssl.jostle.jcajce.provider.mldsa.JOMLDSAPublicKey;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.util.asn1.ASNEncoder;

import java.security.PublicKey;

public class PublicKeyUtil
{
    public static PublicKey fromSubjectPublicKeyInfo(byte[] info, int start, int length)
    {
        PKEYKeySpec spec = ASNEncoder.fromPublicKeyInfo(info, start, length);
        switch (spec.getType())
        {
            case ML_DSA_44:
            case ML_DSA_65:
            case ML_DSA_87:
                return new JOMLDSAPublicKey(spec);
            default:
                throw new IllegalArgumentException("unknown public key type: " + spec.getType());
        }
    }
}
