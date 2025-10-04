/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.mldsa;

import org.openssl.jostle.jcajce.interfaces.MLDSAPublicKey;
import org.openssl.jostle.jcajce.interfaces.OSSLKey;
import org.openssl.jostle.jcajce.provider.AsymmetricKeyImpl;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.MLDSAParameterSpec;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.util.asn1.ASNEncoder;

public class JOMLDSAPublicKey extends AsymmetricKeyImpl implements MLDSAPublicKey, OSSLKey
{

    public JOMLDSAPublicKey(PKEYKeySpec spec)
    {
        super(spec);
    }

    @Override
    public String getAlgorithm()
    {
        return getType().name();
    }

    @Override
    public String getFormat()
    {
        return "X.509";
    }

    @Override
    public byte[] getEncoded()
    {
        // ASN1
        return ASNEncoder.asSubjectPublicKeyInfo(spec);
    }

    public byte[] getDirectEncoding()
    {
        //
        // Raw bytes
        //
        long len = NISelector.MLDSAServiceNI.handleErrors(NISelector.MLDSAServiceNI.getPublicKey(spec.getReference(), null));
        byte[] out = new byte[(int) len];
        NISelector.MLDSAServiceNI.handleErrors(NISelector.MLDSAServiceNI.getPublicKey(spec.getReference(), out));

        return out;
    }


    public PKEYKeySpec getSpec()
    {
        return spec;
    }

    public MLDSAParameterSpec getParameterSpec()
    {
        switch (spec.getType())
        {
            case ML_DSA_44:
                return MLDSAParameterSpec.ml_dsa_44;
            case ML_DSA_87:
                return MLDSAParameterSpec.ml_dsa_87;
            case ML_DSA_65:
                return MLDSAParameterSpec.ml_dsa_65;
            default:
                throw new IllegalArgumentException("unknown parameter type: " + spec.getType().name());

        }
    }
}
