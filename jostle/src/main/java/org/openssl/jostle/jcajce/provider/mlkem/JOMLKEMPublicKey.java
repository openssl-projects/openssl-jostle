/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.mlkem;

import org.openssl.jostle.jcajce.interfaces.MLKEMPublicKey;
import org.openssl.jostle.jcajce.provider.AsymmetricKeyImpl;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.jcajce.spec.MLKEMParameterSpec;
import org.openssl.jostle.util.asn1.ASNEncoder;

public class JOMLKEMPublicKey extends AsymmetricKeyImpl implements MLKEMPublicKey
{

    public JOMLKEMPublicKey(PKEYKeySpec spec)
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
        long len = NISelector.MLKEMServiceNI.handleErrors(NISelector.MLKEMServiceNI.getPublicKey(spec.getReference(), null));
        byte[] out = new byte[(int) len];
        NISelector.MLKEMServiceNI.handleErrors(NISelector.MLKEMServiceNI.getPublicKey(spec.getReference(), out));

        return out;
    }


    public PKEYKeySpec getSpec()
    {
        return spec;
    }

    public MLKEMParameterSpec getParameterSpec()
    {

        MLKEMParameterSpec parameterSpec = MLKEMParameterSpec.getSpecForOSSLType(spec.getType());

        if (parameterSpec == null)
        {
            throw new IllegalArgumentException("unknown parameter type: " + spec.getType().name());
        }
        return parameterSpec;
    }

    @Override
    public byte[] getPublicData()
    {
        return getDirectEncoding();
    }
}
