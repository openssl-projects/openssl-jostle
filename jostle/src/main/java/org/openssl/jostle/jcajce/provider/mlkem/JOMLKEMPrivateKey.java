/*
 *  Copyright 2005-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://www.openssl.org/source/license.html
 *
 */

package org.openssl.jostle.jcajce.provider.mlkem;

import org.openssl.jostle.jcajce.interfaces.MLKEMPrivateKey;
import org.openssl.jostle.jcajce.interfaces.MLKEMPublicKey;
import org.openssl.jostle.jcajce.provider.AsymmetricKeyImpl;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.MLKEMParameterSpec;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.util.asn1.ASNEncoder;

public class JOMLKEMPrivateKey extends AsymmetricKeyImpl implements MLKEMPrivateKey
{
    final boolean seedOnly;

    public JOMLKEMPrivateKey(PKEYKeySpec spec)
    {
        super(spec);
        seedOnly = false;
    }

    public JOMLKEMPrivateKey(PKEYKeySpec spec, boolean seedOnly)
    {
        super(spec);
        this.seedOnly = seedOnly;
    }

    @Override
    public String getAlgorithm()
    {
        return getType().name();
    }

    @Override
    public String getFormat()
    {
        return "PKCS#8";
    }

    @Override
    public byte[] getEncoded()
    {
        return ASNEncoder.asSubjectPrivateKeyInfo(spec);
    }

    public byte[] getSeed()
    {
        long len = NISelector.MLKEMServiceNI.handleErrors(NISelector.MLKEMServiceNI.getSeed(spec.getReference(), null));
        byte[] out = new byte[(int) len];
        NISelector.MLKEMServiceNI.handleErrors(NISelector.MLKEMServiceNI.getSeed(spec.getReference(), out));

        return out;
    }

    @Override
    public MLKEMPrivateKey getPrivateKey(boolean preferSeedOnly)
    {
        if (preferSeedOnly)
        {

        }
        return null;
    }

    public byte[] getDirectEncoding()
    {
        //
        // Raw bytes
        //
        long len = NISelector.MLKEMServiceNI.handleErrors(NISelector.MLKEMServiceNI.getPrivateKey(spec.getReference(), null));
        byte[] out = new byte[(int) len];
        NISelector.MLKEMServiceNI.handleErrors(NISelector.MLKEMServiceNI.getPrivateKey(spec.getReference(), out));

        return out;
    }


    @Override
    public MLKEMPublicKey getPublicKey()
    {
        return new JOMLKEMPublicKey(this.getSpec());
    }

    @Override
    public byte[] getPrivateData()
    {
        return getDirectEncoding();
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

}
