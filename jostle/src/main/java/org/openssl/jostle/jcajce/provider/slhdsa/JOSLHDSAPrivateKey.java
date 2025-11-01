/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.slhdsa;

import org.openssl.jostle.jcajce.interfaces.OSSLKey;
import org.openssl.jostle.jcajce.interfaces.SLHDSAPrivateKey;
import org.openssl.jostle.jcajce.interfaces.SLHDSAPublicKey;
import org.openssl.jostle.jcajce.provider.AsymmetricKeyImpl;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.jcajce.spec.SLHDSAParameterSpec;
import org.openssl.jostle.util.asn1.ASNEncoder;

class JOSLHDSAPrivateKey extends AsymmetricKeyImpl implements SLHDSAPrivateKey, OSSLKey
{
//    final boolean seedOnly;

    public JOSLHDSAPrivateKey(PKEYKeySpec spec)
    {
        super(spec);

    }


    @Override
    public String getAlgorithm()
    {
        return getType().getAlgorithmName();
    }

    @Override
    public String getFormat()
    {
        return "PKCS#8";
    }

    @Override
    public byte[] getEncoded()
    {
        return ASNEncoder.asPrivateKeyInfo(spec);
    }

    public byte[] getDirectEncoding()
    {
        //
        // Raw bytes
        //
        long len = NISelector.SLHDSAServiceNI.handleErrors(NISelector.SLHDSAServiceNI.getPrivateKey(spec.getReference(), null));
        byte[] out = new byte[(int) len];
        NISelector.SLHDSAServiceNI.handleErrors(NISelector.SLHDSAServiceNI.getPrivateKey(spec.getReference(), out));

        return out;
    }


    @Override
    public SLHDSAPublicKey getPublicKey()
    {
        return new JOSLHDSAPublicKey(this.getSpec());
    }


    public PKEYKeySpec getSpec()
    {
        return spec;
    }

    public SLHDSAParameterSpec getParameterSpec()
    {
        SLHDSAParameterSpec slhdsaParameterSpec = SLHDSAParameterSpec.getSpecForOSSLType(spec.getType());

        if (slhdsaParameterSpec == null)
        {
            throw new IllegalArgumentException("unknown parameter type: " + spec.getType().name());
        }
        return slhdsaParameterSpec;
    }

}
