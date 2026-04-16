/*
 *
 *   Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *   Licensed under the Apache License 2.0 (the "License"). You may not use
 *   this file except in compliance with the License.  You can obtain a copy
 *   in the file LICENSE in the source distribution or at
 *   https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.ed;

import org.openssl.jostle.jcajce.interfaces.EdDSAPrivateKey;
import org.openssl.jostle.jcajce.interfaces.EdDSAPublicKey;
import org.openssl.jostle.jcajce.interfaces.OSSLKey;
import org.openssl.jostle.jcajce.provider.AsymmetricKeyImpl;
import org.openssl.jostle.jcajce.spec.EdDSAParameterSpec;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.util.asn1.ASNEncoder;
import org.openssl.jostle.util.asn1.PrivateKeyOptions;

public class JOEdPrivateKey extends AsymmetricKeyImpl implements EdDSAPrivateKey, OSSLKey
{

    public JOEdPrivateKey(PKEYKeySpec spec)
    {
        super(spec);
    }


    @Override
    public EdDSAPublicKey getPublicKey()
    {
        return new JOEdPublicKey(spec);
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
        return ASNEncoder.asPrivateKeyInfo(spec, PrivateKeyOptions.DEFAULT);
    }

    @Override
    public PKEYKeySpec getSpec()
    {
        return spec;
    }

    public EdDSAParameterSpec getParameterSpec()
    {
        switch (spec.getType())
        {
            case ED448:
                return EdDSAParameterSpec.ED448;
            case ED25519:
                return EdDSAParameterSpec.ED25519;
            default:
                throw new IllegalArgumentException("unknown parameter type: " + spec.getType().name());

        }
    }

}
