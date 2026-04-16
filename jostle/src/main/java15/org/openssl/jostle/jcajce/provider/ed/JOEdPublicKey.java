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

import org.openssl.jostle.jcajce.interfaces.EdDSAPublicKey;
import org.openssl.jostle.jcajce.provider.AsymmetricKeyImpl;
import org.openssl.jostle.jcajce.spec.EdDSAParameterSpec;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.util.asn1.ASNEncoder;

import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.EdECPoint;
import java.security.spec.NamedParameterSpec;

public class JOEdPublicKey extends AsymmetricKeyImpl implements EdDSAPublicKey, java.security.interfaces.EdECPublicKey
{
    public JOEdPublicKey(PKEYKeySpec spec)
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
        return "X.509";
    }

    @Override
    public byte[] getEncoded()
    {
        return ASNEncoder.asSubjectPublicKeyInfo(spec);
    }

    public PKEYKeySpec getSpec()
    {
        return spec;
    }

    @Override
    public EdECPoint getPoint()
    {
        return null;
    }

    @Override
    public NamedParameterSpec getParams()
    {

        if (spec.getType() == OSSLKeyType.ED25519)
        {
            return NamedParameterSpec.ED25519;
        }
        else if (spec.getType() == OSSLKeyType.ED448)
        {
            return NamedParameterSpec.ED448;
        }
        throw new IllegalArgumentException("Unknown OSSLKeyType: " + spec.getType().name());
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
