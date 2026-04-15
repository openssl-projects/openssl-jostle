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
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.util.asn1.ASNEncoder;
import org.openssl.jostle.util.asn1.PrivateKeyOptions;

import java.security.interfaces.EdECPrivateKey;
import java.util.Optional;

public class JOEdPrivateKey extends AsymmetricKeyImpl implements EdDSAPrivateKey, OSSLKey, EdECPrivateKey
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

    @Override
    public Optional<byte[]> getBytes()
    {
        if (OSSLKeyType.ED25519 == getType() || OSSLKeyType.ED448 == getType())
        {
            return Optional.of(getEncoded());
        }

        throw new IllegalArgumentException("Unknown OSSLKeyType: " + getType());

    }
}
