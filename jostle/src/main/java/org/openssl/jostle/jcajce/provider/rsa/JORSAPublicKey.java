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

package org.openssl.jostle.jcajce.provider.rsa;

import org.openssl.jostle.jcajce.interfaces.OSSLKey;
import org.openssl.jostle.jcajce.interfaces.RSAPublicKey;
import org.openssl.jostle.jcajce.provider.AsymmetricKeyImpl;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.util.asn1.ASNEncoder;

import java.math.BigInteger;

class JORSAPublicKey extends AsymmetricKeyImpl implements RSAPublicKey, OSSLKey
{

    JORSAPublicKey(PKEYKeySpec spec)
    {
        super(spec);
    }

    @Override
    public String getAlgorithm()
    {
        return "RSA";
    }

    @Override
    public String getFormat()
    {
        return "X.509";
    }

    @Override
    public byte[] getEncoded()
    {
        synchronized (this)
        {
            return ASNEncoder.asSubjectPublicKeyInfo(spec);
        }
    }

    @Override
    public PKEYKeySpec getSpec()
    {
        return spec;
    }

    @Override
    public BigInteger getModulus()
    {
        return RSAComponents.getRequired(spec, RSAServiceNI.COMP_MODULUS);
    }

    @Override
    public BigInteger getPublicExponent()
    {
        return RSAComponents.getRequired(spec, RSAServiceNI.COMP_PUBLIC_EXPONENT);
    }
}
