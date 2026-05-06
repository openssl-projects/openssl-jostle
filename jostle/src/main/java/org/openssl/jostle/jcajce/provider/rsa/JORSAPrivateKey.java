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
import org.openssl.jostle.jcajce.interfaces.RSAPrivateCrtKey;
import org.openssl.jostle.jcajce.interfaces.RSAPublicKey;
import org.openssl.jostle.jcajce.provider.AsymmetricKeyImpl;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.util.asn1.ASNEncoder;
import org.openssl.jostle.util.asn1.PrivateKeyOptions;

import java.math.BigInteger;

/**
 * Single private-key impl that satisfies both {@link RSAPrivateKey}
 * and {@link RSAPrivateCrtKey}. CRT-component getters return null
 * when the underlying EVP_PKEY was not constructed with CRT data
 * (e.g. via plain RSAPrivateKeySpec, or a PKCS#8 blob that omitted
 * them — uncommon but legal per RFC 8017).
 */
class JORSAPrivateKey extends AsymmetricKeyImpl implements RSAPrivateCrtKey, OSSLKey
{

    JORSAPrivateKey(PKEYKeySpec spec)
    {
        super(spec);
    }

    @Override
    public RSAPublicKey getPublicKey()
    {
        return new JORSAPublicKey(spec);
    }

    @Override
    public String getAlgorithm()
    {
        return "RSA";
    }

    @Override
    public String getFormat()
    {
        return "PKCS#8";
    }

    @Override
    public byte[] getEncoded()
    {
        synchronized (this)
        {
            return ASNEncoder.asPrivateKeyInfo(spec, PrivateKeyOptions.DEFAULT);
        }
    }

    @Override
    public PKEYKeySpec getSpec()
    {
        return spec;
    }

    // --- RSAKey / RSAPrivateKey ---

    @Override
    public BigInteger getModulus()
    {
        return RSAComponents.getRequired(spec, RSAServiceNI.COMP_MODULUS);
    }

    @Override
    public BigInteger getPrivateExponent()
    {
        return RSAComponents.getRequired(spec, RSAServiceNI.COMP_PRIVATE_EXPONENT);
    }

    // --- RSAPrivateCrtKey ---

    @Override
    public BigInteger getPublicExponent()
    {
        return RSAComponents.getOptional(spec, RSAServiceNI.COMP_PUBLIC_EXPONENT);
    }

    @Override
    public BigInteger getPrimeP()
    {
        return RSAComponents.getOptional(spec, RSAServiceNI.COMP_PRIME_P);
    }

    @Override
    public BigInteger getPrimeQ()
    {
        return RSAComponents.getOptional(spec, RSAServiceNI.COMP_PRIME_Q);
    }

    @Override
    public BigInteger getPrimeExponentP()
    {
        return RSAComponents.getOptional(spec, RSAServiceNI.COMP_EXPONENT_P);
    }

    @Override
    public BigInteger getPrimeExponentQ()
    {
        return RSAComponents.getOptional(spec, RSAServiceNI.COMP_EXPONENT_Q);
    }

    @Override
    public BigInteger getCrtCoefficient()
    {
        return RSAComponents.getOptional(spec, RSAServiceNI.COMP_CRT_COEFFICIENT);
    }
}
