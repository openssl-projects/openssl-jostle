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
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.util.asn1.Asn1Ni;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.util.asn1.ASN1Encoder;

import java.math.BigInteger;

class JORSAPublicKey extends AsymmetricKeyImpl implements RSAPublicKey, OSSLKey
{
    // The NI backends that own the underlying PKEY - component reads and
    // encoding must go through the interface library that created the key
    // (NISelector for JSL, FIPSNISelector for JSLFIPS).
    private final RSAServiceNI rsaServiceNI;
    private final Asn1Ni asn1NI;

    JORSAPublicKey(PKEYKeySpec spec)
    {
        this(NISelector.RSAServiceNI, NISelector.Asn1NI, spec);
    }

    JORSAPublicKey(RSAServiceNI rsaServiceNI, Asn1Ni asn1NI, PKEYKeySpec spec)
    {
        super(spec);
        this.rsaServiceNI = rsaServiceNI;
        this.asn1NI = asn1NI;
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
            return ASN1Encoder.asSubjectPublicKeyInfo(asn1NI, spec);
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
        return RSAComponents.getRequired(rsaServiceNI, spec, RSAServiceNI.COMP_MODULUS);
    }

    @Override
    public BigInteger getPublicExponent()
    {
        return RSAComponents.getRequired(rsaServiceNI, spec, RSAServiceNI.COMP_PUBLIC_EXPONENT);
    }
}
