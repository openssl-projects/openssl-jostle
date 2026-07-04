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

package org.openssl.jostle.jcajce.provider.ec;

import org.openssl.jostle.jcajce.interfaces.ECKey;
import org.openssl.jostle.jcajce.interfaces.OSSLKey;
import org.openssl.jostle.jcajce.provider.AsymmetricKeyImpl;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.util.asn1.ASN1Encoder;
import org.openssl.jostle.util.asn1.Asn1Ni;

import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

class JOECPublicKey extends AsymmetricKeyImpl implements ECPublicKey, ECKey, OSSLKey
{
    // The NI backends that own the underlying PKEY (NISelector for JSL,
    // FIPSNISelector for JSLFIPS).
    private final ECServiceNI ecServiceNI;
    private final Asn1Ni asn1NI;

    JOECPublicKey(PKEYKeySpec spec)
    {
        this(NISelector.ECServiceNI, NISelector.Asn1NI, spec);
    }

    JOECPublicKey(ECServiceNI ecServiceNI, Asn1Ni asn1NI, PKEYKeySpec spec)
    {
        super(spec);
        this.ecServiceNI = ecServiceNI;
        this.asn1NI = asn1NI;
    }

    @Override
    public String getAlgorithm()
    {
        return "EC";
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
    public ECPoint getW()
    {
        return new ECPoint(
                ECComponents.getBigInteger(ecServiceNI, spec, ECServiceNI.COMP_PUBLIC_X),
                ECComponents.getBigInteger(ecServiceNI, spec, ECServiceNI.COMP_PUBLIC_Y));
    }

    @Override
    public ECParameterSpec getParams()
    {
        return ECComponents.resolveParams(ECComponents.getCurveName(ecServiceNI, spec));
    }
}
