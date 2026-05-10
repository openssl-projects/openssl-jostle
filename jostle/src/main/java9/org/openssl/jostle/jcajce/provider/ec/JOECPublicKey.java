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
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.util.asn1.ASNEncoder;

import java.lang.ref.Reference;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

/**
 * Java 9+ override of the Java 8 baseline. Uses
 * {@link Reference#reachabilityFence} to keep this key reachable across
 * the native encoding call, replacing the {@code synchronized(this)}
 * idiom in the baseline.
 */
class JOECPublicKey extends AsymmetricKeyImpl implements ECPublicKey, ECKey, OSSLKey
{
    JOECPublicKey(PKEYKeySpec spec)
    {
        super(spec);
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
        try
        {
            return ASNEncoder.asSubjectPublicKeyInfo(spec);
        }
        finally
        {
            Reference.reachabilityFence(this);
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
                ECComponents.getBigInteger(spec, ECServiceNI.COMP_PUBLIC_X),
                ECComponents.getBigInteger(spec, ECServiceNI.COMP_PUBLIC_Y));
    }

    @Override
    public ECParameterSpec getParams()
    {
        return ECComponents.resolveParams(ECComponents.getCurveName(spec));
    }
}
