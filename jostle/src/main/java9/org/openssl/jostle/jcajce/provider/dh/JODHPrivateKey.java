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

package org.openssl.jostle.jcajce.provider.dh;

import org.openssl.jostle.jcajce.interfaces.DHKey;
import org.openssl.jostle.jcajce.interfaces.OSSLKey;
import org.openssl.jostle.jcajce.provider.AsymmetricKeyImpl;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.util.asn1.ASN1Encoder;
import org.openssl.jostle.util.asn1.PrivateKeyOptions;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.spec.DHParameterSpec;
import java.lang.ref.Reference;
import java.math.BigInteger;

/**
 * Java 9+ override of the Java 8 baseline. Uses
 * {@link Reference#reachabilityFence} to keep this key reachable across
 * the native encoding call, replacing the {@code synchronized(this)}
 * idiom in the baseline.
 */
class JODHPrivateKey extends AsymmetricKeyImpl implements DHPrivateKey, DHKey, OSSLKey
{
    JODHPrivateKey(PKEYKeySpec spec)
    {
        super(spec);
    }

    @Override
    public String getAlgorithm()
    {
        return "DH";
    }

    @Override
    public String getFormat()
    {
        return "PKCS#8";
    }

    @Override
    public byte[] getEncoded()
    {
        try
        {
            return ASN1Encoder.asPrivateKeyInfo(spec, PrivateKeyOptions.DEFAULT);
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
    public BigInteger getX()
    {
        return DHComponents.getBigInteger(spec, DHServiceNI.COMP_PRIVATE_VALUE);
    }

    @Override
    public DHParameterSpec getParams()
    {
        return DHComponents.getParams(spec);
    }
}
