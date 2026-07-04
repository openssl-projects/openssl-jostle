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
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.util.asn1.ASN1Encoder;
import org.openssl.jostle.util.asn1.Asn1Ni;
import org.openssl.jostle.util.asn1.PrivateKeyOptions;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.spec.DHParameterSpec;
import java.math.BigInteger;

class JODHPrivateKey extends AsymmetricKeyImpl implements DHPrivateKey, DHKey, OSSLKey
{
    // The NI backends that own the underlying PKEY (NISelector for JSL,
    // FIPSNISelector for JSLFIPS).
    private final DHServiceNI dhServiceNI;
    private final Asn1Ni asn1NI;

    JODHPrivateKey(PKEYKeySpec spec)
    {
        this(NISelector.DHServiceNI, NISelector.Asn1NI, spec);
    }

    JODHPrivateKey(DHServiceNI dhServiceNI, Asn1Ni asn1NI, PKEYKeySpec spec)
    {
        super(spec);
        this.dhServiceNI = dhServiceNI;
        this.asn1NI = asn1NI;
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
        synchronized (this)
        {
            return ASN1Encoder.asPrivateKeyInfo(asn1NI, spec, PrivateKeyOptions.DEFAULT);
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
        return DHComponents.getBigInteger(dhServiceNI, spec, DHServiceNI.COMP_PRIVATE_VALUE);
    }

    @Override
    public DHParameterSpec getParams()
    {
        return DHComponents.getParams(dhServiceNI, spec);
    }
}
