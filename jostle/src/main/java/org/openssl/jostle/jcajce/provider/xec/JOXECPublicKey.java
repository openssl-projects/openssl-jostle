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

package org.openssl.jostle.jcajce.provider.xec;

import org.openssl.jostle.jcajce.interfaces.OSSLKey;
import org.openssl.jostle.jcajce.interfaces.XDHKey;
import org.openssl.jostle.jcajce.provider.AsymmetricKeyImpl;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.util.asn1.ASN1Encoder;
import org.openssl.jostle.util.asn1.Asn1Ni;

import java.security.PublicKey;

/**
 * X25519 / X448 public key. The concrete algorithm ("X25519" / "X448")
 * comes from the key's {@link org.openssl.jostle.jcajce.spec.OSSLKeyType};
 * the encoding is the generic X.509 SubjectPublicKeyInfo produced by
 * OpenSSL (no curve parameters for Montgomery keys).
 */
class JOXECPublicKey extends AsymmetricKeyImpl implements PublicKey, XDHKey, OSSLKey
{
    // The NI backend that encodes the underlying PKEY (NISelector for JSL,
    // FIPSNISelector for JSLFIPS).
    private final Asn1Ni asn1NI;

    JOXECPublicKey(PKEYKeySpec spec)
    {
        this(NISelector.Asn1NI, spec);
    }

    JOXECPublicKey(Asn1Ni asn1NI, PKEYKeySpec spec)
    {
        super(spec);
        this.asn1NI = asn1NI;
    }

    @Override
    public String getAlgorithm()
    {
        return spec.getType().getAlgorithmName();
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
}
