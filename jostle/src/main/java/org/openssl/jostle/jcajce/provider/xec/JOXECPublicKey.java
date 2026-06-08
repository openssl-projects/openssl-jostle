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
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.util.asn1.ASNEncoder;

import java.security.PublicKey;

/**
 * X25519 / X448 public key. The concrete algorithm ("X25519" / "X448")
 * comes from the key's {@link org.openssl.jostle.jcajce.spec.OSSLKeyType};
 * the encoding is the generic X.509 SubjectPublicKeyInfo produced by
 * OpenSSL (no curve parameters for Montgomery keys).
 */
class JOXECPublicKey extends AsymmetricKeyImpl implements PublicKey, XDHKey, OSSLKey
{
    JOXECPublicKey(PKEYKeySpec spec)
    {
        super(spec);
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
            return ASNEncoder.asSubjectPublicKeyInfo(spec);
        }
    }

    @Override
    public PKEYKeySpec getSpec()
    {
        return spec;
    }
}
