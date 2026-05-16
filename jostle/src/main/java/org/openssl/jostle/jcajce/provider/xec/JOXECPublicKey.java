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
import org.openssl.jostle.jcajce.interfaces.XECKey;
import org.openssl.jostle.jcajce.provider.AsymmetricKeyImpl;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.util.asn1.ASNEncoder;

import java.security.PublicKey;

/**
 * X25519 / X448 public key. The two curves share a class because at the
 * Jostle level the only difference is the underlying OpenSSL key type,
 * which is carried in {@link PKEYKeySpec#getType()}. The advertised
 * algorithm name ("X25519" or "X448") is derived from the spec rather
 * than hard-coded.
 *
 * <p>Java 11+ provides {@code java.security.interfaces.XECPublicKey}
 * with a {@code getU()} accessor; a Java 11 override copy of this class
 * implementing that interface is a TODO. For Java 8 / class-path
 * consumers and for the most common CMP / TLS paths (which only need
 * X.509 encoding via {@link #getEncoded()}), this baseline is sufficient.
 */
public class JOXECPublicKey extends AsymmetricKeyImpl implements PublicKey, XECKey, OSSLKey
{
    JOXECPublicKey(PKEYKeySpec spec)
    {
        super(spec);
    }

    @Override
    public String getAlgorithm()
    {
        return spec.getType().getTypeName();
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
