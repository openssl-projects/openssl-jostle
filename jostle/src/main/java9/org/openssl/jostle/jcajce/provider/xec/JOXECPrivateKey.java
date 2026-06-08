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
import org.openssl.jostle.util.asn1.PrivateKeyOptions;

import java.lang.ref.Reference;
import java.security.PrivateKey;

/**
 * Java 9+ override of the Java 8 baseline. Uses
 * {@link Reference#reachabilityFence} to keep this key reachable across the
 * native encoding call, replacing the {@code synchronized(this)} idiom in
 * the baseline. The public surface is identical to the baseline copy.
 *
 * <p>X25519 / X448 private key. Encodes as PKCS#8 PrivateKeyInfo via the
 * generic {@link ASNEncoder}; the concrete algorithm comes from the key's
 * {@link org.openssl.jostle.jcajce.spec.OSSLKeyType}.
 */
class JOXECPrivateKey extends AsymmetricKeyImpl implements PrivateKey, XDHKey, OSSLKey
{
    JOXECPrivateKey(PKEYKeySpec spec)
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
        return "PKCS#8";
    }

    @Override
    public byte[] getEncoded()
    {
        try
        {
            return ASNEncoder.asPrivateKeyInfo(spec, PrivateKeyOptions.DEFAULT);
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
}
