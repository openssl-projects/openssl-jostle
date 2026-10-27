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

package org.openssl.jostle.util;

import org.openssl.jostle.jcajce.interfaces.SLHDSAPrivateKey;
import org.openssl.jostle.jcajce.interfaces.SLHDSAPublicKey;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.jcajce.spec.SLHDSAParameterSpec;

import java.security.PublicKey;

/** A public key presented as a private one, so a signing init meets a key with no private half. */
public class SLHDSAProxyPrivateKey implements SLHDSAPrivateKey
{
    private final SLHDSAPublicKey publicKey;
    private final PKEYKeySpec spec;

    public SLHDSAProxyPrivateKey(PublicKey publicKey)
    {
        if (!(publicKey instanceof SLHDSAPublicKey))
        {
            throw new IllegalArgumentException("public key must be an SLH-DSA public key");
        }
        this.publicKey = (SLHDSAPublicKey) publicKey;
        this.spec = ((SLHDSAPublicKey) publicKey).getSpec();
    }

    @Override
    public SLHDSAPublicKey getPublicKey()
    {
        return publicKey;
    }

    @Override
    public String getAlgorithm()
    {
        return publicKey.getAlgorithm();
    }

    @Override
    public String getFormat()
    {
        return null;
    }

    @Override
    public byte[] getEncoded()
    {
        return new byte[0];
    }

    @Override
    public SLHDSAParameterSpec getParameterSpec()
    {
        return publicKey.getParameterSpec();
    }

    @Override
    public PKEYKeySpec getSpec()
    {
        return spec;
    }
}
