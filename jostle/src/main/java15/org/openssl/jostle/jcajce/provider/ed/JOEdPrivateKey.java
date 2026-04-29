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

package org.openssl.jostle.jcajce.provider.ed;

import org.openssl.jostle.jcajce.interfaces.EdDSAPrivateKey;
import org.openssl.jostle.jcajce.interfaces.EdDSAPublicKey;
import org.openssl.jostle.jcajce.interfaces.OSSLKey;
import org.openssl.jostle.jcajce.provider.AsymmetricKeyImpl;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.EdDSAParameterSpec;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.util.asn1.ASNEncoder;
import org.openssl.jostle.util.asn1.PrivateKeyOptions;

import java.lang.ref.Reference;
import java.security.interfaces.EdECPrivateKey;
import java.security.spec.NamedParameterSpec;
import java.util.Optional;

public class JOEdPrivateKey extends AsymmetricKeyImpl implements EdDSAPrivateKey, OSSLKey, EdECPrivateKey
{

    public JOEdPrivateKey(PKEYKeySpec spec)
    {
        super(spec);
    }


    @Override
    public EdDSAPublicKey getPublicKey()
    {
        return new JOEdPublicKey(spec);
    }

    @Override
    public String getAlgorithm()
    {
        return getType().getAlgorithmName();
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

    /**
     * Raw RFC 8032 private scalar bytes (32 for Ed25519, 57 for Ed448).
     * The try/finally with Reference.reachabilityFence keeps `this` alive
     * across the native calls so the underlying EVP_PKEY can't be reclaimed
     * mid-flight.
     */
    public byte[] getRawScalar()
    {
        try
        {
            int len = NISelector.EDServiceNI.getPrivateKey(spec.getReference(), null);
            byte[] raw = new byte[len];
            NISelector.EDServiceNI.getPrivateKey(spec.getReference(), raw);
            return raw;
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }

    /**
     * Raw RFC 8032 public-key bytes corresponding to this private key, read
     * from the underlying EVP_PKEY (which holds both halves of the pair).
     */
    public byte[] getRawPublic()
    {
        try
        {
            int len = NISelector.EDServiceNI.getPublicKey(spec.getReference(), null);
            byte[] raw = new byte[len];
            NISelector.EDServiceNI.getPublicKey(spec.getReference(), raw);
            return raw;
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }

    @Override
    public Optional<byte[]> getBytes()
    {
        if (OSSLKeyType.ED25519 == getType() || OSSLKeyType.ED448 == getType())
        {
            return Optional.of(getRawScalar());
        }
        throw new IllegalArgumentException("Unknown OSSLKeyType: " + getType());
    }

    public EdDSAParameterSpec getParameterSpec()
    {
        switch (spec.getType())
        {
            case ED448:
                return EdDSAParameterSpec.ED448;
            case ED25519:
                return EdDSAParameterSpec.ED25519;
            default:
                throw new IllegalArgumentException("unknown parameter type: " + spec.getType().name());
        }
    }



    @Override
    public NamedParameterSpec getParams()
    {

        if (spec.getType() == OSSLKeyType.ED25519)
        {
            return NamedParameterSpec.ED25519;
        }
        else if (spec.getType() == OSSLKeyType.ED448)
        {
            return NamedParameterSpec.ED448;
        }
        throw new IllegalArgumentException("Unknown OSSLKeyType: " + spec.getType().name());
    }
}
