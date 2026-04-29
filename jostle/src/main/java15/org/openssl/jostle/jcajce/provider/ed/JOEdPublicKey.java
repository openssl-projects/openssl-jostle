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

import org.openssl.jostle.jcajce.interfaces.EdDSAPublicKey;
import org.openssl.jostle.jcajce.provider.AsymmetricKeyImpl;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.EdDSAParameterSpec;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.util.asn1.ASNEncoder;

import java.lang.ref.Reference;
import java.math.BigInteger;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.EdECPoint;
import java.security.spec.NamedParameterSpec;

public class JOEdPublicKey extends AsymmetricKeyImpl implements EdDSAPublicKey, java.security.interfaces.EdECPublicKey
{
    public JOEdPublicKey(PKEYKeySpec spec)
    {
        super(spec);
    }

    @Override
    public String getAlgorithm()
    {
        return getType().getAlgorithmName();
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

    public PKEYKeySpec getSpec()
    {
        return spec;
    }

    /**
     * Raw RFC 8032 public key bytes (32 for Ed25519, 57 for Ed448). The
     * try/finally with Reference.reachabilityFence keeps `this` alive across
     * the native calls so the underlying EVP_PKEY can't be reclaimed mid-flight.
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
    public EdECPoint getPoint()
    {
        // RFC 8032 §3.1 / §5.2.2: the encoded public key is the y coordinate
        // as a little-endian unsigned integer with the sign of x packed into
        // the MSB of the last byte.
        byte[] raw = getRawPublic();
        int len = raw.length;

        boolean xOdd = (raw[len - 1] & 0x80) != 0;
        raw[len - 1] &= (byte) 0x7F;

        // little-endian → big-endian for BigInteger
        for (int i = 0, j = len - 1; i < j; i++, j--)
        {
            byte tmp = raw[i];
            raw[i] = raw[j];
            raw[j] = tmp;
        }

        return new EdECPoint(xOdd, new BigInteger(1, raw));
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
}
