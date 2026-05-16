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

import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.util.asn1.ASNEncoder;

import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * KeyFactorySpi for X25519 / X448. Round-trips X.509 SubjectPublicKeyInfo
 * (public) and PKCS#8 PrivateKeyInfo (private) through OpenSSL via the
 * existing {@link ASNEncoder} helpers — same path EC and RSA use.
 *
 * <p>The factory accepts either curve. A pinned variant could reject a
 * spec whose decoded type doesn't match, but for CMP / CMS usage the
 * bcpkix layer typically asks for "XDH" without pinning, so we accept
 * both here and let the caller dispatch on the resulting key type.
 */
public class XECKeyFactorySpi extends KeyFactorySpi
{
    private final OSSLKeyType mandatedType;

    public XECKeyFactorySpi()
    {
        this.mandatedType = null;
    }

    public XECKeyFactorySpi(OSSLKeyType mandatedType)
    {
        this.mandatedType = mandatedType;
    }

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException
    {
        if (keySpec instanceof X509EncodedKeySpec)
        {
            byte[] encoded = ((X509EncodedKeySpec) keySpec).getEncoded();
            PKEYKeySpec spec = ASNEncoder.fromSubjectPublicKeyInfo(encoded, 0, encoded.length);
            requireXEC(spec);
            return new JOXECPublicKey(spec);
        }
        throw new InvalidKeySpecException(
                "unsupported key spec: " + (keySpec == null ? "null" : keySpec.getClass().getName())
                        + ". Use X509EncodedKeySpec.");
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException
    {
        if (keySpec instanceof PKCS8EncodedKeySpec)
        {
            byte[] encoded = ((PKCS8EncodedKeySpec) keySpec).getEncoded();
            PKEYKeySpec spec = ASNEncoder.fromPrivateKeyInfo(encoded, 0, encoded.length);
            requireXEC(spec);
            return new JOXECPrivateKey(spec);
        }
        throw new InvalidKeySpecException(
                "unsupported key spec: " + (keySpec == null ? "null" : keySpec.getClass().getName())
                        + ". Use PKCS8EncodedKeySpec.");
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException
    {
        if (key == null)
        {
            throw new InvalidKeySpecException("key is null");
        }
        if (key instanceof JOXECPublicKey)
        {
            if (X509EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return keySpec.cast(new X509EncodedKeySpec(key.getEncoded()));
            }
            throw new InvalidKeySpecException(
                    "unsupported key spec for XDH public key: " + keySpec);
        }
        if (key instanceof JOXECPrivateKey)
        {
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return keySpec.cast(new PKCS8EncodedKeySpec(key.getEncoded()));
            }
            throw new InvalidKeySpecException(
                    "unsupported key spec for XDH private key: " + keySpec);
        }
        throw new InvalidKeySpecException(
                "unrecognised key type: " + key.getClass().getName());
    }

    @Override
    protected Key engineTranslateKey(Key key) throws java.security.InvalidKeyException
    {
        if (key instanceof JOXECPublicKey || key instanceof JOXECPrivateKey)
        {
            return key;
        }
        // Foreign XDH key — re-encode and decode through us so we own
        // the EVP_PKEY.
        try
        {
            byte[] encoded = key.getEncoded();
            if (encoded == null)
            {
                throw new java.security.InvalidKeyException("foreign key has no encoded form");
            }
            if (key instanceof PrivateKey)
            {
                return engineGeneratePrivate(new PKCS8EncodedKeySpec(encoded));
            }
            return engineGeneratePublic(new X509EncodedKeySpec(encoded));
        }
        catch (InvalidKeySpecException e)
        {
            throw new java.security.InvalidKeyException(e.getMessage(), e);
        }
    }

    private void requireXEC(PKEYKeySpec spec) throws InvalidKeySpecException
    {
        OSSLKeyType t = spec.getType();
        if (t != OSSLKeyType.X25519 && t != OSSLKeyType.X448)
        {
            throw new InvalidKeySpecException(
                    "expected X25519 / X448 key but got " + t.getAlgorithmName());
        }
        if (mandatedType != null && mandatedType != t)
        {
            throw new InvalidKeySpecException(
                    "expected " + mandatedType.getAlgorithmName()
                            + " but got " + t.getAlgorithmName());
        }
    }
}
