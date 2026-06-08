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
import org.openssl.jostle.util.asn1.ASN1Encoder;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * KeyFactorySpi for X25519 / X448. Supports the encoded key-spec forms:
 * <ol>
 *   <li>{@link X509EncodedKeySpec} for public keys — decoded via the
 *       generic {@link ASN1Encoder} (OpenSSL auto-detects the X25519 / X448
 *       type from the SubjectPublicKeyInfo algorithm OID);</li>
 *   <li>{@link PKCS8EncodedKeySpec} for private keys — same path.</li>
 * </ol>
 *
 * <p>The raw-component spec forms ({@code XECPublicKeySpec} /
 * {@code XECPrivateKeySpec}) are Java 11+ and out of scope for this cut;
 * callers use the encoded forms, which round-trip through OpenSSL.
 */
public class XECKeyFactorySpi extends KeyFactorySpi
{
    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException
    {
        if (keySpec instanceof X509EncodedKeySpec)
        {
            byte[] encoded = ((X509EncodedKeySpec) keySpec).getEncoded();
            PKEYKeySpec spec = ASN1Encoder.fromSubjectPublicKeyInfo(encoded, 0, encoded.length);
            requireXEC(spec);
            return new JOXECPublicKey(spec);
        }
        throw new InvalidKeySpecException(
                "unsupported key spec: " + keySpec + ". Use X509EncodedKeySpec.");
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException
    {
        if (keySpec instanceof PKCS8EncodedKeySpec)
        {
            byte[] encoded = ((PKCS8EncodedKeySpec) keySpec).getEncoded();
            PKEYKeySpec spec = ASN1Encoder.fromPrivateKeyInfo(encoded, 0, encoded.length);
            requireXEC(spec);
            return new JOXECPrivateKey(spec);
        }
        throw new InvalidKeySpecException(
                "unsupported key spec: " + keySpec + ". Use PKCS8EncodedKeySpec.");
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException
    {
        if (key instanceof JOXECPublicKey)
        {
            if (X509EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return keySpec.cast(new X509EncodedKeySpec(((JOXECPublicKey) key).getEncoded()));
            }
            throw new InvalidKeySpecException("unsupported key spec for XDH public key: " + keySpec);
        }
        if (key instanceof JOXECPrivateKey)
        {
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return keySpec.cast(new PKCS8EncodedKeySpec(((JOXECPrivateKey) key).getEncoded()));
            }
            throw new InvalidKeySpecException("unsupported key spec for XDH private key: " + keySpec);
        }
        throw new InvalidKeySpecException(
                "unrecognised key type: " + (key == null ? "null" : key.getClass().getName()));
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException
    {
        if (key instanceof JOXECPublicKey || key instanceof JOXECPrivateKey)
        {
            return key;
        }
        // Foreign XDH key — re-encode and decode through us so we own the EVP_PKEY.
        try
        {
            byte[] encoded = key.getEncoded();
            if (encoded == null)
            {
                throw new InvalidKeyException("foreign key has no encoded form");
            }
            if (key instanceof PrivateKey)
            {
                return engineGeneratePrivate(new PKCS8EncodedKeySpec(encoded));
            }
            return engineGeneratePublic(new X509EncodedKeySpec(encoded));
        }
        catch (InvalidKeySpecException e)
        {
            throw new InvalidKeyException(e.getMessage(), e);
        }
    }

    private static void requireXEC(PKEYKeySpec spec) throws InvalidKeySpecException
    {
        if (spec.getType() != OSSLKeyType.X25519 && spec.getType() != OSSLKeyType.X448)
        {
            throw new InvalidKeySpecException(
                    "expected an XDH key but got " + spec.getType().getAlgorithmName());
        }
    }
}
