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

import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.rand.DefaultRandSource;
import org.openssl.jostle.util.asn1.ASN1Encoder;

import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * KeyFactorySpi for finite-field Diffie-Hellman. Supports the
 * following key-spec forms:
 * <ol>
 *   <li>{@link X509EncodedKeySpec} for public keys — decoded via the
 *       generic {@link ASN1Encoder} into a Jostle {@code EVP_PKEY};</li>
 *   <li>{@link PKCS8EncodedKeySpec} for private keys — same path;</li>
 *   <li>{@link DHPublicKeySpec} for public keys — the BigInteger
 *       components (y, p, g) are imported directly through
 *       {@code EVP_PKEY_fromdata};</li>
 *   <li>{@link DHPrivateKeySpec} for private keys — the components
 *       (x, p, g) are imported the same way; the public value
 *       y = g^x mod p is computed on the native side because
 *       OpenSSL's FFC import does not re-derive it.</li>
 * </ol>
 */
public class DHKeyFactorySpi extends KeyFactorySpi
{
    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException
    {
        if (keySpec instanceof X509EncodedKeySpec)
        {
            byte[] encoded = ((X509EncodedKeySpec) keySpec).getEncoded();
            PKEYKeySpec spec = ASN1Encoder.fromSubjectPublicKeyInfo(encoded, 0, encoded.length);
            requireDH(spec);
            return new JODHPublicKey(spec);
        }
        if (keySpec instanceof DHPublicKeySpec)
        {
            DHPublicKeySpec pubSpec = (DHPublicKeySpec) keySpec;
            byte[] p = magnitude(pubSpec.getP(), "p");
            byte[] g = magnitude(pubSpec.getG(), "g");
            byte[] y = magnitude(pubSpec.getY(), "y");
            long ref = NISelector.DHServiceNI.makePublicFromComponents(p, g, y);
            return new JODHPublicKey(new PKEYKeySpec(ref, OSSLKeyType.DH));
        }
        throw new InvalidKeySpecException("unsupported key spec: " + keySpec
                + ". Use X509EncodedKeySpec or DHPublicKeySpec.");
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException
    {
        if (keySpec instanceof PKCS8EncodedKeySpec)
        {
            byte[] encoded = ((PKCS8EncodedKeySpec) keySpec).getEncoded();
            PKEYKeySpec spec = ASN1Encoder.fromPrivateKeyInfo(encoded, 0, encoded.length);
            requireDH(spec);
            return new JODHPrivateKey(spec);
        }
        if (keySpec instanceof DHPrivateKeySpec)
        {
            DHPrivateKeySpec privSpec = (DHPrivateKeySpec) keySpec;
            byte[] p = magnitude(privSpec.getP(), "p");
            byte[] g = magnitude(privSpec.getG(), "g");
            byte[] x = magnitude(privSpec.getX(), "x");
            long ref = NISelector.DHServiceNI.makePrivateFromComponents(
                    p, g, x,
                    DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom()));
            return new JODHPrivateKey(new PKEYKeySpec(ref, OSSLKeyType.DH));
        }
        throw new InvalidKeySpecException("unsupported key spec: " + keySpec
                + ". Use PKCS8EncodedKeySpec or DHPrivateKeySpec.");
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException
    {
        if (key instanceof JODHPublicKey)
        {
            JODHPublicKey pub = (JODHPublicKey) key;
            if (X509EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return keySpec.cast(new X509EncodedKeySpec(pub.getEncoded()));
            }
            if (DHPublicKeySpec.class.isAssignableFrom(keySpec))
            {
                DHParameterSpec params = pub.getParams();
                return keySpec.cast(new DHPublicKeySpec(
                        pub.getY(), params.getP(), params.getG()));
            }
            throw new InvalidKeySpecException("unsupported key spec for DH public key: " + keySpec);
        }
        if (key instanceof JODHPrivateKey)
        {
            JODHPrivateKey priv = (JODHPrivateKey) key;
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return keySpec.cast(new PKCS8EncodedKeySpec(priv.getEncoded()));
            }
            if (DHPrivateKeySpec.class.isAssignableFrom(keySpec))
            {
                DHParameterSpec params = priv.getParams();
                return keySpec.cast(new DHPrivateKeySpec(
                        priv.getX(), params.getP(), params.getG()));
            }
            throw new InvalidKeySpecException("unsupported key spec for DH private key: " + keySpec);
        }
        throw new InvalidKeySpecException(
                "unrecognised key type: " + (key == null ? "null" : key.getClass().getName()));
    }

    @Override
    protected Key engineTranslateKey(Key key) throws java.security.InvalidKeyException
    {
        if (key instanceof JODHPublicKey || key instanceof JODHPrivateKey)
        {
            return key;
        }
        // Foreign DH key — re-encode and decode through us so we
        // own the EVP_PKEY.
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


    /**
     * Validate and convert one BigInteger component to its big-endian
     * unsigned magnitude. DH components are all positive integers; a
     * null or non-positive value is a malformed spec.
     */
    private static byte[] magnitude(BigInteger value, String name)
            throws InvalidKeySpecException
    {
        if (value == null)
        {
            throw new InvalidKeySpecException("DH component '" + name + "' is null");
        }
        if (value.signum() <= 0)
        {
            throw new InvalidKeySpecException("DH component '" + name + "' must be positive");
        }
        return DHComponents.unsignedMagnitude(value);
    }

    private static void requireDH(PKEYKeySpec spec) throws InvalidKeySpecException
    {
        if (spec.getType() != OSSLKeyType.DH)
        {
            throw new InvalidKeySpecException(
                    "expected DH key but got " + spec.getType().getAlgorithmName());
        }
    }
}
