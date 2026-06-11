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

package org.openssl.jostle.jcajce.provider.dsa;

import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.rand.DefaultRandSource;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.asn1.ASN1Encoder;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * KeyFactorySpi for DSA. Supports the following key-spec forms:
 * <ol>
 *   <li>{@link X509EncodedKeySpec} for public keys — decoded via the
 *       generic {@link ASN1Encoder} into a Jostle {@code EVP_PKEY};</li>
 *   <li>{@link PKCS8EncodedKeySpec} for private keys — same path;</li>
 *   <li>{@link DSAPublicKeySpec} for public keys — the BigInteger
 *       components (y, p, q, g) are imported directly through
 *       {@code EVP_PKEY_fromdata};</li>
 *   <li>{@link DSAPrivateKeySpec} for private keys — the components
 *       (x, p, q, g) are imported the same way; the public value
 *       y = g^x mod p is computed on the native side because
 *       OpenSSL's FFC import does not re-derive it.</li>
 * </ol>
 */
public class DSAKeyFactorySpi extends KeyFactorySpi
{
    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException
    {
        if (keySpec instanceof X509EncodedKeySpec)
        {
            byte[] encoded = ((X509EncodedKeySpec) keySpec).getEncoded();
            try
            {
                PKEYKeySpec spec = ASN1Encoder.fromSubjectPublicKeyInfo(encoded, 0, encoded.length);
                requireDSA(spec);
                return new JODSAPublicKey(spec);
            }
            catch (RuntimeException e)
            {
                // Malformed encoding surfaces from the decoder as OpenSSLException
                // / IllegalArgumentException; the KeyFactory contract requires
                // InvalidKeySpecException (RSAKeyFactorySpi precedent).
                throw new InvalidKeySpecException("unable to decode DSA public key", e);
            }
        }
        if (keySpec instanceof DSAPublicKeySpec)
        {
            DSAPublicKeySpec pubSpec = (DSAPublicKeySpec) keySpec;
            byte[] p = magnitude(pubSpec.getP(), "p");
            byte[] q = magnitude(pubSpec.getQ(), "q");
            byte[] g = magnitude(pubSpec.getG(), "g");
            byte[] y = magnitude(pubSpec.getY(), "y");
            long ref = NISelector.DSAServiceNI.makePublicFromComponents(p, q, g, y);
            return new JODSAPublicKey(new PKEYKeySpec(ref, OSSLKeyType.DSA));
        }
        throw new InvalidKeySpecException("unsupported key spec: " + keySpec
                + ". Use X509EncodedKeySpec or DSAPublicKeySpec.");
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException
    {
        if (keySpec instanceof PKCS8EncodedKeySpec)
        {
            // getEncoded() returns a fresh copy carrying the private value x —
            // scrub it once the native key is built (Ed/RSA precedent).
            byte[] encoded = ((PKCS8EncodedKeySpec) keySpec).getEncoded();
            try
            {
                PKEYKeySpec spec = ASN1Encoder.fromPrivateKeyInfo(encoded, 0, encoded.length);
                requireDSA(spec);
                return new JODSAPrivateKey(spec);
            }
            catch (RuntimeException e)
            {
                throw new InvalidKeySpecException("unable to decode DSA private key", e);
            }
            finally
            {
                if (encoded != null)
                {
                    Arrays.fill(encoded, (byte) 0);
                }
            }
        }
        if (keySpec instanceof DSAPrivateKeySpec)
        {
            DSAPrivateKeySpec privSpec = (DSAPrivateKeySpec) keySpec;
            byte[] p = magnitude(privSpec.getP(), "p");
            byte[] q = magnitude(privSpec.getQ(), "q");
            byte[] g = magnitude(privSpec.getG(), "g");
            byte[] x = magnitude(privSpec.getX(), "x");
            long ref = NISelector.DSAServiceNI.makePrivateFromComponents(
                    p, q, g, x,
                    DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom()));
            return new JODSAPrivateKey(new PKEYKeySpec(ref, OSSLKeyType.DSA));
        }
        throw new InvalidKeySpecException("unsupported key spec: " + keySpec
                + ". Use PKCS8EncodedKeySpec or DSAPrivateKeySpec.");
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException
    {
        if (key instanceof JODSAPublicKey)
        {
            JODSAPublicKey pub = (JODSAPublicKey) key;
            if (X509EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return keySpec.cast(new X509EncodedKeySpec(pub.getEncoded()));
            }
            if (DSAPublicKeySpec.class.isAssignableFrom(keySpec))
            {
                java.security.interfaces.DSAParams params = pub.getParams();
                return keySpec.cast(new DSAPublicKeySpec(
                        pub.getY(), params.getP(), params.getQ(), params.getG()));
            }
            throw new InvalidKeySpecException("unsupported key spec for DSA public key: " + keySpec);
        }
        if (key instanceof JODSAPrivateKey)
        {
            JODSAPrivateKey priv = (JODSAPrivateKey) key;
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return keySpec.cast(new PKCS8EncodedKeySpec(priv.getEncoded()));
            }
            if (DSAPrivateKeySpec.class.isAssignableFrom(keySpec))
            {
                java.security.interfaces.DSAParams params = priv.getParams();
                return keySpec.cast(new DSAPrivateKeySpec(
                        priv.getX(), params.getP(), params.getQ(), params.getG()));
            }
            throw new InvalidKeySpecException("unsupported key spec for DSA private key: " + keySpec);
        }
        throw new InvalidKeySpecException(
                "unrecognised key type: " + (key == null ? "null" : key.getClass().getName()));
    }

    @Override
    protected Key engineTranslateKey(Key key) throws java.security.InvalidKeyException
    {
        if (key instanceof JODSAPublicKey || key instanceof JODSAPrivateKey)
        {
            return key;
        }
        if (key == null)
        {
            throw new java.security.InvalidKeyException("key is null");
        }
        // Foreign DSA key — re-encode and decode through us so we
        // own the EVP_PKEY.
        byte[] encoded = null;
        try
        {
            encoded = key.getEncoded();
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
        catch (RuntimeException e)
        {
            // A hostile/broken foreign key can throw from getEncoded();
            // surface the typed exception the translate contract requires.
            throw new java.security.InvalidKeyException("unable to translate key", e);
        }
        finally
        {
            // The local copy may carry private material — scrub it
            // (engineGeneratePrivate scrubbed only its own inner clone).
            if (encoded != null)
            {
                Arrays.fill(encoded, (byte) 0);
            }
        }
    }


    /**
     * Validate and convert one BigInteger component to its big-endian
     * unsigned magnitude. DSA components are all positive integers; a
     * null or non-positive value is a malformed spec.
     */
    /**
     * Upper bound on any imported DSA component. DoS protection: the
     * private import eagerly computes y = g^x mod p natively, which is
     * O(bits^3) — an unbounded p turns the KeyFactory into a CPU sink.
     */
    private static final int MAX_COMPONENT_BITS = 16384;

    private static byte[] magnitude(BigInteger value, String name)
            throws InvalidKeySpecException
    {
        if (value == null)
        {
            throw new InvalidKeySpecException("DSA component '" + name + "' is null");
        }
        if (value.signum() <= 0)
        {
            throw new InvalidKeySpecException("DSA component '" + name + "' must be positive");
        }
        if (value.bitLength() > MAX_COMPONENT_BITS)
        {
            throw new InvalidKeySpecException("DSA component '" + name + "' exceeds "
                    + MAX_COMPONENT_BITS + " bits");
        }
        return DSAComponents.unsignedMagnitude(value);
    }

    private static void requireDSA(PKEYKeySpec spec) throws InvalidKeySpecException
    {
        if (spec.getType() != OSSLKeyType.DSA)
        {
            throw new InvalidKeySpecException(
                    "expected DSA key but got " + spec.getType().getAlgorithmName());
        }
    }
}
