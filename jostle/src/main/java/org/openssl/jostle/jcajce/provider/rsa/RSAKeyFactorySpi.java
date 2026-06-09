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

package org.openssl.jostle.jcajce.provider.rsa;

import org.openssl.jostle.jcajce.interfaces.RSAPrivateCrtKey;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.asn1.ASN1Encoder;
import org.openssl.jostle.util.asn1.KeyInfoCanonicalizer;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RSAKeyFactorySpi extends KeyFactorySpi
{
    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException
    {
        if (keySpec instanceof X509EncodedKeySpec)
        {
            // An id-RSASSA-PSS SPKI is a structurally-identical RSA key; rewrite
            // it to rsaEncryption (as BC/SunRsaSign do) so it imports under RSA.
            // A plain rsaEncryption key is returned unchanged.
            byte[] encoded = KeyInfoCanonicalizer.rsaSubjectPublicKeyInfo(
                    ((X509EncodedKeySpec) keySpec).getEncoded());
            try
            {
                PKEYKeySpec spec = ASN1Encoder.fromSubjectPublicKeyInfo(encoded, 0, encoded.length);
                requireRSA(spec);
                return new JORSAPublicKey(spec);
            }
            catch (RuntimeException e)
            {
                // Malformed encoding surfaces from the decoder as OpenSSLException
                // / IllegalArgumentException; the KeyFactory contract requires
                // InvalidKeySpecException. requireRSA's InvalidKeySpecException is
                // checked, so it propagates unwrapped.
                throw new InvalidKeySpecException("unable to decode RSA public key", e);
            }
        }
        if (keySpec instanceof RSAPublicKeySpec)
        {
            RSAPublicKeySpec rsa = (RSAPublicKeySpec) keySpec;
            PKEYKeySpec spec = new PKEYKeySpec(NISelector.SpecNI.allocate(), OSSLKeyType.RSA);
            NISelector.RSAServiceNI.decodePublicComponents(
                    spec.getReference(),
                    unsignedMagnitude(rsa.getModulus()),
                    unsignedMagnitude(rsa.getPublicExponent()));
            return new JORSAPublicKey(spec);
        }
        throw new InvalidKeySpecException("unsupported key spec: " + keySpec);
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException
    {
        if (keySpec instanceof PKCS8EncodedKeySpec)
        {
            // See engineGeneratePublic: rewrite an id-RSASSA-PSS PrivateKeyInfo to
            // rsaEncryption; a plain rsaEncryption key is returned unchanged.
            // getEncoded() returns a fresh copy carrying the RSA private key
            // material — scrub it (and any rewritten copy the canonicalizer
            // allocated) once the native key is built, matching EdKeyFactorySpi.
            byte[] pkcs8 = ((PKCS8EncodedKeySpec) keySpec).getEncoded();
            byte[] encoded = KeyInfoCanonicalizer.rsaPrivateKeyInfo(pkcs8);
            try
            {
                PKEYKeySpec spec = ASN1Encoder.fromPrivateKeyInfo(encoded, 0, encoded.length);
                requireRSA(spec);
                return new JORSAPrivateKey(spec);
            }
            catch (RuntimeException e)
            {
                throw new InvalidKeySpecException("unable to decode RSA private key", e);
            }
            finally
            {
                if (pkcs8 != null)
                {
                    Arrays.fill(pkcs8, (byte) 0);
                }
                if (encoded != null && encoded != pkcs8)
                {
                    Arrays.fill(encoded, (byte) 0);
                }
            }
        }
        if (keySpec instanceof RSAPrivateCrtKeySpec)
        {
            // Test before RSAPrivateKeySpec — RSAPrivateCrtKeySpec extends it.
            RSAPrivateCrtKeySpec rsa = (RSAPrivateCrtKeySpec) keySpec;
            PKEYKeySpec spec = new PKEYKeySpec(NISelector.SpecNI.allocate(), OSSLKeyType.RSA);
            NISelector.RSAServiceNI.decodePrivateComponentsCrt(
                    spec.getReference(),
                    unsignedMagnitude(rsa.getModulus()),
                    unsignedMagnitude(rsa.getPublicExponent()),
                    unsignedMagnitude(rsa.getPrivateExponent()),
                    unsignedMagnitude(rsa.getPrimeP()),
                    unsignedMagnitude(rsa.getPrimeQ()),
                    unsignedMagnitude(rsa.getPrimeExponentP()),
                    unsignedMagnitude(rsa.getPrimeExponentQ()),
                    unsignedMagnitude(rsa.getCrtCoefficient()));
            return new JORSAPrivateKey(spec);
        }
        if (keySpec instanceof RSAPrivateKeySpec)
        {
            // Non-CRT private. CRT-component getters on the resulting
            // key will return null per the JCA contract.
            RSAPrivateKeySpec rsa = (RSAPrivateKeySpec) keySpec;
            PKEYKeySpec spec = new PKEYKeySpec(NISelector.SpecNI.allocate(), OSSLKeyType.RSA);
            // OpenSSL needs the public exponent to construct the EVP_PKEY,
            // which RSAPrivateKeySpec doesn't supply. We can reconstruct
            // it via e = mod_inverse(d_mod_phi) but only with p and q —
            // which we also don't have. Reject explicitly rather than
            // ship a key that won't function.
            throw new InvalidKeySpecException(
                    "RSAPrivateKeySpec without CRT components is not supported "
                            + "— OpenSSL requires the public exponent to construct an EVP_PKEY. "
                            + "Use RSAPrivateCrtKeySpec or PKCS8EncodedKeySpec instead.");
        }
        throw new InvalidKeySpecException("unsupported key spec: " + keySpec);
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException
    {
        if (key instanceof JORSAPublicKey)
        {
            JORSAPublicKey pub = (JORSAPublicKey) key;
            if (X509EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return keySpec.cast(new X509EncodedKeySpec(pub.getEncoded()));
            }
            if (RSAPublicKeySpec.class.isAssignableFrom(keySpec))
            {
                return keySpec.cast(new RSAPublicKeySpec(pub.getModulus(), pub.getPublicExponent()));
            }
            throw new InvalidKeySpecException("unsupported key spec for RSA public key: " + keySpec);
        }
        if (key instanceof JORSAPrivateKey)
        {
            JORSAPrivateKey priv = (JORSAPrivateKey) key;
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return keySpec.cast(new PKCS8EncodedKeySpec(priv.getEncoded()));
            }
            if (RSAPrivateCrtKeySpec.class.isAssignableFrom(keySpec))
            {
                BigInteger p = priv.getPrimeP();
                if (p == null)
                {
                    throw new InvalidKeySpecException(
                            "key has no CRT components — cannot produce RSAPrivateCrtKeySpec");
                }
                return keySpec.cast(new RSAPrivateCrtKeySpec(
                        priv.getModulus(), priv.getPublicExponent(),
                        priv.getPrivateExponent(),
                        p, priv.getPrimeQ(),
                        priv.getPrimeExponentP(), priv.getPrimeExponentQ(),
                        priv.getCrtCoefficient()));
            }
            if (RSAPrivateKeySpec.class.isAssignableFrom(keySpec))
            {
                return keySpec.cast(new RSAPrivateKeySpec(priv.getModulus(), priv.getPrivateExponent()));
            }
            throw new InvalidKeySpecException("unsupported key spec for RSA private key: " + keySpec);
        }
        throw new InvalidKeySpecException("unrecognised key type: " + (key == null ? "null" : key.getClass().getName()));
    }

    @Override
    protected Key engineTranslateKey(Key key) throws java.security.InvalidKeyException
    {
        if (key instanceof JORSAPublicKey || key instanceof JORSAPrivateKey)
        {
            return key;
        }
        // Foreign RSA key — re-encode and decode through us so we
        // own the EVP_PKEY.
        try
        {
            if (key instanceof java.security.interfaces.RSAPrivateCrtKey)
            {
                java.security.interfaces.RSAPrivateCrtKey rsa =
                        (java.security.interfaces.RSAPrivateCrtKey) key;
                return engineGeneratePrivate(new RSAPrivateCrtKeySpec(
                        rsa.getModulus(), rsa.getPublicExponent(),
                        rsa.getPrivateExponent(),
                        rsa.getPrimeP(), rsa.getPrimeQ(),
                        rsa.getPrimeExponentP(), rsa.getPrimeExponentQ(),
                        rsa.getCrtCoefficient()));
            }
            if (key instanceof java.security.interfaces.RSAPublicKey)
            {
                java.security.interfaces.RSAPublicKey rsa =
                        (java.security.interfaces.RSAPublicKey) key;
                return engineGeneratePublic(new RSAPublicKeySpec(
                        rsa.getModulus(), rsa.getPublicExponent()));
            }
            // Fall through to encoded form.
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


    private static void requireRSA(PKEYKeySpec spec) throws InvalidKeySpecException
    {
        if (spec.getType() != OSSLKeyType.RSA)
        {
            throw new InvalidKeySpecException(
                    "expected RSA key but got " + spec.getType().getAlgorithmName());
        }
    }

    /**
     * BigInteger.toByteArray returns a two's-complement encoding,
     * which for positive integers is the unsigned magnitude with at
     * most one extra leading zero byte. The native layer's
     * {@code BN_bin2bn} accepts either form, so we pass the toByteArray
     * output through unchanged.
     */
    private static byte[] unsignedMagnitude(BigInteger v)
    {
        return v.toByteArray();
    }
}
