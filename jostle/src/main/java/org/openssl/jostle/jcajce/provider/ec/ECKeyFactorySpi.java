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

package org.openssl.jostle.jcajce.provider.ec;

import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.rand.DefaultRandSource;
import org.openssl.jostle.rand.RandSource;
import org.openssl.jostle.util.asn1.ASNEncoder;

import java.math.BigInteger;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyFactorySpi;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * KeyFactorySpi for EC. Supports the following key-spec forms:
 * <ol>
 *   <li>{@link X509EncodedKeySpec} for public keys — decoded via the
 *       generic {@link ASNEncoder} into a Jostle {@code EVP_PKEY};</li>
 *   <li>{@link PKCS8EncodedKeySpec} for private keys — same path;</li>
 *   <li>{@link ECPublicKeySpec} for public keys — the BigInteger
 *       components are encoded to X.509 SubjectPublicKeyInfo via the
 *       JDK's SunEC provider and then decoded as in (1);</li>
 *   <li>{@link ECPrivateKeySpec} for private keys — the scalar is
 *       passed directly to a dedicated EC entry point that calls
 *       {@code EVP_PKEY_fromdata} with
 *       {@code OSSL_PKEY_PARAM_GROUP_NAME} +
 *       {@code OSSL_PKEY_PARAM_PRIV_KEY}. This avoids the
 *       SunEC-encode → OpenSSL-decode round-trip, which is fragile
 *       because OpenSSL's PKCS#8 decoder rejects some SunEC
 *       emissions ("unknown public key type"). OpenSSL re-derives the
 *       public point with point-blinded multiplication, which consumes
 *       RAND — the SPI passes a {@link RandSource} from
 *       {@code CryptoServicesRegistrar} accordingly.</li>
 * </ol>
 *
 * <p>Delegating only the public-key BigInteger-to-DER step to SunEC
 * (always present in a JDK) lets us reuse the existing OpenSSL-side
 * decoded-form path without maintaining a separate Java DER builder.
 * The private-key path stays inside our own EC bridge to dodge the
 * cross-provider PKCS#8 fragility.
 */
public class ECKeyFactorySpi extends KeyFactorySpi
{
    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException
    {
        if (keySpec instanceof X509EncodedKeySpec)
        {
            byte[] encoded = ((X509EncodedKeySpec) keySpec).getEncoded();
            PKEYKeySpec spec = ASNEncoder.fromSubjectPublicKeyInfo(encoded, 0, encoded.length);
            requireEC(spec);
            return new JOECPublicKey(spec);
        }
        if (keySpec instanceof ECPublicKeySpec)
        {
            // Raw component spec: delegate the X.509 SubjectPublicKeyInfo
            // encoding to the JDK's SunEC provider, then route the bytes
            // through our existing decoded-form path. SunEC ships with
            // every JDK so there's no extra runtime dependency, and it
            // handles the OID/parameter encoding the same way OpenSSL's
            // SPKI parser expects.
            byte[] encoded = encodeViaSunEC((ECPublicKeySpec) keySpec);
            PKEYKeySpec spec = ASNEncoder.fromSubjectPublicKeyInfo(encoded, 0, encoded.length);
            requireEC(spec);
            return new JOECPublicKey(spec);
        }
        throw new InvalidKeySpecException("unsupported key spec: " + keySpec
                + ". Use X509EncodedKeySpec or ECPublicKeySpec.");
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException
    {
        if (keySpec instanceof PKCS8EncodedKeySpec)
        {
            byte[] encoded = ((PKCS8EncodedKeySpec) keySpec).getEncoded();
            PKEYKeySpec spec = ASNEncoder.fromPrivateKeyInfo(encoded, 0, encoded.length);
            requireEC(spec);
            return new JOECPrivateKey(spec);
        }
        if (keySpec instanceof ECPrivateKeySpec)
        {
            // Component-form private key: build the EVP_PKEY directly
            // from the scalar via the EC-specific
            // makePrivateFromComponents entry point. We deliberately
            // avoid a SunEC-encode → OpenSSL-decode round-trip here
            // because OpenSSL's PKCS#8 decoder rejects some SunEC
            // emissions ("unknown public key type"); the components
            // path uses EVP_PKEY_fromdata, which OpenSSL accepts
            // unconditionally.
            return generatePrivateFromComponents(
                    (ECPrivateKeySpec) keySpec);
        }
        throw new InvalidKeySpecException("unsupported key spec: " + keySpec
                + ". Use PKCS8EncodedKeySpec or ECPrivateKeySpec.");
    }

    /**
     * Build a Jostle EC private key from a raw {@link ECPrivateKeySpec}.
     * The path is:
     * <ol>
     *   <li>resolve the {@code ECParameterSpec} back to an OpenSSL
     *       curve name via {@link ECComponents#findCurveName};</li>
     *   <li>convert the scalar {@code S} to a fixed-length, big-endian
     *       unsigned magnitude byte string of the curve byte length;</li>
     *   <li>call {@link ECServiceNI#makePrivateFromComponents}, which
     *       on the C side runs {@code EVP_PKEY_fromdata} with
     *       {@code OSSL_PKEY_PARAM_GROUP_NAME} +
     *       {@code OSSL_PKEY_PARAM_PRIV_KEY}. OpenSSL re-derives the
     *       public point internally via point-blinded scalar multiplication
     *       (the reason a {@link RandSource} is required).</li>
     * </ol>
     */
    private PrivateKey generatePrivateFromComponents(ECPrivateKeySpec spec)
            throws InvalidKeySpecException
    {
        if (spec.getS() == null)
        {
            throw new InvalidKeySpecException("ECPrivateKeySpec scalar is null");
        }
        if (spec.getParams() == null)
        {
            throw new InvalidKeySpecException("ECPrivateKeySpec params are null");
        }

        String curveName = ECComponents.findCurveName(spec.getParams());
        if (curveName == null)
        {
            throw new InvalidKeySpecException(
                    "unable to resolve ECParameterSpec to a known OpenSSL curve");
        }

        int fieldBits = spec.getParams().getCurve().getField().getFieldSize();
        int curveBytes = (fieldBits + 7) / 8;
        byte[] scalarBE = unsignedMagnitudeBE(spec.getS(), curveBytes);

        long ref = NISelector.ECServiceNI.makePrivateFromComponents(
                curveName, scalarBE,
                DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom()));
        PKEYKeySpec pkSpec = new PKEYKeySpec(ref, OSSLKeyType.EC);
        return new JOECPrivateKey(pkSpec);
    }

    /**
     * Convert a positive {@link BigInteger} to a fixed-length,
     * big-endian, unsigned magnitude byte string. {@code BigInteger.toByteArray}
     * is two's-complement and may include a leading zero (sign byte) or
     * be shorter than the curve byte length — neither matches OpenSSL's
     * {@code OSSL_PKEY_PARAM_PRIV_KEY} expectation.
     */
    private static byte[] unsignedMagnitudeBE(BigInteger value, int byteLength)
            throws InvalidKeySpecException
    {
        if (value.signum() < 0)
        {
            throw new InvalidKeySpecException("scalar is negative");
        }
        byte[] raw = value.toByteArray();
        // Drop the optional leading zero (sign byte from two's-complement).
        int start = (raw.length > 1 && raw[0] == 0) ? 1 : 0;
        int magLen = raw.length - start;
        if (magLen > byteLength)
        {
            throw new InvalidKeySpecException(
                    "scalar (" + magLen + " bytes) exceeds curve size ("
                            + byteLength + " bytes)");
        }
        byte[] out = new byte[byteLength];
        System.arraycopy(raw, start, out, byteLength - magLen, magLen);
        return out;
    }


    /**
     * Convert an {@link ECPublicKeySpec} to its X.509 SubjectPublicKeyInfo
     * encoding via SunEC. We pick SunEC explicitly (rather than a generic
     * {@code KeyFactory.getInstance("EC")}) so the output bytes don't
     * vary across the user's installed providers.
     */
    private static byte[] encodeViaSunEC(ECPublicKeySpec spec) throws InvalidKeySpecException
    {
        try
        {
            KeyFactory kf = KeyFactory.getInstance("EC", "SunEC");
            PublicKey sunPub = kf.generatePublic(spec);
            byte[] encoded = sunPub.getEncoded();
            if (encoded == null)
            {
                throw new InvalidKeySpecException(
                        "SunEC produced a public key without an X.509 encoding");
            }
            return encoded;
        }
        catch (NoSuchAlgorithmException | NoSuchProviderException e)
        {
            // SunEC ships with every JDK; absence here is unusual.
            throw new InvalidKeySpecException(
                    "ECPublicKeySpec support requires the SunEC provider", e);
        }
    }


    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException
    {
        if (key instanceof JOECPublicKey)
        {
            JOECPublicKey pub = (JOECPublicKey) key;
            if (X509EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return keySpec.cast(new X509EncodedKeySpec(pub.getEncoded()));
            }
            if (ECPublicKeySpec.class.isAssignableFrom(keySpec))
            {
                return keySpec.cast(new ECPublicKeySpec(pub.getW(), pub.getParams()));
            }
            throw new InvalidKeySpecException("unsupported key spec for EC public key: " + keySpec);
        }
        if (key instanceof JOECPrivateKey)
        {
            JOECPrivateKey priv = (JOECPrivateKey) key;
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return keySpec.cast(new PKCS8EncodedKeySpec(priv.getEncoded()));
            }
            if (ECPrivateKeySpec.class.isAssignableFrom(keySpec))
            {
                return keySpec.cast(new ECPrivateKeySpec(priv.getS(), priv.getParams()));
            }
            throw new InvalidKeySpecException("unsupported key spec for EC private key: " + keySpec);
        }
        throw new InvalidKeySpecException(
                "unrecognised key type: " + (key == null ? "null" : key.getClass().getName()));
    }

    @Override
    protected Key engineTranslateKey(Key key) throws java.security.InvalidKeyException
    {
        if (key instanceof JOECPublicKey || key instanceof JOECPrivateKey)
        {
            return key;
        }
        // Foreign EC key — re-encode and decode through us so we
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


    private static void requireEC(PKEYKeySpec spec) throws InvalidKeySpecException
    {
        if (spec.getType() != OSSLKeyType.EC)
        {
            throw new InvalidKeySpecException(
                    "expected EC key but got " + spec.getType().getAlgorithmName());
        }
    }
}
