/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.mldsa;

import org.openssl.jostle.jcajce.interfaces.MLDSAPrivateKey;
import org.openssl.jostle.jcajce.interfaces.MLDSAPublicKey;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.*;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.asn1.ASN1Encoder;
import org.openssl.jostle.util.asn1.KeyInfoCanonicalizer;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class MLDSAKeyFactorySpiImpl extends KeyFactorySpi
{

    private final OSSLKeyType fixedType;

    private static final Map<MLDSAParameterSpec, OSSLKeyType> typeMap = Collections.unmodifiableMap(new HashMap<MLDSAParameterSpec, OSSLKeyType>()
    {
        {
            put(MLDSAParameterSpec.ml_dsa_44, OSSLKeyType.ML_DSA_44);
            put(MLDSAParameterSpec.ml_dsa_65, OSSLKeyType.ML_DSA_65);
            put(MLDSAParameterSpec.ml_dsa_87, OSSLKeyType.ML_DSA_87);
        }
    });

    public MLDSAKeyFactorySpiImpl(OSSLKeyType keyType)
    {
        this.fixedType = keyType;
        assert keyType != null;
    }

    public MLDSAKeyFactorySpiImpl()
    {
        this.fixedType = OSSLKeyType.NONE;
    }

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException
    {
        if (keySpec instanceof X509EncodedKeySpec)
        {
            byte[] encoded = KeyInfoCanonicalizer.subjectPublicKeyInfo(((X509EncodedKeySpec) keySpec).getEncoded());

            try
            {
                PKEYKeySpec pkeySpec = ASN1Encoder.fromSubjectPublicKeyInfo(encoded, 0, encoded.length);

                if (fixedType != OSSLKeyType.NONE && fixedType != pkeySpec.getType())
                {
                    throw new InvalidKeySpecException("expected " + fixedType.getAlgorithmName() + " but got " + pkeySpec.getType().getAlgorithmName());
                }

                switch (pkeySpec.getType())
                {
                    case ML_DSA_44:
                    case ML_DSA_65:
                    case ML_DSA_87:
                        break;
                    default:
                        throw new InvalidKeySpecException("expected ML-DSA key but got " + pkeySpec.getType());
                }

                return new JOMLDSAPublicKey(pkeySpec);
            }
            catch (RuntimeException e)
            {
                // Malformed encoding surfaces from the decoder as OpenSSLException
                // / IllegalArgumentException; the KeyFactory contract requires
                // InvalidKeySpecException (RSAKeyFactorySpi precedent).
                throw new InvalidKeySpecException("unable to decode ML-DSA public key", e);
            }
        }
        else
        {
            if (keySpec instanceof MLDSAPublicKeySpec)
            {
                MLDSAPublicKeySpec pubSpec = (MLDSAPublicKeySpec) keySpec;

                OSSLKeyType osslKeyType = typeMap.get(pubSpec.getParameterSpec());

                if (osslKeyType == null)
                {
                    // A spec built with a null / unrecognised parameter set
                    // would otherwise NPE at osslKeyType.getKsType().
                    throw new InvalidKeySpecException("unknown ML-DSA parameter set: " + pubSpec.getParameterSpec());
                }

                if (fixedType != OSSLKeyType.NONE && osslKeyType != fixedType)
                {
                    throw new InvalidKeySpecException("Invalid KeySpec: " + keySpec);
                }

                byte[] encoded = pubSpec.getPublicData();
                try
                {
                    PKEYKeySpec pkeySpec = new PKEYKeySpec(NISelector.SpecNI.allocate(), osslKeyType);

                    NISelector.MLDSAServiceNI.decode_publicKey(
                            pkeySpec.getReference(), osslKeyType.getKsType(), encoded, 0, encoded.length);
                    return new JOMLDSAPublicKey(pkeySpec);
                }
                catch (RuntimeException e)
                {
                    // A wrong-length / malformed raw encoding surfaces from the
                    // decoder as IllegalArgumentException / OpenSSLException; the
                    // KeyFactory contract requires InvalidKeySpecException (matches
                    // the X509 wrapper above).
                    throw new InvalidKeySpecException("unable to decode ML-DSA public key", e);
                }
                finally
                {
                    Arrays.clear(encoded);
                }
            }
        }
        throw new InvalidKeySpecException("Invalid KeySpec: " + keySpec);
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException
    {
        if (keySpec instanceof PKCS8EncodedKeySpec)
        {

            byte[] pkcs8 = ((PKCS8EncodedKeySpec) keySpec).getEncoded();
            byte[] encoded = KeyInfoCanonicalizer.privateKeyInfo(pkcs8);

            try
            {
                PKEYKeySpec pkeySpec = ASN1Encoder.fromPrivateKeyInfo(encoded, 0, encoded.length);

                if (fixedType != OSSLKeyType.NONE && fixedType != pkeySpec.getType())
                {
                    throw new InvalidKeySpecException("expected " + fixedType.getAlgorithmName() + " but got " + pkeySpec.getType());
                }

                switch (pkeySpec.getType())
                {
                    case ML_DSA_44:
                    case ML_DSA_65:
                    case ML_DSA_87:
                        break;
                    default:
                        throw new InvalidKeySpecException("expected ML-DSA key but got " + pkeySpec.getType());
                }

                return new JOMLDSAPrivateKey(pkeySpec);
            }
            catch (RuntimeException e)
            {
                throw new InvalidKeySpecException("unable to decode ML-DSA private key", e);
            }
            finally
            {
                // The PKCS#8 blob and any canonicalized copy carry the raw private
                // key — scrub both, on failure paths too (MLKEM/Ed/RSA precedent).
                Arrays.clear(pkcs8);
                if (encoded != null && encoded != pkcs8)
                {
                    Arrays.clear(encoded);
                }
            }
        }
        else
        {
            if (keySpec instanceof MLDSAPrivateKeySpec)
            {
                MLDSAPrivateKeySpec spec = (MLDSAPrivateKeySpec) keySpec;
                OSSLKeyType osslKeyType = typeMap.get(spec.getParameterSpec());

                if (osslKeyType == null)
                {
                    // A spec built with a null / unrecognised parameter set
                    // would otherwise NPE at osslKeyType.getKsType().
                    throw new InvalidKeySpecException("unknown ML-DSA parameter set: " + spec.getParameterSpec());
                }

                if (fixedType != OSSLKeyType.NONE && osslKeyType != fixedType)
                {
                    throw new InvalidKeySpecException("Invalid KeySpec: " + keySpec);
                }

                byte[] encoded;
                if (spec.isSeed())
                {
                    encoded = spec.getSeed();
                }
                else
                {
                    encoded = spec.getPrivateData();
                }
                try
                {
                    PKEYKeySpec pkeySpec = new PKEYKeySpec(NISelector.SpecNI.allocate(), osslKeyType);
                    NISelector.MLDSAServiceNI.decode_privateKey(
                            pkeySpec.getReference(), osslKeyType.getKsType(),
                            encoded, 0, encoded.length);
                    return new JOMLDSAPrivateKey(pkeySpec, spec.isSeed());
                }
                catch (RuntimeException e)
                {
                    // A wrong-length / malformed raw encoding surfaces from the
                    // decoder as IllegalArgumentException / OpenSSLException; the
                    // KeyFactory contract requires InvalidKeySpecException (matches
                    // the PKCS#8 wrapper above).
                    throw new InvalidKeySpecException("unable to decode ML-DSA private key", e);
                }
                finally
                {
                    // Transient raw seed / private encoding cloned from the spec.
                    Arrays.clear(encoded);
                }
            }
        }

        throw new InvalidKeySpecException("Invalid KeySpec: " + keySpec);
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException
    {
        if (key instanceof JOMLDSAPrivateKey)
        {
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return keySpec.cast(new PKCS8EncodedKeySpec(key.getEncoded()));
            }
            else
            {
                if (MLDSAPrivateKeySpec.class.isAssignableFrom(keySpec))
                {
                    JOMLDSAPrivateKey mKey = (JOMLDSAPrivateKey) key;
                    if (mKey.seedOnly)
                    {
                        return keySpec.cast(new MLDSAPrivateKeySpec(mKey.getParameterSpec(), mKey.getSeed()));
                    }
                    else
                    {
                        // Long form: the spec/decode contract is RAW private data,
                        // NOT the PKCS#8 blob getEncoded() returns (the 2-arg
                        // constructor is the 32-byte seed form and would throw
                        // "incorrect length for seed").
                        return keySpec.cast(new MLDSAPrivateKeySpec(mKey.getParameterSpec(), mKey.getPrivateData(), null));
                    }
                }
            }
            throw new InvalidKeySpecException("Invalid KeySpec: " + keySpec);
        }
        else
        {
            if (key instanceof JOMLDSAPublicKey)
            {
                if (X509EncodedKeySpec.class.isAssignableFrom(keySpec))
                {
                    return keySpec.cast(new X509EncodedKeySpec(key.getEncoded()));
                }
                else
                {
                    if (MLDSAPublicKeySpec.class.isAssignableFrom(keySpec))
                    {
                        JOMLDSAPublicKey mKey = (JOMLDSAPublicKey) key;
                        // The spec/decode contract is RAW public data, NOT the
                        // X.509 SubjectPublicKeyInfo DER getEncoded() returns.
                        return keySpec.cast(new MLDSAPublicKeySpec(mKey.getParameterSpec(), mKey.getPublicData()));
                    }
                }
                throw new InvalidKeySpecException("Invalid KeySpec: " + keySpec);
            }
        }
        throw new InvalidKeySpecException("Invalid Key: " + key);
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException
    {
        if (key instanceof MLDSAPrivateKey || key instanceof MLDSAPublicKey)
        {
            return key;
        }
        if (key == null)
        {
            throw new InvalidKeyException("Invalid Key: null");
        }
        // Foreign ML-DSA key (e.g. the JDK's NamedX509Key from a parsed
        // certificate) — re-encode and decode through us so we own the
        // EVP_PKEY. Mirrors MLKEMKeyFactorySpi / ECKeyFactorySpi.
        byte[] encoded = null;
        try
        {
            encoded = key.getEncoded();
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
        catch (RuntimeException e)
        {
            // A hostile/broken foreign key can throw from getEncoded();
            // surface the typed exception the translate contract requires.
            throw new InvalidKeyException("unable to translate key", e);
        }
        finally
        {
            // The local copy may carry private material — scrub it
            // (engineGeneratePrivate scrubbed only its own inner clone).
            Arrays.clear(encoded);
        }
    }


}
