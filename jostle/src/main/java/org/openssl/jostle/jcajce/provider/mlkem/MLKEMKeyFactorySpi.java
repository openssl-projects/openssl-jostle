/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.mlkem;

import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.jcajce.interfaces.MLKEMPrivateKey;
import org.openssl.jostle.jcajce.interfaces.MLKEMPublicKey;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.*;
import org.openssl.jostle.rand.DefaultRandSource;
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

public class MLKEMKeyFactorySpi extends KeyFactorySpi
{

    private final OSSLKeyType fixedType;

    private static final Map<MLKEMParameterSpec, OSSLKeyType> typeMap = Collections.unmodifiableMap(new HashMap<MLKEMParameterSpec, OSSLKeyType>()
    {
        {
            put(MLKEMParameterSpec.ml_kem_512, OSSLKeyType.ML_KEM_512);
            put(MLKEMParameterSpec.ml_kem_768, OSSLKeyType.ML_KEM_768);
            put(MLKEMParameterSpec.ml_kem_1024, OSSLKeyType.ML_KEM_1024);
        }
    });

    public MLKEMKeyFactorySpi(OSSLKeyType keyType)
    {
        this.fixedType = keyType;
        assert keyType != null;
    }

    public MLKEMKeyFactorySpi()
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
                    case ML_KEM_512:
                    case ML_KEM_768:
                    case ML_KEM_1024:
                        break;
                    default:
                        throw new InvalidKeySpecException("expected ML-KEM key but got " + pkeySpec.getType().getAlgorithmName());
                }

                return new JOMLKEMPublicKey(pkeySpec);
            }
            catch (RuntimeException e)
            {
                // Malformed encoding surfaces from the decoder as OpenSSLException
                // / IllegalArgumentException; the KeyFactory contract requires
                // InvalidKeySpecException (RSAKeyFactorySpi precedent).
                throw new InvalidKeySpecException("unable to decode ML-KEM public key", e);
            }
        }
        else
        {
            if (keySpec instanceof MLKEMPublicKeySpec)
            {
                MLKEMPublicKeySpec pubSpec = (MLKEMPublicKeySpec) keySpec;

                OSSLKeyType osslKeyType = typeMap.get(pubSpec.getParameterSpec());
                if (osslKeyType == null)
                {
                    // A null / unrecognised parameter set would otherwise NPE at
                    // osslKeyType.getKsType(); surface the typed KeyFactory error.
                    throw new InvalidKeySpecException("unknown or missing ML-KEM parameter set in key spec");
                }

                if (fixedType != OSSLKeyType.NONE && osslKeyType != fixedType)
                {
                    throw new InvalidKeySpecException("Invalid KeySpec: " + keySpec);
                }

                byte[] encoded = pubSpec.getPublicData();
                try
                {
                    PKEYKeySpec pkeySpec = new PKEYKeySpec(NISelector.SpecNI.allocate(), osslKeyType);

                    NISelector.MLKEMServiceNI.decode_publicKey(
                            pkeySpec.getReference(), osslKeyType.getKsType(), encoded, 0, encoded.length,
                            DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom()));
                    return new JOMLKEMPublicKey(pkeySpec);
                }
                catch (RuntimeException e)
                {
                    // The native decoder surfaces a malformed encoding as
                    // OpenSSLException / IllegalArgumentException; the KeyFactory
                    // contract requires InvalidKeySpecException (the X.509 path
                    // above already wraps).
                    throw new InvalidKeySpecException("unable to decode ML-KEM public key", e);
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
            // getEncoded() returns a fresh copy carrying the private key
            // material — scrub it (and any rewritten copy the canonicalizer
            // allocated) once the native key is built (Ed/RSA precedent).
            byte[] pkcs8 = ((PKCS8EncodedKeySpec) keySpec).getEncoded();
            byte[] encoded = KeyInfoCanonicalizer.privateKeyInfo(pkcs8);

            try
            {
                PKEYKeySpec pkeySpec = ASN1Encoder.fromPrivateKeyInfo(encoded, 0, encoded.length);

                if (fixedType != OSSLKeyType.NONE && fixedType != pkeySpec.getType())
                {
                    throw new InvalidKeySpecException("expected " + fixedType + " but got " + pkeySpec.getType().getAlgorithmName());
                }

                switch (pkeySpec.getType())
                {
                    case ML_KEM_512:
                    case ML_KEM_768:
                    case ML_KEM_1024:
                        break;
                    default:
                        throw new InvalidKeySpecException("expected ML-KEM key but got " + pkeySpec.getType().getAlgorithmName());
                }

                return new JOMLKEMPrivateKey(pkeySpec);
            }
            catch (RuntimeException e)
            {
                throw new InvalidKeySpecException("unable to decode ML-KEM private key", e);
            }
            finally
            {
                Arrays.clear(pkcs8);
                if (encoded != null && encoded != pkcs8)
                {
                    Arrays.clear(encoded);
                }
            }
        }
        else
        {
            if (keySpec instanceof MLKEMPrivateKeySpec)
            {
                MLKEMPrivateKeySpec spec = (MLKEMPrivateKeySpec) keySpec;
                OSSLKeyType osslKeyType = typeMap.get(spec.getParameterSpec());
                if (osslKeyType == null)
                {
                    // A null / unrecognised parameter set would otherwise NPE at
                    // osslKeyType.getKsType(); surface the typed KeyFactory error.
                    throw new InvalidKeySpecException("unknown or missing ML-KEM parameter set in key spec");
                }

                if (fixedType != OSSLKeyType.NONE && osslKeyType != fixedType)
                {
                    throw new InvalidKeySpecException("Invalid KeySpec: " + keySpec);
                }

                // Holds the seed or long-form private material — secret; scrubbed
                // in the finally (the KeySpec getters returned fresh clones).
                byte[] material = null;

                // Both the seed keygen and the long-form decode run a native
                // pairwise-consistency test that encapsulates, consuming entropy
                // at the variant's security level (ML-KEM-768/1024 need 192/256
                // bits). Resolve a strength-appropriate DRBG so the C-side RAND
                // gate is satisfied — the default SecureRandom is a 128-bit DRBG
                // on Windows JDK 9+ and would otherwise fail the PCT (GH #34).
                int strengthBits = spec.getParameterSpec().getRequiredStrengthBits();
                try
                {
                    PKEYKeySpec pkeySpec;
                    if (spec.isSeed())
                    {
                        // Seed-only form: derive the keypair from the 64-byte
                        // seed via OSSL_PKEY_PARAM_ML_KEM_SEED keygen rather
                        // than via decode_privateKey (which only accepts the
                        // long form).
                        material = spec.getSeed();
                        long ref = NISelector.MLKEMServiceNI.generateKeyPair(
                                osslKeyType.getKsType(),
                                material, material.length,
                                DefaultRandSource.replaceWith(null, null, strengthBits));
                        pkeySpec = new PKEYKeySpec(ref, osslKeyType);
                    }
                    else
                    {
                        material = spec.getPrivateData();
                        pkeySpec = new PKEYKeySpec(NISelector.SpecNI.allocate(), osslKeyType);
                        NISelector.MLKEMServiceNI.decode_privateKey(
                                pkeySpec.getReference(), osslKeyType.getKsType(),
                                material, 0, material.length,
                                DefaultRandSource.replaceWith(null, null, strengthBits));
                    }
                    return new JOMLKEMPrivateKey(pkeySpec, spec.isSeed());
                }
                catch (RuntimeException e)
                {
                    // Malformed key material surfaces from the native decoder /
                    // seed keygen as OpenSSLException / IllegalArgumentException;
                    // the KeyFactory contract requires InvalidKeySpecException
                    // (the PKCS#8 path above already wraps).
                    throw new InvalidKeySpecException("unable to decode ML-KEM private key", e);
                }
                finally
                {
                    Arrays.clear(material);
                }
            }
        }

        throw new InvalidKeySpecException("Invalid KeySpec: " + keySpec);
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException
    {
        if (key instanceof JOMLKEMPrivateKey)
        {
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return keySpec.cast(new PKCS8EncodedKeySpec(key.getEncoded()));
            }
            else
            {
                if (MLKEMPrivateKeySpec.class.isAssignableFrom(keySpec))
                {
                    JOMLKEMPrivateKey mKey = (JOMLKEMPrivateKey) key;
                    if (mKey.seedOnly)
                    {
                        byte[] seed = mKey.getSeed();
                        try
                        {
                            return keySpec.cast(new MLKEMPrivateKeySpec(mKey.getParameterSpec(), seed));
                        }
                        finally
                        {
                            // MLKEMPrivateKeySpec clones its input; scrub the
                            // local copy of the secret seed.
                            Arrays.clear(seed);
                        }
                    }
                    else
                    {
                        // Long-form spec: feed the RAW private data through the
                        // (params, privateData, publicData) constructor — the
                        // 2-arg constructor is the seed form and requires a
                        // 64-byte seed, so passing getEncoded() (a PKCS#8 blob)
                        // there always threw.
                        byte[] privateData = mKey.getPrivateData();
                        try
                        {
                            return keySpec.cast(new MLKEMPrivateKeySpec(mKey.getParameterSpec(), privateData, null));
                        }
                        finally
                        {
                            Arrays.clear(privateData);
                        }
                    }
                }
            }
            throw new InvalidKeySpecException("Invalid KeySpec: " + keySpec);
        }
        else
        {
            if (key instanceof JOMLKEMPublicKey)
            {
                if (X509EncodedKeySpec.class.isAssignableFrom(keySpec))
                {
                    return keySpec.cast(new X509EncodedKeySpec(key.getEncoded()));
                }
                else
                {
                    if (MLKEMPublicKeySpec.class.isAssignableFrom(keySpec))
                    {
                        JOMLKEMPublicKey mKey = (JOMLKEMPublicKey) key;
                        // Feed the RAW public data — getEncoded() is the X.509
                        // SubjectPublicKeyInfo blob, but MLKEMPublicKeySpec
                        // expects the long-form public key.
                        return keySpec.cast(new MLKEMPublicKeySpec(mKey.getParameterSpec(), mKey.getPublicData()));
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
        if (key instanceof MLKEMPrivateKey || key instanceof MLKEMPublicKey)
        {
            return key;
        }
        if (key == null)
        {
            throw new InvalidKeyException("Invalid Key: null");
        }
        // Foreign ML-KEM key (e.g. the JDK's NamedX509Key from a parsed
        // certificate) — re-encode and decode through us so we own the
        // EVP_PKEY. Mirrors ECKeyFactorySpi / XECKeyFactorySpi.
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
