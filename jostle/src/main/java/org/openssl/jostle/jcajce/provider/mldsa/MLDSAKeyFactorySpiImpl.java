/*
 *  Copyright 2005-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://www.openssl.org/source/license.html
 *
 */

package org.openssl.jostle.jcajce.provider.mldsa;

import org.openssl.jostle.jcajce.interfaces.MLDSAPrivateKey;
import org.openssl.jostle.jcajce.interfaces.MLDSAPublicKey;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.*;
import org.openssl.jostle.util.asn1.ASNEncoder;

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
            byte[] encoded = ((X509EncodedKeySpec) keySpec).getEncoded();

            PKEYKeySpec pkeySpec = ASNEncoder.fromPublicKeyInfo(encoded, 0, encoded.length);

            if (fixedType != OSSLKeyType.NONE && fixedType != pkeySpec.getType())
            {
                throw new InvalidKeySpecException("expected " + fixedType + " but got " + pkeySpec.getType());
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
        } else if (keySpec instanceof MLDSAPublicKeySpec)
        {
            MLDSAPublicKeySpec pubSpec = (MLDSAPublicKeySpec) keySpec;

            OSSLKeyType osslKeyType = typeMap.get(pubSpec.getParameterSpec());

            if (fixedType != OSSLKeyType.NONE && osslKeyType != fixedType)
            {
                throw new InvalidKeySpecException("Invalid KeySpec: " + keySpec);
            }

            byte[] encoed = ((MLDSAPublicKeySpec) keySpec).getPublicData();
            PKEYKeySpec pkeySpec = new PKEYKeySpec(NISelector.SpecNI.allocate(), osslKeyType);

            NISelector.MLDSAServiceNI.handleErrors(NISelector.MLDSAServiceNI.decode_publicKey(
                    pkeySpec.getReference(), osslKeyType.getKsType(), encoed, 0, encoed.length));
            return new JOMLDSAPublicKey(pkeySpec);
        }
        throw new InvalidKeySpecException("Invalid KeySpec: " + keySpec);
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException
    {
        if (keySpec instanceof PKCS8EncodedKeySpec)
        {

            byte[] encoded = ((PKCS8EncodedKeySpec) keySpec).getEncoded();

            PKEYKeySpec pkeySpec = ASNEncoder.fromPrivateKeyInfo(encoded, 0, encoded.length);

            if (fixedType != OSSLKeyType.NONE && fixedType != pkeySpec.getType())
            {
                throw new InvalidKeySpecException("expected " + fixedType + " but got " + pkeySpec.getType());
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
        } else if (keySpec instanceof MLDSAPrivateKeySpec)
        {
            MLDSAPrivateKeySpec spec = (MLDSAPrivateKeySpec) keySpec;
            OSSLKeyType osslKeyType = typeMap.get(spec.getParameterSpec());

            if (fixedType != OSSLKeyType.NONE && osslKeyType != fixedType)
            {
                throw new InvalidKeySpecException("Invalid KeySpec: " + keySpec);
            }

            byte[] encoded;
            if (spec.isSeed())
            {
                encoded = spec.getSeed();
            } else
            {
                encoded = spec.getPrivateData();
            }
            PKEYKeySpec pkeySpec = new PKEYKeySpec(NISelector.SpecNI.allocate(), osslKeyType);
            NISelector.MLDSAServiceNI.handleErrors(NISelector.MLDSAServiceNI.decode_privateKey(
                    pkeySpec.getReference(), osslKeyType.getKsType(),
                    encoded, 0, encoded.length));
            return new JOMLDSAPrivateKey(pkeySpec, spec.isSeed());
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
            } else if (MLDSAPrivateKeySpec.class.isAssignableFrom(keySpec))
            {
                JOMLDSAPrivateKey mKey = (JOMLDSAPrivateKey) key;
                if (mKey.seedOnly)
                {
                    return keySpec.cast(new MLDSAPrivateKeySpec(mKey.getParameterSpec(), mKey.getSeed()));
                } else
                {
                    return keySpec.cast(new MLDSAPrivateKeySpec(mKey.getParameterSpec(), mKey.getEncoded()));
                }
            }
            throw new InvalidKeySpecException("Invalid KeySpec: " + keySpec);
        } else if (key instanceof JOMLDSAPublicKey)
        {
            if (X509EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return keySpec.cast(new X509EncodedKeySpec(key.getEncoded()));
            } else if (MLDSAPublicKeySpec.class.isAssignableFrom(keySpec))
            {
                JOMLDSAPublicKey mKey = (JOMLDSAPublicKey) key;
                return keySpec.cast(new MLDSAPublicKeySpec(mKey.getParameterSpec(), mKey.getEncoded()));
            }
            throw new InvalidKeySpecException("Invalid KeySpec: " + keySpec);
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
        throw new InvalidKeyException("Invalid Key: " + key);
    }






}
