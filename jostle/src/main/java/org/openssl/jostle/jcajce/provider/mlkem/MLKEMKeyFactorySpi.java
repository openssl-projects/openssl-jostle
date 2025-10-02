/*
 *  Copyright 2005-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://www.openssl.org/source/license.html
 *
 */

package org.openssl.jostle.jcajce.provider.mlkem;

import org.openssl.jostle.jcajce.interfaces.MLKEMPrivateKey;
import org.openssl.jostle.jcajce.interfaces.MLKEMPublicKey;
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

public class MLKEMKeyFactorySpi extends KeyFactorySpi
{

    private final OSSLKeyType fixedType;

    private static final Map<MLKEMParameterSpec, OSSLKeyType> typeMap = Collections.unmodifiableMap(new HashMap<MLKEMParameterSpec, OSSLKeyType>()
    {
        {
            put(MLKEMParameterSpec.ml_kem_512, OSSLKeyType.ML_KEM_512);
            put(MLKEMParameterSpec.ml_kem_768, OSSLKeyType.ML_KEM_512);
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
            byte[] encoded = ((X509EncodedKeySpec) keySpec).getEncoded();

            PKEYKeySpec pkeySpec = ASNEncoder.fromPublicKeyInfo(encoded, 0, encoded.length);

            if (fixedType != OSSLKeyType.NONE && fixedType != pkeySpec.getType())
            {
                throw new InvalidKeySpecException("expected " + fixedType + " but got " + pkeySpec.getType());
            }

            switch (pkeySpec.getType())
            {
                case ML_KEM_512:
                case ML_KEM_768:
                case ML_KEM_1024:
                    break;
                default:
                    throw new InvalidKeySpecException("expected ML-KEM key but got " + pkeySpec.getType());
            }

            return new JOMLKEMPublicKey(pkeySpec);
        } else if (keySpec instanceof MLKEMPublicKeySpec)
        {
            MLKEMPublicKeySpec pubSpec = (MLKEMPublicKeySpec) keySpec;

            OSSLKeyType osslKeyType = typeMap.get(pubSpec.getParameterSpec());

            if (fixedType != OSSLKeyType.NONE && osslKeyType != fixedType)
            {
                throw new InvalidKeySpecException("Invalid KeySpec: " + keySpec);
            }

            byte[] encoded = ((MLKEMPublicKeySpec) keySpec).getPublicData();
            PKEYKeySpec pkeySpec = new PKEYKeySpec(NISelector.SpecNI.allocate(), osslKeyType);

            NISelector.MLKEMServiceNI.handleErrors(NISelector.MLKEMServiceNI.decode_publicKey(
                    pkeySpec.getReference(), osslKeyType.getKsType(), encoded, 0, encoded.length));
            return new JOMLKEMPublicKey(pkeySpec);
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
                case ML_KEM_512:
                case ML_KEM_768:
                case ML_KEM_1024:
                    break;
                default:
                    throw new InvalidKeySpecException("expected ML-KEM key but got " + pkeySpec.getType());
            }

            return new JOMLKEMPrivateKey(pkeySpec);
        } else if (keySpec instanceof MLKEMPrivateKeySpec)
        {
            MLKEMPrivateKeySpec spec = (MLKEMPrivateKeySpec) keySpec;
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
            NISelector.MLKEMServiceNI.handleErrors(NISelector.MLKEMServiceNI.decode_privateKey(
                    pkeySpec.getReference(), osslKeyType.getKsType(),
                    encoded, 0, encoded.length));
            return new JOMLKEMPrivateKey(pkeySpec, spec.isSeed());
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
            } else if (MLKEMPrivateKeySpec.class.isAssignableFrom(keySpec))
            {
                JOMLKEMPrivateKey mKey = (JOMLKEMPrivateKey) key;
                if (mKey.seedOnly)
                {
                    return keySpec.cast(new MLKEMPrivateKeySpec(mKey.getParameterSpec(), mKey.getSeed()));
                } else
                {
                    return keySpec.cast(new MLKEMPrivateKeySpec(mKey.getParameterSpec(), mKey.getEncoded()));
                }
            }
            throw new InvalidKeySpecException("Invalid KeySpec: " + keySpec);
        } else if (key instanceof JOMLKEMPublicKey)
        {
            if (X509EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return keySpec.cast(new X509EncodedKeySpec(key.getEncoded()));
            } else if (MLKEMPublicKeySpec.class.isAssignableFrom(keySpec))
            {
                JOMLKEMPublicKey mKey = (JOMLKEMPublicKey) key;
                return keySpec.cast(new MLKEMPublicKeySpec(mKey.getParameterSpec(), mKey.getEncoded()));
            }
            throw new InvalidKeySpecException("Invalid KeySpec: " + keySpec);
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
        throw new InvalidKeyException("Invalid Key: " + key);
    }

}
