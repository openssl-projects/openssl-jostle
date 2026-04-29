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

package org.openssl.jostle.jcajce.provider.ed;

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

public class EdKeyFactorySpi extends KeyFactorySpi
{
    private final OSSLKeyType fixedType;

    private static final Map<EdDSAParameterSpec, OSSLKeyType> typeMap = Collections.unmodifiableMap(new HashMap<EdDSAParameterSpec, OSSLKeyType>()
    {
        {
            put(EdDSAParameterSpec.ED25519, OSSLKeyType.ED25519);
            put(EdDSAParameterSpec.ED448, OSSLKeyType.ED448);
        }
    });

    public EdKeyFactorySpi(OSSLKeyType fixedType)
    {
        this.fixedType = fixedType;
        assert fixedType != null;
    }

    public EdKeyFactorySpi()
    {
        this.fixedType = OSSLKeyType.NONE;
    }


    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException
    {
        if (keySpec instanceof X509EncodedKeySpec)
        {
            byte[] encoded = ((X509EncodedKeySpec) keySpec).getEncoded();
            PKEYKeySpec pkeySpec = ASNEncoder.fromSubjectPublicKeyInfo(encoded, 0, encoded.length);
            if (fixedType != OSSLKeyType.NONE && fixedType != pkeySpec.getType())
            {
                throw new InvalidKeySpecException("expected " + fixedType.getAlgorithmName() + " but got " + pkeySpec.getType().getAlgorithmName());
            }

            switch (pkeySpec.getType())
            {
                case ED25519:
                case ED448:
                    break;
                default:
                    throw new InvalidKeySpecException("expected ED key but got " + pkeySpec.getType());
            }

            return new JOEdPublicKey(pkeySpec);
        }
        else
        {
            if (keySpec instanceof EdDSAPublicKeySpec)
            {
                EdDSAPublicKeySpec pubSpec = (EdDSAPublicKeySpec) keySpec;

                OSSLKeyType osslKeyType = typeMap.get(pubSpec.getParameterSpec());

                if (fixedType != OSSLKeyType.NONE && osslKeyType != fixedType)
                {
                    throw new InvalidKeySpecException("Invalid KeySpec: " + keySpec);
                }

                byte[] encoded = ((EdDSAPublicKeySpec) keySpec).getPublicData();
                PKEYKeySpec pkeySpec = new PKEYKeySpec(NISelector.SpecNI.allocate(), osslKeyType);

                NISelector.EDServiceNI.decode_publicKey(
                        pkeySpec.getReference(), osslKeyType.getKsType(), encoded, 0, encoded.length);
                return new JOEdPublicKey(pkeySpec);
            }
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
                throw new InvalidKeySpecException("expected " + fixedType.getAlgorithmName() + " but got " + pkeySpec.getType());
            }

            switch (pkeySpec.getType())
            {
                case ED25519:
                case ED448:
                    break;
                default:
                    throw new InvalidKeySpecException("expected ED key but got " + pkeySpec.getType());
            }

            return new JOEdPrivateKey(pkeySpec);
        }
        else
        {
            if (keySpec instanceof EdDSAPrivateKeySpec)
            {
                EdDSAPrivateKeySpec spec = (EdDSAPrivateKeySpec) keySpec;
                OSSLKeyType osslKeyType = typeMap.get(spec.getParameterSpec());

                if (fixedType != OSSLKeyType.NONE && osslKeyType != fixedType)
                {
                    throw new InvalidKeySpecException("Invalid KeySpec: " + keySpec);
                }

                byte[] encoded = spec.getPrivateData();

                PKEYKeySpec pkeySpec = new PKEYKeySpec(NISelector.SpecNI.allocate(), osslKeyType);
                NISelector.EDServiceNI.decode_privateKey(
                        pkeySpec.getReference(), osslKeyType.getKsType(),
                        encoded, 0, encoded.length);
                return new JOEdPrivateKey(pkeySpec);
            }
        }

        throw new InvalidKeySpecException("Invalid KeySpec: " + keySpec);
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException
    {
        if (key instanceof JOEdPrivateKey)
        {
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return keySpec.cast(new PKCS8EncodedKeySpec(key.getEncoded()));
            }
            else
            {
                if (EdDSAPrivateKeySpec.class.isAssignableFrom(keySpec))
                {
                    JOEdPrivateKey mKey = (JOEdPrivateKey) key;
                    return keySpec.cast(new EdDSAPrivateKeySpec(
                            mKey.getParameterSpec(),
                            mKey.getRawScalar(),
                            mKey.getRawPublic()));
                }
            }
        }
        else if (key instanceof JOEdPublicKey)
        {
            if (X509EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return keySpec.cast(new X509EncodedKeySpec(key.getEncoded()));
            }
            else
            {
                if (EdDSAPublicKeySpec.class.isAssignableFrom(keySpec))
                {
                    JOEdPublicKey mKey = (JOEdPublicKey) key;
                    return keySpec.cast(new EdDSAPublicKeySpec(
                            mKey.getParameterSpec(), mKey.getRawPublic())
                    );
                }
            }
        }

        throw new InvalidKeySpecException("Invalid KeySpec: " + keySpec);

    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException
    {
        if (key instanceof JOEdPublicKey || key instanceof JOEdPrivateKey)
        {
            return key;
        }
        throw new InvalidKeyException("Invalid Key: " + key);
    }

    public static class ED25519 extends EdKeyFactorySpi
    {
        public ED25519()
        {
            super(OSSLKeyType.ED25519);
        }
    }

    public static class ED448 extends EdKeyFactorySpi
    {
        public ED448()
        {
            super(OSSLKeyType.ED448);
        }
    }

}
