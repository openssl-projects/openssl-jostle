/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.slhdsa;

import org.openssl.jostle.jcajce.interfaces.SLHDSAPrivateKey;
import org.openssl.jostle.jcajce.interfaces.SLHDSAPublicKey;
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

public class SLHDSAKeyFactorySpi extends KeyFactorySpi
{

    private final OSSLKeyType fixedType;

    private static final Map<SLHDSAParameterSpec, OSSLKeyType> typeMap;

    static
    {
        typeMap = Collections.unmodifiableMap(new HashMap<SLHDSAParameterSpec, OSSLKeyType>()
        {
            {
                SLHDSAParameterSpec.getParameterSpecs().forEach(it -> {
                    put(it, it.getKeyType());
                });
            }
        });

    }


    public SLHDSAKeyFactorySpi(OSSLKeyType keyType)
    {
        this.fixedType = keyType;
        assert keyType != null;
    }

    public SLHDSAKeyFactorySpi()
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

            if (SLHDSAParameterSpec.getSpecForOSSLType(pkeySpec.getType()) == null)
            {
                throw new InvalidKeySpecException("expected SLH-DSA key but got " + pkeySpec.getType());
            }

            return new JOSLHDSAPublicKey(pkeySpec);
        } else if (keySpec instanceof SLHDSAPublicKeySpec)
        {
            SLHDSAPublicKeySpec pubSpec = (SLHDSAPublicKeySpec) keySpec;

            OSSLKeyType osslKeyType = typeMap.get(pubSpec.getParameterSpec());

            if (fixedType != OSSLKeyType.NONE && osslKeyType != fixedType)
            {
                throw new InvalidKeySpecException("Invalid KeySpec: " + keySpec);
            }

            byte[] encoed = ((SLHDSAPublicKeySpec) keySpec).getPublicData();
            PKEYKeySpec pkeySpec = new PKEYKeySpec(NISelector.SpecNI.allocate(), osslKeyType);

            NISelector.SLHDSAServiceNI.handleErrors(NISelector.SLHDSAServiceNI.decode_publicKey(
                    pkeySpec.getReference(), osslKeyType.getKsType(), encoed, 0, encoed.length));
            return new JOSLHDSAPublicKey(pkeySpec);
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

            if (SLHDSAParameterSpec.getSpecForOSSLType(pkeySpec.getType()) == null)
            {
                throw new InvalidKeySpecException("expected SLH-DSA key but got " + pkeySpec.getType());
            }

            return new JOSLHDSAPrivateKey(pkeySpec);
        } else if (keySpec instanceof SLHDSAPrivateKeySpec)
        {
            SLHDSAPrivateKeySpec spec = (SLHDSAPrivateKeySpec) keySpec;
            OSSLKeyType osslKeyType = typeMap.get(spec.getParameterSpec());

            if (fixedType != OSSLKeyType.NONE && osslKeyType != fixedType)
            {
                throw new InvalidKeySpecException("Invalid KeySpec: " + keySpec);
            }

            byte[] encoded = spec.getPrivateData();

            PKEYKeySpec pkeySpec = new PKEYKeySpec(NISelector.SpecNI.allocate(), osslKeyType);
            NISelector.SLHDSAServiceNI.handleErrors(NISelector.SLHDSAServiceNI.decode_privateKey(
                    pkeySpec.getReference(), osslKeyType.getKsType(),
                    encoded, 0, encoded.length));
            return new JOSLHDSAPrivateKey(pkeySpec);
        }

        throw new InvalidKeySpecException("Invalid KeySpec: " + keySpec);
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException
    {
        if (key instanceof JOSLHDSAPrivateKey)
        {
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return keySpec.cast(new PKCS8EncodedKeySpec(key.getEncoded()));
            } else if (SLHDSAPrivateKeySpec.class.isAssignableFrom(keySpec))
            {
                JOSLHDSAPrivateKey mKey = (JOSLHDSAPrivateKey) key;
                return keySpec.cast(new SLHDSAPrivateKeySpec(mKey.getParameterSpec(), mKey.getDirectEncoding()));
            }
            throw new InvalidKeySpecException("Invalid KeySpec: " + keySpec);
        } else if (key instanceof JOSLHDSAPublicKey)
        {
            if (X509EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return keySpec.cast(new X509EncodedKeySpec(key.getEncoded()));
            } else if (SLHDSAPublicKeySpec.class.isAssignableFrom(keySpec))
            {
                JOSLHDSAPublicKey mKey = (JOSLHDSAPublicKey) key;
                return keySpec.cast(new SLHDSAPublicKeySpec(mKey.getParameterSpec(), mKey.getDirectEncoding()));
            }
            throw new InvalidKeySpecException("Invalid KeySpec: " + keySpec);
        }
        throw new InvalidKeySpecException("Invalid Key: " + key);
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException
    {
        if (key instanceof SLHDSAPrivateKey || key instanceof SLHDSAPublicKey)
        {
            return key;
        }
        throw new InvalidKeyException("Invalid Key: " + key);
    }


}
