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

import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.EdDSAParameterSpec;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.rand.DefaultRandSource;
import org.openssl.jostle.rand.RandSource;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

public class EdDSAKeyPairGenerator extends KeyPairGenerator
{
    private static final EDServiceNI edServiceNI = NISelector.EDServiceNI;
    private OSSLKeyType keyType = OSSLKeyType.NONE;
    private RandSource random = DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom());


    private static final Map<Object, OSSLKeyType> paramToTypeMap = new HashMap<Object, OSSLKeyType>()
    {
        {
            put("EDDSA", OSSLKeyType.NONE);
            put("ED25519", OSSLKeyType.ED25519);
            put("ED448", OSSLKeyType.ED448);
            put(EdDSAParameterSpec.ED25519, OSSLKeyType.ED25519);
            put(EdDSAParameterSpec.ED448, OSSLKeyType.ED448);
        }
    };

    public EdDSAKeyPairGenerator()
    {
        this(null);
    }

    public EdDSAKeyPairGenerator(Object algorithm)
    {
        super(algorithm.toString());
        keyType = paramToTypeMap.get(algorithm);

        if (keyType == null)
        {
            throw new IllegalArgumentException("unknown algorithm: " + algorithm);
        }
    }

    @Override
    public void initialize(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException
    {
        initialize(params, null);
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException
    {
        this.random = DefaultRandSource.replaceWith(this.random, random);

        if (!(params instanceof EdDSAParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("expected instance of EdDSAParameterSpec");
        }

        OSSLKeyType newType = paramToTypeMap.get(((EdDSAParameterSpec) params).getName());

        if (newType == null)
        {
            throw new InvalidAlgorithmParameterException("unknown algorithm: " + ((EdDSAParameterSpec) params).getName());
        }

        if (keyType == OSSLKeyType.NONE)
        {
            keyType = newType;
        }

        if (keyType != newType)
        {
            throw new InvalidAlgorithmParameterException("expected " + keyType + " but was supplied " + newType);
        }

    }

    @Override
    public KeyPair generateKeyPair()
    {
        long res = edServiceNI.generateKeyPair(keyType.getKsType(), random);

        if (res == 0)
        {
            throw new IllegalStateException("unexpected null pointer from native layer");
        }

        PKEYKeySpec spec = new PKEYKeySpec(res, keyType);
        return new KeyPair(new JOEdPublicKey(spec), new JOEdPrivateKey(spec));
    }


    public static class ED25519 extends EdDSAKeyPairGenerator
    {
        public ED25519()
        {
            super(EdDSAParameterSpec.ED25519);
        }
    }

    public static class ED448 extends EdDSAKeyPairGenerator
    {
        public ED448()
        {
            super(EdDSAParameterSpec.ED448);
        }
    }
}
