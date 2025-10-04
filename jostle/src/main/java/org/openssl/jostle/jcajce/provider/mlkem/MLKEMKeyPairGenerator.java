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

import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.mlkem.JOMLKEMPrivateKey;
import org.openssl.jostle.jcajce.provider.mlkem.JOMLKEMPublicKey;
import org.openssl.jostle.jcajce.spec.MLKEMParameterSpec;
import org.openssl.jostle.jcajce.spec.MLKEMPrivateKeySpec;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

public class MLKEMKeyPairGenerator extends KeyPairGenerator
{

    private OSSLKeyType keyType;

    private static final Map<Object, OSSLKeyType> paramToTypeMap = new HashMap<Object, OSSLKeyType>()
    {
        {
            put("ML-KEM", OSSLKeyType.NONE);

            put("ML-KEM-512", OSSLKeyType.ML_KEM_512);
            put("ML-KEM-768", OSSLKeyType.ML_KEM_768);
            put("ML-KEM-1024", OSSLKeyType.ML_KEM_1024);

            put(MLKEMParameterSpec.ml_kem_512, OSSLKeyType.ML_KEM_512);
            put(MLKEMParameterSpec.ml_kem_768, OSSLKeyType.ML_KEM_768);
            put(MLKEMParameterSpec.ml_kem_1024, OSSLKeyType.ML_KEM_1024);
        }
    };


    /**
     * Creates a {@code KeyPairGenerator} object for the specified algorithm.
     *
     * @param algorithm the standard string name of the algorithm.
     *                  See the KeyPairGenerator section in the <a href=
     *                  "{@docRoot}/../specs/security/standard-names.html#keypairgenerator-algorithms">
     *                  Java Security Standard Algorithm Names Specification</a>
     *                  for information about standard algorithm names.
     */
    public MLKEMKeyPairGenerator(Object algorithm)
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
        if (!(params instanceof MLKEMParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("only MLKEMParameterSpec is supported got " + params.getClass().getName());
        }

        MLKEMParameterSpec spec = (MLKEMParameterSpec) params;

        OSSLKeyType newType = paramToTypeMap.get(spec.getName());

        if (newType == null)
        {
            throw new InvalidAlgorithmParameterException("unknown algorithm: " + spec.getName());
        }

        if (keyType == OSSLKeyType.NONE)
        {
            keyType = newType;
        }

        if (keyType != newType)
        {
            throw new InvalidAlgorithmParameterException("expected " +  MLKEMParameterSpec.getSpecForOSSLType(keyType).getName() + " but was supplied " + MLKEMParameterSpec.getSpecForOSSLType(newType).getName());
        }

        keyType = newType;

    }

    @Override
    public KeyPair generateKeyPair()
    {
        long res = NISelector.MLKEMServiceNI.generateKeyPair(keyType.getKsType());
        if (res < 0)
        {
            NISelector.MLKEMServiceNI.handleErrors(res);
        } else if (res == 0)
        {
            throw new IllegalStateException("unexpected null pointer from native layer");
        }

        PKEYKeySpec spec = new PKEYKeySpec(res, keyType);
        return new KeyPair(new JOMLKEMPublicKey(spec), new JOMLKEMPrivateKey(spec));
    }



}
