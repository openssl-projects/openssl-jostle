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

import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.MLDSAParameterSpec;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

public class MLDSAKeyPairGeneratorImpl extends KeyPairGenerator
{

    private OSSLKeyType keyType;

    private static final Map<Object, OSSLKeyType> paramToTypeMap = new HashMap<Object, OSSLKeyType>()
    {
        {
            put("ML-DSA", OSSLKeyType.NONE);

            put("ML-DSA-44", OSSLKeyType.ML_DSA_44);
            put("ML-DSA-65", OSSLKeyType.ML_DSA_65);
            put("ML-DSA-87", OSSLKeyType.ML_DSA_87);

            put(MLDSAParameterSpec.ml_dsa_44, OSSLKeyType.ML_DSA_44);
            put(MLDSAParameterSpec.ml_dsa_65, OSSLKeyType.ML_DSA_65);
            put(MLDSAParameterSpec.ml_dsa_87, OSSLKeyType.ML_DSA_87);
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
    public MLDSAKeyPairGeneratorImpl(Object algorithm)
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
        if (!(params instanceof MLDSAParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("only MLDSAParameterSpec is supported");
        }

        MLDSAParameterSpec spec = (MLDSAParameterSpec) params;

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
            throw new InvalidAlgorithmParameterException("expected " + keyType + " but was supplied " + newType);
        }
    }

    @Override
    public KeyPair generateKeyPair()
    {
        long res = NISelector.MLDSAServiceNI.generateKeyPair(keyType.getKsType());
        if (res < 0)
        {
            NISelector.MLDSAServiceNI.handleErrors(res);
        } else if (res == 0)
        {
            throw new IllegalStateException("unexpected null pointer from native layer");
        }

        PKEYKeySpec spec = new PKEYKeySpec(res, keyType);
        return new KeyPair(new JOMLDSAPublicKey(spec), new JOMLDSAPrivateKey(spec));
    }

    public static class MLDSA44 extends MLDSAKeyPairGeneratorImpl
    {

        public MLDSA44()
        {
            super(MLDSAParameterSpec.ml_dsa_44);
        }
    }

    public static class MLDSA65 extends MLDSAKeyPairGeneratorImpl
    {

        public MLDSA65()
        {
            super(MLDSAParameterSpec.ml_dsa_65);
        }
    }

    public static class MLDSA87 extends MLDSAKeyPairGeneratorImpl
    {

        public MLDSA87()
        {
            super(MLDSAParameterSpec.ml_dsa_87);
        }
    }

}
