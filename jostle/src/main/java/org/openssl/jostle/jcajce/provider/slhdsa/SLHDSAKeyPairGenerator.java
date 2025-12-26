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

import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.jcajce.spec.SLHDSAParameterSpec;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import static org.openssl.jostle.jcajce.spec.OSSLKeyType.NONE;

public class SLHDSAKeyPairGenerator extends KeyPairGenerator
{

    private final OSSLKeyType forcedType;
    private OSSLKeyType keyType;

    private static final Map<Object, OSSLKeyType> paramToTypeMap = new HashMap<Object, OSSLKeyType>()
    {
        {
            put("SLH-DSA", NONE);
            SLHDSAParameterSpec.getParameterNames().forEach((key) -> {
                SLHDSAParameterSpec value = SLHDSAParameterSpec.fromName(key);
                put(value.getName(), ((SLHDSAParameterSpec) value).getKeyType());
                put(value,((SLHDSAParameterSpec) value).getKeyType());
            });
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
    public SLHDSAKeyPairGenerator(Object algorithm)
    {
        super(algorithm.toString());
        forcedType = paramToTypeMap.get(algorithm);

        if (forcedType == null)
        {
            throw new IllegalArgumentException("unknown algorithm: " + algorithm);
        }

        if (forcedType != OSSLKeyType.NONE)
        {
            keyType = forcedType;
        }
    }

    @Override
    public void initialize(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException
    {
        if (!(params instanceof SLHDSAParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("only SLHDSAParameterSpec is supported");
        }

        SLHDSAParameterSpec spec = (SLHDSAParameterSpec) params;

        OSSLKeyType newType = paramToTypeMap.get(spec.getName());

        if (newType == null)
        {
            throw new InvalidAlgorithmParameterException("unknown algorithm: " + spec.getName());
        }

        if (forcedType == OSSLKeyType.NONE)
        {
            keyType = newType;
        } else
        {
            if (forcedType != newType)
            {
                throw new InvalidAlgorithmParameterException(
                        "expected " + SLHDSAParameterSpec.getSpecForOSSLType(forcedType).getName() + " but was supplied " + SLHDSAParameterSpec.getSpecForOSSLType(newType).getName());
            }
            keyType = newType;
        }
    }

    public KeyPair generateKeyPair()
    {
        long res = NISelector.SLHDSAServiceNI.generateKeyPair(keyType.getKsType());
        if (res < 0)
        {
            NISelector.SLHDSAServiceNI.handleErrors(res);
        } else if (res == 0)
        {
            throw new IllegalStateException("unexpected null pointer from native layer");
        }

        PKEYKeySpec spec = new PKEYKeySpec(res, keyType);
        return new KeyPair(new JOSLHDSAPublicKey(spec), new JOSLHDSAPrivateKey(spec));
    }


}
