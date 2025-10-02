/*
 *  Copyright 2005-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://www.openssl.org/source/license.html
 *
 */

package org.openssl.jostle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.*;

public class MLKEMParameterSpec implements AlgorithmParameterSpec
{

    public static final MLKEMParameterSpec ml_kem_512 = new MLKEMParameterSpec("ML-KEM-512", OSSLKeyType.ML_KEM_512);
    public static final MLKEMParameterSpec ml_kem_768 = new MLKEMParameterSpec("ML-KEM-768", OSSLKeyType.ML_KEM_768);
    public static final MLKEMParameterSpec ml_kem_1024 = new MLKEMParameterSpec("ML-KEM-1024", OSSLKeyType.ML_KEM_1024);

    private static final Map parameters = new HashMap();

    private static final Set<MLKEMParameterSpec> parameterSpecs = Collections.unmodifiableSet(new HashSet<MLKEMParameterSpec>()
    {
        {
            add(ml_kem_512);
            add(ml_kem_768);
            add(ml_kem_1024);
        }
    });

    private static Map<OSSLKeyType, MLKEMParameterSpec> typeToSpec = Collections.unmodifiableMap(new HashMap<OSSLKeyType, MLKEMParameterSpec>()
    {
        {
            parameterSpecs.forEach(spec -> put(spec.getKeyType(), spec));
        }
    });


    static
    {
        parameters.put("ml-kem-512", MLKEMParameterSpec.ml_kem_512);
        parameters.put("ml-kem-768", MLKEMParameterSpec.ml_kem_768);
        parameters.put("ml-kem-1024", MLKEMParameterSpec.ml_kem_1024);

        parameters.put("kyber512", MLKEMParameterSpec.ml_kem_512);
        parameters.put("kyber768", MLKEMParameterSpec.ml_kem_768);
        parameters.put("kyber1024", MLKEMParameterSpec.ml_kem_1024);

        parameters.put(OSSLKeyType.ML_KEM_512, ml_kem_512);
        parameters.put(OSSLKeyType.ML_KEM_768, ml_kem_768);
        parameters.put(OSSLKeyType.ML_KEM_1024, ml_kem_1024);


    }

    private final String name;
    private final OSSLKeyType keyType;

    private MLKEMParameterSpec(String name, OSSLKeyType keyType)
    {
        this.name = name;
        this.keyType = keyType;
    }

    public String getName()
    {
        return name;
    }

    public OSSLKeyType getKeyType()
    {
        return keyType;
    }

    public static MLKEMParameterSpec fromName(String name)
    {
        if (name == null)
        {
            throw new IllegalArgumentException("name cannot be null");
        }
        MLKEMParameterSpec spec = (MLKEMParameterSpec) parameters.get(name);
        if (spec == null)
        {
            throw new IllegalArgumentException("Unknown MLKEM parameter spec: " + name);
        }
        return spec;
    }

    public static Set<MLKEMParameterSpec> getParameterSpecs()
    {
        return parameterSpecs;
    }


    public static MLKEMParameterSpec getSpecForOSSLType(OSSLKeyType keyType)
    {
        return typeToSpec.get(keyType);
    }

    @Override
    public boolean equals(Object o)
    {
        if (o == null || getClass() != o.getClass()) return false;
        MLKEMParameterSpec that = (MLKEMParameterSpec) o;
        return Objects.equals(name, that.name);
    }

    @Override
    public int hashCode()
    {
        return Objects.hashCode(name);
    }
}
