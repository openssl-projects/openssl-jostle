/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.spec;

import org.openssl.jostle.util.Strings;

import java.security.spec.AlgorithmParameterSpec;
import java.util.*;

public class MLKEMParameterSpec implements AlgorithmParameterSpec
{

    public static final MLKEMParameterSpec ml_kem_512 = new MLKEMParameterSpec("ML-KEM-512", OSSLKeyType.ML_KEM_512);
    public static final MLKEMParameterSpec ml_kem_768 = new MLKEMParameterSpec("ML-KEM-768", OSSLKeyType.ML_KEM_768);
    public static final MLKEMParameterSpec ml_kem_1024 = new MLKEMParameterSpec("ML-KEM-1024", OSSLKeyType.ML_KEM_1024);

    private static final Map<String, MLKEMParameterSpec> parameters = new HashMap<>();

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

        // Short aliases (no hyphens), matching the "MLKEM512" alias form used by
        // OSSLKeyType. Looked up case-insensitively via fromName's toLowerCase.
        parameters.put("mlkem512", MLKEMParameterSpec.ml_kem_512);
        parameters.put("mlkem768", MLKEMParameterSpec.ml_kem_768);
        parameters.put("mlkem1024", MLKEMParameterSpec.ml_kem_1024);
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

    /**
     * NIST security strength (in bits) per FIPS 203 Table 2:
     * <ul>
     *   <li>ML-KEM-512  — security category 1, 128-bit strength</li>
     *   <li>ML-KEM-768  — security category 3, 192-bit strength</li>
     *   <li>ML-KEM-1024 — security category 5, 256-bit strength</li>
     * </ul>
     *
     * <p>This drives the JCE SPI's default-SecureRandom selection — when
     * a caller calls {@code init(spec)} without supplying a
     * {@code SecureRandom}, the SPI uses this value to instantiate a
     * DRBG whose reported strength meets OpenSSL's RAND-strength gate.
     * Using a 128-bit-strength DRBG with ML-KEM-768/1024 produces an
     * {@link org.openssl.jostle.jcajce.provider.OpenSSLException} on
     * the encap/keygen path (see GH issue #34).
     */
    public int getRequiredStrengthBits()
    {
        if (keyType == OSSLKeyType.ML_KEM_512)
        {
            return 128;
        }
        if (keyType == OSSLKeyType.ML_KEM_768)
        {
            return 192;
        }
        if (keyType == OSSLKeyType.ML_KEM_1024)
        {
            return 256;
        }
        // Unknown type — be conservative and ask for the strongest.
        return 256;
    }

    public static MLKEMParameterSpec fromName(String name)
    {
        if (name == null)
        {
            throw new NullPointerException("name cannot be null");
        }

        MLKEMParameterSpec parameterSpec = (MLKEMParameterSpec)parameters.get(Strings.toLowerCase(name));

        if (parameterSpec == null)
        {
            throw new IllegalArgumentException("unknown parameter name: " + name);
        }

        return parameterSpec;
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
        if (o == null || getClass() != o.getClass())
        {
            return false;
        }
        MLKEMParameterSpec that = (MLKEMParameterSpec) o;
        return Objects.equals(name, that.name);
    }

    @Override
    public int hashCode()
    {
        return Objects.hashCode(name);
    }
}
