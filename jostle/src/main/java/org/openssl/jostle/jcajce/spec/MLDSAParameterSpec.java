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
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * AlgorithmSpec for ML-DSA
 */
public class MLDSAParameterSpec
        implements AlgorithmParameterSpec
{
    public static final MLDSAParameterSpec ml_dsa_44 = new MLDSAParameterSpec("ML-DSA-44", false);
    public static final MLDSAParameterSpec ml_dsa_65 = new MLDSAParameterSpec("ML-DSA-65", false);
    public static final MLDSAParameterSpec ml_dsa_87 = new MLDSAParameterSpec("ML-DSA-87", false);


    private static final Map<String, MLDSAParameterSpec> parameters = new HashMap<>();

    static
    {
        parameters.put("ml-dsa-44", MLDSAParameterSpec.ml_dsa_44);
        parameters.put("ml-dsa-65", MLDSAParameterSpec.ml_dsa_65);
        parameters.put("ml-dsa-87", MLDSAParameterSpec.ml_dsa_87);

    }

    private final String name;
    private final boolean isPreHash;

    private MLDSAParameterSpec(String name, boolean isPreHash)
    {
        this.name = name;
        this.isPreHash = isPreHash;
    }

    public String getName()
    {
        return name;
    }

    /**
     * NIST security strength (in bits) per FIPS 204 Table 1:
     * <ul>
     *   <li>ML-DSA-44 — security category 2, 128-bit strength</li>
     *   <li>ML-DSA-65 — security category 3, 192-bit strength</li>
     *   <li>ML-DSA-87 — security category 5, 256-bit strength</li>
     * </ul>
     *
     * <p>Drives the JCE SPI's default-SecureRandom selection when the
     * caller doesn't supply one explicitly. See {@link MLKEMParameterSpec#getRequiredStrengthBits}
     * for the rationale (GH issue #34).
     */
    public int getRequiredStrengthBits()
    {
        if (this == ml_dsa_44)
        {
            return 128;
        }
        if (this == ml_dsa_65)
        {
            return 192;
        }
        if (this == ml_dsa_87)
        {
            return 256;
        }
        // Unknown — conservative.
        return 256;
    }


    public static MLDSAParameterSpec fromName(String name)
    {
        if (name == null)
        {
            throw new NullPointerException("name cannot be null");
        }

        MLDSAParameterSpec parameterSpec = (MLDSAParameterSpec) parameters.get(Strings.toLowerCase(name));

        if (parameterSpec == null)
        {
            throw new IllegalArgumentException("unknown parameter name: " + name);
        }

        return parameterSpec;
    }


    @Override
    public boolean equals(Object o)
    {
        if (o == null || getClass() != o.getClass())
        {
            return false;
        }
        MLDSAParameterSpec that = (MLDSAParameterSpec) o;
        return Objects.equals(name, that.name);
    }

    @Override
    public int hashCode()
    {
        return Objects.hashCode(name);
    }
}
