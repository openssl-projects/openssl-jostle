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
import java.util.stream.Collectors;

public class SLHDSAParameterSpec implements AlgorithmParameterSpec
{
    public static final SLHDSAParameterSpec slh_dsa_sha2_128f = new SLHDSAParameterSpec("SLH-DSA-SHA2-128F", OSSLKeyType.SLH_DSA_SHA2_128f);
    public static final SLHDSAParameterSpec slh_dsa_sha2_128s = new SLHDSAParameterSpec("SLH-DSA-SHA2-128S", OSSLKeyType.SLH_DSA_SHA2_128s);

    public static final SLHDSAParameterSpec slh_dsa_sha2_192f = new SLHDSAParameterSpec("SLH-DSA-SHA2-192F", OSSLKeyType.SLH_DSA_SHA2_192f);
    public static final SLHDSAParameterSpec slh_dsa_sha2_192s = new SLHDSAParameterSpec("SLH-DSA-SHA2-192S", OSSLKeyType.SLH_DSA_SHA2_192s);

    public static final SLHDSAParameterSpec slh_dsa_sha2_256f = new SLHDSAParameterSpec("SLH-DSA-SHA2-256F", OSSLKeyType.SLH_DSA_SHA2_256f);
    public static final SLHDSAParameterSpec slh_dsa_sha2_256s = new SLHDSAParameterSpec("SLH-DSA-SHA2-256S", OSSLKeyType.SLH_DSA_SHA2_256s);

    // SHAKE-256.

    public static final SLHDSAParameterSpec slh_dsa_shake_128f = new SLHDSAParameterSpec("SLH-DSA-SHAKE-128F", OSSLKeyType.SLH_DSA_SHAKE_128f);
    public static final SLHDSAParameterSpec slh_dsa_shake_128s = new SLHDSAParameterSpec("SLH-DSA-SHAKE-128S", OSSLKeyType.SLH_DSA_SHAKE_128s);

    public static final SLHDSAParameterSpec slh_dsa_shake_192f = new SLHDSAParameterSpec("SLH-DSA-SHAKE-192F", OSSLKeyType.SLH_DSA_SHAKE_192f);
    public static final SLHDSAParameterSpec slh_dsa_shake_192s = new SLHDSAParameterSpec("SLH-DSA-SHAKE-192S", OSSLKeyType.SLH_DSA_SHAKE_192s);

    public static final SLHDSAParameterSpec slh_dsa_shake_256f = new SLHDSAParameterSpec("SLH-DSA-SHAKE-256F", OSSLKeyType.SLH_DSA_SHAKE_256f);
    public static final SLHDSAParameterSpec slh_dsa_shake_256s = new SLHDSAParameterSpec("SLH-DSA-SHAKE-256S", OSSLKeyType.SLH_DSA_SHAKE_256s);

    private static final Map<String, SLHDSAParameterSpec> parameters = new HashMap<>();
    private static final Map<OSSLKeyType, SLHDSAParameterSpec> osslTypeToSpec;

    private static final Set<SLHDSAParameterSpec> parameterSpecs;


    static
    {
        parameters.put("slh-dsa-sha2-128f", SLHDSAParameterSpec.slh_dsa_sha2_128f);
        parameters.put("slh-dsa-sha2-128s", SLHDSAParameterSpec.slh_dsa_sha2_128s);
        parameters.put("slh-dsa-sha2-192f", SLHDSAParameterSpec.slh_dsa_sha2_192f);
        parameters.put("slh-dsa-sha2-192s", SLHDSAParameterSpec.slh_dsa_sha2_192s);
        parameters.put("slh-dsa-sha2-256f", SLHDSAParameterSpec.slh_dsa_sha2_256f);
        parameters.put("slh-dsa-sha2-256s", SLHDSAParameterSpec.slh_dsa_sha2_256s);

        parameters.put("sha2-128f", SLHDSAParameterSpec.slh_dsa_sha2_128f);
        parameters.put("sha2-128s", SLHDSAParameterSpec.slh_dsa_sha2_128s);
        parameters.put("sha2-192f", SLHDSAParameterSpec.slh_dsa_sha2_192f);
        parameters.put("sha2-192s", SLHDSAParameterSpec.slh_dsa_sha2_192s);
        parameters.put("sha2-256f", SLHDSAParameterSpec.slh_dsa_sha2_256f);
        parameters.put("sha2-256s", SLHDSAParameterSpec.slh_dsa_sha2_256s);

        parameters.put("slh-dsa-shake-128f", SLHDSAParameterSpec.slh_dsa_shake_128f);
        parameters.put("slh-dsa-shake-128s", SLHDSAParameterSpec.slh_dsa_shake_128s);
        parameters.put("slh-dsa-shake-192f", SLHDSAParameterSpec.slh_dsa_shake_192f);
        parameters.put("slh-dsa-shake-192s", SLHDSAParameterSpec.slh_dsa_shake_192s);
        parameters.put("slh-dsa-shake-256f", SLHDSAParameterSpec.slh_dsa_shake_256f);
        parameters.put("slh-dsa-shake-256s", SLHDSAParameterSpec.slh_dsa_shake_256s);

        parameters.put("shake-128f", SLHDSAParameterSpec.slh_dsa_shake_128f);
        parameters.put("shake-128s", SLHDSAParameterSpec.slh_dsa_shake_128s);
        parameters.put("shake-192f", SLHDSAParameterSpec.slh_dsa_shake_192f);
        parameters.put("shake-192s", SLHDSAParameterSpec.slh_dsa_shake_192s);
        parameters.put("shake-256f", SLHDSAParameterSpec.slh_dsa_shake_256f);
        parameters.put("shake-256s", SLHDSAParameterSpec.slh_dsa_shake_256s);


        parameterSpecs = Collections.unmodifiableSet(new HashSet<SLHDSAParameterSpec>(parameters.values()));

        osslTypeToSpec = Collections.unmodifiableMap(new HashMap<OSSLKeyType, SLHDSAParameterSpec>()
        {
            {
                parameters.forEach((k, v) -> {
                    put((OSSLKeyType) v.keyType, (SLHDSAParameterSpec) v);
                });
            }
        });

    }

    private final OSSLKeyType keyType;
    private final String name;

    public static Set<String> getParameterNames()
    {
        return parameters.values().stream().map(SLHDSAParameterSpec::getName).collect(Collectors.toSet());
    }


    public static Set<SLHDSAParameterSpec> getParameterSpecs()
    {
        return parameterSpecs;
    }

    public static SLHDSAParameterSpec getSpecForOSSLType(OSSLKeyType keyType)
    {
        return osslTypeToSpec.get(keyType);
    }

    private SLHDSAParameterSpec(String name, OSSLKeyType keyType)
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


    public static SLHDSAParameterSpec fromName(String name)
    {
        if (name == null)
        {
            throw new NullPointerException("name cannot be null");
        }

        SLHDSAParameterSpec parameterSpec = (SLHDSAParameterSpec) parameters.get(Strings.toLowerCase(name));

        if (parameterSpec == null)
        {
            throw new IllegalArgumentException("unknown parameter name: " + name);
        }

        return parameterSpec;
    }


    @Override
    public boolean equals(Object o)
    {
        if (o == null || getClass() != o.getClass()) return false;
        SLHDSAParameterSpec that = (SLHDSAParameterSpec) o;
        return keyType == that.keyType && Objects.equals(name, that.name);
    }

    @Override
    public int hashCode()
    {
        return Objects.hash(keyType, name);
    }

    @Override
    public String toString()
    {
        return name + "(" + keyType + ")";
    }
}
