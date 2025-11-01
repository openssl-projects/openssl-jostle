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

// ksType values must match macros in key_spec.h

import java.util.HashMap;
import java.util.Map;

// TODO make these strings this is too rigid
public enum OSSLKeyType
{
    NONE(0),
    ML_DSA_44(1, "ML-DSA-44", "MLDSA44", "2.16.840.1.101.3.4.3.17", "id-ml-dsa-44"),
    ML_DSA_65(2, "ML-DSA-65", "MLDSA65", "2.16.840.1.101.3.4.3.18", "id-ml-dsa-65"),
    ML_DSA_87(3, "ML-DSA-87", "MLDSA87", "2.16.840.1.101.3.4.3.19", "id-ml-dsa-87"),
    ML_DSA_SEED(4),
    // HASH-MLDSA
    SLH_DSA_SHA2_128f(5, "SLH-DSA-SHA2-128f", "id-slh-dsa-sha2-128f", "2.16.840.1.101.3.4.3.21"),
    SLH_DSA_SHA2_128s(6, "SLH-DSA-SHA2-128s", "id-slh-dsa-sha2-128s", "2.16.840.1.101.3.4.3.20"),
    SLH_DSA_SHA2_192f(7, "SLH-DSA-SHA2-192f", "id-slh-dsa-sha2-192f", "2.16.840.1.101.3.4.3.23"),
    SLH_DSA_SHA2_192s(8, "SLH-DSA-SHA2-192s", "id-slh-dsa-sha2-192s", "2.16.840.1.101.3.4.3.22"),
    SLH_DSA_SHA2_256f(9, "SLH-DSA-SHA2-256f", "id-slh-dsa-sha2-256f", "2.16.840.1.101.3.4.3.25"),
    SLH_DSA_SHA2_256s(10, "SLH-DSA-SHA2-256s", "id-slh-dsa-sha2-256s", "2.16.840.1.101.3.4.3.24"),
    SLH_DSA_SHAKE_128f(11, "SLH-DSA-SHAKE-128f", "id-slh-dsa-shake-128f", "2.16.840.1.101.3.4.3.27"),
    SLH_DSA_SHAKE_128s(12, "SLH-DSA-SHAKE-128s", "id-slh-dsa-shake-128s", "2.16.840.1.101.3.4.3.26"),
    SLH_DSA_SHAKE_192f(13, "SLH-DSA-SHAKE-192f", "id-slh-dsa-shake-192f", "2.16.840.1.101.3.4.3.29"),
    SLH_DSA_SHAKE_192s(14, "SLH-DSA-SHAKE-192s", "id-slh-dsa-shake-192s", "2.16.840.1.101.3.4.3.28"),
    SLH_DSA_SHAKE_256f(15, "SLH-DSA-SHAKE-256f", "id-slh-dsa-shake-256f", "2.16.840.1.101.3.4.3.31"),
    SLH_DSA_SHAKE_256s(16, "SLH-DSA-SHAKE-256s", "id-slh-dsa-shake-256s", "2.16.840.1.101.3.4.3.30"),
    ML_KEM_512(17, "ML-KEM-512", "MLKEM512", "id-alg-ml-kem-512", "2.16.840.1.101.3.4.4.1"),
    ML_KEM_768(18, "ML-KEM-768", "MLKEM768", "id-alg-ml-kem-768", "2.16.840.1.101.3.4.4.2"),
    ML_KEM_1024(19, "ML-KEM-1024", "MLKEM1024", "id-alg-ml-kem-1024", "2.16.840.1.101.3.4.4.3");

    private final String[] aliases;
    int ksType;

    private static Map<String, OSSLKeyType> aliasesMap = new HashMap<String, OSSLKeyType>();

    static
    {
        for (OSSLKeyType keyType : OSSLKeyType.values())
        {
            for (String alias : keyType.aliases)
            {
                aliasesMap.put(alias, keyType);
            }
        }
    }

    OSSLKeyType(int ksType, String... aliases)
    {
        this.ksType = ksType;
        this.aliases = aliases;
    }

    public int getKsType()
    {
        return ksType;
    }

    public String getAlgorithmName()
    {
        return name().replace('_', '-').toUpperCase();
    }


    public static OSSLKeyType forAlias(String alias)
    {
        if (alias == null)
        {
            throw new IllegalArgumentException("null alias");
        }
        return aliasesMap.get(alias);
    }

    public static OSSLKeyType fromKsType(int ksType)
    {
        for (OSSLKeyType type : OSSLKeyType.values())
        {
            if (type.ksType == ksType)
            {
                return type;
            }
        }
        throw new IllegalArgumentException("Unknown OSSLKeyType " + ksType);
    }


}
