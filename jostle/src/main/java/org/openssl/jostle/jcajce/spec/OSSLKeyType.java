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

import org.openssl.jostle.util.asn1.oids.NISTObjectIdentifiers;

import java.util.HashMap;
import java.util.Map;

// TODO make these strings this is too rigid
public enum OSSLKeyType
{
    NONE(0),
    ML_DSA_44(1, "ML-DSA-44", "MLDSA44", NISTObjectIdentifiers.id_ml_dsa_44.getId(), "id-ml-dsa-44"),
    ML_DSA_65(2, "ML-DSA-65", "MLDSA65", NISTObjectIdentifiers.id_ml_dsa_65.getId(), "id-ml-dsa-65"),
    ML_DSA_87(3, "ML-DSA-87", "MLDSA87", NISTObjectIdentifiers.id_ml_dsa_87.getId(), "id-ml-dsa-87"),
    ML_DSA_SEED(4),
    // HASH-MLDSA
    SLH_DSA_SHA2_128f(5, "SLH-DSA-SHA2-128f", "id-slh-dsa-sha2-128f", NISTObjectIdentifiers.id_slh_dsa_sha2_128f.getId()),
    SLH_DSA_SHA2_128s(6, "SLH-DSA-SHA2-128s", "id-slh-dsa-sha2-128s", NISTObjectIdentifiers.id_slh_dsa_sha2_128s.getId()),
    SLH_DSA_SHA2_192f(7, "SLH-DSA-SHA2-192f", "id-slh-dsa-sha2-192f", NISTObjectIdentifiers.id_slh_dsa_sha2_192f.getId()),
    SLH_DSA_SHA2_192s(8, "SLH-DSA-SHA2-192s", "id-slh-dsa-sha2-192s", NISTObjectIdentifiers.id_slh_dsa_sha2_192s.getId()),
    SLH_DSA_SHA2_256f(9, "SLH-DSA-SHA2-256f", "id-slh-dsa-sha2-256f", NISTObjectIdentifiers.id_slh_dsa_sha2_256f.getId()),
    SLH_DSA_SHA2_256s(10, "SLH-DSA-SHA2-256s", "id-slh-dsa-sha2-256s", NISTObjectIdentifiers.id_slh_dsa_sha2_256s.getId()),
    SLH_DSA_SHAKE_128f(11, "SLH-DSA-SHAKE-128f", "id-slh-dsa-shake-128f", NISTObjectIdentifiers.id_slh_dsa_shake_128f.getId()),
    SLH_DSA_SHAKE_128s(12, "SLH-DSA-SHAKE-128s", "id-slh-dsa-shake-128s", NISTObjectIdentifiers.id_slh_dsa_shake_128s.getId()),
    SLH_DSA_SHAKE_192f(13, "SLH-DSA-SHAKE-192f", "id-slh-dsa-shake-192f", NISTObjectIdentifiers.id_slh_dsa_shake_192f.getId()),
    SLH_DSA_SHAKE_192s(14, "SLH-DSA-SHAKE-192s", "id-slh-dsa-shake-192s", NISTObjectIdentifiers.id_slh_dsa_shake_192s.getId()),
    SLH_DSA_SHAKE_256f(15, "SLH-DSA-SHAKE-256f", "id-slh-dsa-shake-256f", NISTObjectIdentifiers.id_slh_dsa_shake_256f.getId()),
    SLH_DSA_SHAKE_256s(16, "SLH-DSA-SHAKE-256s", "id-slh-dsa-shake-256s", NISTObjectIdentifiers.id_slh_dsa_shake_256s.getId()),
    ML_KEM_512(17, "ML-KEM-512", "MLKEM512", "id-alg-ml-kem-512", NISTObjectIdentifiers.id_alg_ml_kem_512.getId()),
    ML_KEM_768(18, "ML-KEM-768", "MLKEM768", "id-alg-ml-kem-768", NISTObjectIdentifiers.id_alg_ml_kem_768.getId()),
    ML_KEM_1024(19, "ML-KEM-1024", "MLKEM1024", "id-alg-ml-kem-1024", NISTObjectIdentifiers.id_alg_ml_kem_1024.getId()),
    ED25519(20, "Ed25519","ED25519"),
    Ed25519ctx(21,"Ed25519ctx","ED25519CTX"),
    Ed25519ph(22,"Ed25519ph","ED25519PH"),
    ED448ph(23,  "Ed448ph","ED448PH"),
    ED448(24, "Ed448", "ED448"),
    RSA(25, "RSA", "1.2.840.113549.1.1.1"),
    EC(26, "EC", "1.2.840.10045.2.1"),
    // XDH key agreement (RFC 8410). First alias is the OpenSSL EVP_PKEY
    // type name (what EVP_PKEY_get0_type_name returns), so decode-by-name
    // through PKEYKeySpec(long) maps to these.
    X25519(27, "X25519", "1.3.101.110", "id-X25519"),
    X448(28, "X448", "1.3.101.111", "id-X448");

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

    public String getTypeName()
    {
        return aliases[0];
    }

}
