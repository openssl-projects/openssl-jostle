/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.util;

import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;

public class DigestUtil
{
    private static Map<String, String> canoncialNames;

    static
    {
        TreeMap<String, String> map = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

        // Alias/Name -> OpenSSL Name

        for (String alg : new String[]{"SHA1", "SHA-1"})
        {
            map.put(alg, "SHA1");
        }
        for (String alg : new String[]{"SHA2-224", "SHA-224", "SHA224"})
        {
            map.put(alg, "SHA2-224");
        }

        for (String alg : new String[]{"SHA2-256", "SHA-256", "SHA256"})
        {
            map.put(alg, "SHA2-256");
        }

        for (String alg : new String[]{"SHA2-384", "SHA-384", "SHA384"})
        {
            map.put(alg, "SHA2-384");
        }

        for (String alg : new String[]{"SHA2-512", "SHA-512", "SHA512"})
        {
            map.put(alg, "SHA2-512");
        }

        for (String alg : new String[]{"SHA2-512/224", "SHA-512/224", "SHA512-224"})
        {
            map.put(alg, "SHA2-512/224");
        }

        for (String alg : new String[]{"SHA2-512/256", "SHA-512/256", "SHA512-256"})
        {
            map.put(alg, "SHA2-512/256");
        }

        for (String alg : new String[]{"SHA3-224"})
        {
            map.put(alg, "SHA3-224");
        }

        for (String alg : new String[]{"SHA3-256"})
        {
            map.put(alg, "SHA3-256");
        }

        for (String alg : new String[]{"SHA3-384"})
        {
            map.put(alg, "SHA3-384");
        }

        for (String alg : new String[]{"SHA3-512"})
        {
            map.put(alg, "SHA3-512");
        }

        for (String alg : new String[]{"KECCAK-224"})
        {
            map.put(alg, "KECCAK-224");
        }

        for (String alg : new String[]{"KECCAK-256"})
        {
            map.put(alg, "KECCAK-256");
        }

        for (String alg : new String[]{"KECCAK-384"})
        {
            map.put(alg, "KECCAK-384");
        }

        for (String alg : new String[]{"KECCAK-512"})
        {
            map.put(alg, "KECCAK-512");
        }

        for (String alg : new String[]{"KECCAK-KMAC-128", "KECCAK-KMAC128"})
        {
            map.put(alg, "KECCAK-KMAC-128");
        }

        for (String alg : new String[]{"KECCAK-KMAC-256", "KECCAK-KMAC256"})
        {
            map.put(alg, "KECCAK-KMAC-256");
        }

        for (String alg : new String[]{"KMAC-128", "KMAC128"})
        {
            map.put(alg, "KMAC-128");
        }

        for (String alg : new String[]{"KMAC-256", "KMAC256"})
        {
            map.put(alg, "KMAC-256");
        }

        for (String alg : new String[]{"SHAKE-128", "SHAKE128"})
        {
            map.put(alg, "SHAKE-128");
        }

        for (String alg : new String[]{"SHAKE-256", "SHAKE256"})
        {
            map.put(alg, "SHAKE-256");
        }

        for (String alg : new String[]{"BLAKE2S-256", "BLAKE2s256"})
        {
            map.put(alg, "BLAKE2S-256");
        }

        for (String alg : new String[]{"BLAKE2B-512", "BLAKE2b512"})
        {
            map.put(alg, "BLAKE2B-512");
        }

        for (String d : new String[]{"SM3", "MD5", "MD5-SHA1"})
        {
            map.put(d, d);
        }

        for (String alg : new String[]{"RIPEMD160", "RIPEMD-160", "RIPEMD160", "RIPEMD", "RMD160"})
        {
            map.put(alg, "RIPEMD160");
        }

        for (String alg : new String[]{"NULL"})
        {
            map.put(alg, "NULL");
        }


        canoncialNames = Collections.unmodifiableMap(map);
    }

    /**
     * Matches an alias names to something OpenSSL will recognise.
     *
     * @param name the name
     * @return String
     * @throws IllegalArgumentException if the name cannot be matched.
     */
    public static String getCanonicalDigestName(String name)
    {
        if (!canoncialNames.containsKey(name))
        {
            throw new IllegalArgumentException("Unknown digest: " + name);
        }
        return canoncialNames.get(name);
    }

}
