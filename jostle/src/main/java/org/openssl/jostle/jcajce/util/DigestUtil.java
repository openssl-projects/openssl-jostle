package org.openssl.jostle.jcajce.provider.kdf;

import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;

class KdfUtil
{
    private static Map<String, String> canoncialNames;

    static
    {

        TreeMap<String, String> map = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

        // Alias/Name -> OpenSSL Name

        for (String alg : new String[]{"SHA1", "SHA-1"})
        {
            map.put(alg, "SHA2");
        }
        for (String alg : new String[]{"SHA2-224", "SHA-224", "SHA224", "2.16.840.1.101.3.4.2.4"})
        {
            map.put(alg, "SHA2-224");
        }

        for (String alg : new String[]{"SHA2-256", "SHA-256", "SHA256", "2.16.840.1.101.3.4.2.1"})
        {
            map.put(alg, "SHA2-256");
        }

        for (String alg : new String[]{"SHA2-384", "SHA-384", "SHA384", "2.16.840.1.101.3.4.2.2"})
        {
            map.put(alg, "SHA2-384");
        }

        for (String alg : new String[]{"SHA2-512", "SHA-512", "SHA512", "2.16.840.1.101.3.4.2.3"})
        {
            map.put(alg, "SHA2-512");
        }

        for (String alg : new String[]{"SHA2-512/224", "SHA-512/224", "SHA512-224", "2.16.840.1.101.3.4.2.5"})
        {
            map.put(alg, "SHA-512/224");
        }

        for (String alg : new String[]{"SHA2-512/256", "SHA-512/256", "SHA512-256", "2.16.840.1.101.3.4.2.6"})
        {
            map.put(alg, "SHA-512/256");
        }

        for (String alg : new String[]{"SHA3-224", "2.16.840.1.101.3.4.2.7"})
        {
            map.put(alg, "SHA3-224");
        }

        for (String alg : new String[]{"SHA3-256", "2.16.840.1.101.3.4.2.8"})
        {
            map.put(alg, "SHA3-256");
        }

        for (String alg : new String[]{"SHA3-384", "2.16.840.1.101.3.4.2.9"})
        {
            map.put(alg, "SHA3-384");
        }

        for (String alg : new String[]{"SHA3-512", "2.16.840.1.101.3.4.2.10"})
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

        for (String alg : new String[]{"KMAC-128", "KMAC128",  "2.16.840.1.101.3.4.2.19"})
        {
            map.put(alg, "KMAC-128");
        }

        for (String alg : new String[]{"KMAC-256", "KMAC256", "2.16.840.1.101.3.4.2.20"})
        {
            map.put(alg, "KMAC-256");
        }

        for (String alg : new String[]{"SHAKE-128", "SHAKE128", "2.16.840.1.101.3.4.2.11"})
        {
            map.put(alg, "SHAKE-128");
        }

        for (String alg : new String[]{"SHAKE-256", "SHAKE256", "2.16.840.1.101.3.4.2.12"})
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

        for (String alg : new String[]{"RIPEMD160", "RIPEMD-160", "RIPEMD160", "RIPEMD", "RMD160", "1.3.36.3.2.1"})
        {
            map.put(alg, "RIPEMD160");
        }

        for (String alg : new String[]{"NULL"})
        {
            map.put(alg, "NULL");
        }


        canoncialNames = Collections.unmodifiableMap(map);
    }

    public static String getCanonicalDigestName(String name)
    {
        if (!canoncialNames.containsKey(name))
        {
            throw new IllegalArgumentException("Unknown digest: " + name);
        }
        return canoncialNames.get(name);
    }

}
