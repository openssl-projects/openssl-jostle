/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.fips;

import org.openssl.jostle.jcajce.provider.md.MDServiceSPI;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static org.openssl.jostle.OpenSSLNameUtil.parseOpenSSLDefString;

/**
 * MessageDigest registrations for the FIPS provider: the subset of ProvMD's
 * digests the OpenSSL FIPS module serves as approved (fips=yes) - SHA-1, the
 * SHA-2 family, SHA-3 and SHAKE. Deliberately absent (no fips=yes entry in
 * the module): MD5, MD5-SHA1, SM3, BLAKE2s/BLAKE2b, RIPEMD-160. The lib
 * ctx's fips=yes default properties are the enforcement backstop: a name
 * registered here by mistake would still fail to fetch.
 *
 * <p>Names, aliases and OIDs mirror ProvMD so approved algorithms resolve
 * identically through either provider.
 */
class ProvFIPSMD
{
    private static final String PREFIX = "org.openssl.jostle.jcajce.provider.md.";

    public void configure(final JostleFIPSProvider provider)
    {
        Map<String, String> aliasKeyMap = new HashMap<>();
        Map<String, Set<String>> keyAliasMap = new HashMap<>();

        parseOpenSSLDefString("SHA1:SHA-1:SSL3-SHA1:1.3.14.3.2.26", aliasKeyMap, keyAliasMap);
        parseOpenSSLDefString("SHA2-224:SHA-224:SHA224:2.16.840.1.101.3.4.2.4", aliasKeyMap, keyAliasMap);
        parseOpenSSLDefString("SHA2-256:SHA-256:SHA256:2.16.840.1.101.3.4.2.1", aliasKeyMap, keyAliasMap);
        parseOpenSSLDefString("SHA2-384:SHA-384:SHA384:2.16.840.1.101.3.4.2.2", aliasKeyMap, keyAliasMap);
        parseOpenSSLDefString("SHA2-512:SHA-512:SHA512:2.16.840.1.101.3.4.2.3", aliasKeyMap, keyAliasMap);
        parseOpenSSLDefString("SHA2-512/224:SHA-512/224:SHA512-224:2.16.840.1.101.3.4.2.5", aliasKeyMap, keyAliasMap);
        parseOpenSSLDefString("SHA2-512/256:SHA-512/256:SHA512-256:2.16.840.1.101.3.4.2.6", aliasKeyMap, keyAliasMap);

        parseOpenSSLDefString("SHA3-224:2.16.840.1.101.3.4.2.7", aliasKeyMap, keyAliasMap);
        parseOpenSSLDefString("SHA3-256:2.16.840.1.101.3.4.2.8", aliasKeyMap, keyAliasMap);
        parseOpenSSLDefString("SHA3-384:2.16.840.1.101.3.4.2.9", aliasKeyMap, keyAliasMap);
        parseOpenSSLDefString("SHA3-512:2.16.840.1.101.3.4.2.10", aliasKeyMap, keyAliasMap);

        parseOpenSSLDefString("SHAKE-128:SHAKE128:2.16.840.1.101.3.4.2.11", aliasKeyMap, keyAliasMap);
        parseOpenSSLDefString("SHAKE-256:SHAKE256:2.16.840.1.101.3.4.2.12", aliasKeyMap, keyAliasMap);

        final Map<String, String> attr = new HashMap<String, String>();

        for (String name : keyAliasMap.keySet())
        {
            final int xofLen;
            if (name.startsWith("SHAKE-128"))
            {
                xofLen = 32;
            }
            else
            {
                if (name.startsWith("SHAKE-256"))
                {
                    xofLen = 64;
                }
                else
                {
                    xofLen = 0;
                }
            }
            String clName = name.replace("-", "_").replace("/", "_");
            provider.addAlgorithmImplementation("MessageDigest", name, PREFIX + "MDServiceSPI$" + clName, attr,
                    (arg) -> new MDServiceSPI(FIPSNISelector.MDServiceNI, name, xofLen));
            provider.addAlias("MessageDigest", name, keyAliasMap.get(name).toArray(new String[0]));
        }

        //
        // Fixed-output SHAKE variants, mirroring ProvMD (BouncyCastle's
        // CMS/PKIX layer requests these by name).
        //
        provider.addAlgorithmImplementation("MessageDigest", "SHAKE128-256", PREFIX + "MDServiceSPI$SHAKE128_256", attr,
                (arg) -> new MDServiceSPI(FIPSNISelector.MDServiceNI, "SHAKE-128", 32));
        provider.addAlgorithmImplementation("MessageDigest", "SHAKE256-512", PREFIX + "MDServiceSPI$SHAKE256_512", attr,
                (arg) -> new MDServiceSPI(FIPSNISelector.MDServiceNI, "SHAKE-256", 64));
    }
}
