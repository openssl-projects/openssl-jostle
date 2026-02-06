package org.openssl.jostle.jcajce.provider;

import org.openssl.jostle.jcajce.provider.md.MDServiceSPI;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static org.openssl.jostle.OpenSSLNameUtil.parseOpenSSLDefString;

public class ProvMD
{
    private static final String PREFIX = ProvMD.class.getPackage().getName() + ".md.";

    public void configure(final JostleProvider provider)
    {
        configureMLDSA(provider);
    }

    private void configureMLDSA(final JostleProvider provider)
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


        parseOpenSSLDefString("BLAKE2S-256:BLAKE2s256:1.3.6.1.4.1.1722.12.2.2.8", aliasKeyMap, keyAliasMap);
        parseOpenSSLDefString("BLAKE2B-512:BLAKE2b512:1.3.6.1.4.1.1722.12.2.1.16", aliasKeyMap, keyAliasMap);
        parseOpenSSLDefString("SM3:1.2.156.10197.1.401", aliasKeyMap, keyAliasMap);
        parseOpenSSLDefString("MD5:SSL3-MD5:1.2.840.113549.2.5", aliasKeyMap, keyAliasMap);
        parseOpenSSLDefString("MD5-SHA1", aliasKeyMap, keyAliasMap);

        parseOpenSSLDefString("RIPEMD-160:RIPEMD160:RIPEMD:RMD160:1.3.36.3.2.1", aliasKeyMap, keyAliasMap);


        final Map<String, String> attr = new HashMap<String, String>();


        //
        // Canonical names from OpenSSL, see names.h
        //
        for (String name : keyAliasMap.keySet())
        {
            final int xofLen;
            if (name.startsWith("SHAKE-128"))
            {
                xofLen = 32;
            } else if (name.startsWith("SHAKE-256"))
            {
                xofLen = 64;
            } else
            {
                xofLen = 0;
            }
            String clName = "MDServiceSPI$" + (name.replace("-", "_").replace("/", "_"));
            provider.addAlgorithmImplementation("MessageDigest", name, PREFIX + "MDServiceSPI$" + clName, attr, (arg) -> new MDServiceSPI(name, xofLen));
            provider.addAlias("MessageDigest", name, keyAliasMap.get(name));
        }


    }


}