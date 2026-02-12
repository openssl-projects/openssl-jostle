package org.openssl.jostle;

import java.util.*;


public class OpenSSLNameUtil
{

    /**
     * Parse out a string from "names.h" in OpenSSL
     *
     * @param openSSLDefString the value from the header
     * @param aliasToKey       map of aliases to the key
     * @param keyToAlias       map of key to a list of aliases
     */
    public static void parseOpenSSLDefString(String openSSLDefString, Map<String, String> aliasToKey, Map<String, Set<String>> keyToAlias)
    {
        if (openSSLDefString == null)
        {
            return;
        }
        openSSLDefString = openSSLDefString.trim();
        if (openSSLDefString.isEmpty())
        {
            return;
        }

        String[] parts = openSSLDefString.split(":");
        String targetName = parts[0];

        keyToAlias.put(targetName, new HashSet<String>());

        for (String part : parts)
        {
            aliasToKey.put(part, targetName);
            if (!part.equals(targetName))
            {
                keyToAlias.get(targetName).add(part);
            }
        }
    }


}
