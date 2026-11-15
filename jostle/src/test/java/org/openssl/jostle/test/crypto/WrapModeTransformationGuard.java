/*
 *
 *   Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *   Licensed under the Apache License 2.0 (the "License"). You may not use
 *   this file except in compliance with the License.  You can obtain a copy
 *   in the file LICENSE in the source distribution or at
 *   https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.crypto;

import org.junit.jupiter.api.Assertions;

import java.security.Provider;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * The wrap-mode padding refusal lives in engineSetPadding and relies on the mode being known by then, which holds
 * while no Cipher service or alias names a wrap mode inside a transformation (the JCE sets the mode first, and a
 * dedicated wrap name fixes it at construction). This fails if one ever does.
 */
public final class WrapModeTransformationGuard
{
    private static final String[] WRAP_SPELLINGS = {"WRAP", "KW", "WRAP_PAD", "KWP", "WRAP_INV", "KWINV", "WRAP-INV"};

    private WrapModeTransformationGuard()
    {
    }

    private static boolean namesAWrapMode(String algorithm)
    {
        String[] parts = algorithm.split("/", -1);
        if (parts.length < 2)
        {
            return false;
        }
        // A registered "X//Padding" makes the JCE call engineSetMode only, leaving the padding the SPI was built
        // with unchecked; no Jostle Cipher name takes that form, so any is flagged.
        if (parts[1].trim().isEmpty())
        {
            return true;
        }
        for (String w : WRAP_SPELLINGS)
        {
            if (parts[1].trim().toUpperCase(Locale.ROOT).equals(w))
            {
                return true;
            }
        }
        return false;
    }

    public static void assertNone(Provider provider)
    {
        Assertions.assertNotNull(provider);
        List<String> offending = new ArrayList<String>();
        int transformations = 0;
        int aliasesRead = 0;
        for (Provider.Service s : provider.getServices())
        {
            if ("Cipher".equals(s.getType()) && s.getAlgorithm().contains("/"))
            {
                transformations++;
                if (namesAWrapMode(s.getAlgorithm()))
                {
                    offending.add(s.getAlgorithm());
                }
            }
        }
        for (Object k : provider.keySet())
        {
            String key = String.valueOf(k);
            String name = null;
            if (key.startsWith("Cipher."))
            {
                name = key.substring("Cipher.".length());
            }
            else if (key.startsWith("Alg.Alias.Cipher."))
            {
                name = key.substring("Alg.Alias.Cipher.".length());
            }
            if (name != null)
            {
                if (key.startsWith("Alg.Alias."))
                {
                    aliasesRead++;
                }
                int space = name.indexOf(' ');
                name = space < 0 ? name : name.substring(0, space);
                if (name.contains("/"))
                {
                    transformations++;
                    if (namesAWrapMode(name))
                    {
                        offending.add(key);
                    }
                }
            }
        }
        Assertions.assertTrue(transformations > 0,
                provider.getName() + ": no Cipher transformation seen; the guard is not reading the provider");
        // Its own floor: the alias walk must read some Cipher alias, whether or not one carries a transformation.
        Assertions.assertTrue(aliasesRead > 0,
                provider.getName() + ": no Cipher alias read; the alias walk reads nothing");
        Assertions.assertTrue(offending.isEmpty(),
                provider.getName() + " registers a wrap mode inside a transformation: " + offending);
    }
}
